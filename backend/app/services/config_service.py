"""
Configuration service - the single source of truth for every runtime knob.

Five singleton tables (``network``, ``detection``, ``alerts``, ``model``,
``system``) hold the persisted values.  :data:`SPECS` describes each field once -
label, description, type, allowed range and the concrete runtime effect - and
everything else is derived from it:

* validation (:func:`validate`) rejects out-of-range or non-permitted values
  *before* anything is written, so an invalid configuration can never be stored;
* the admin settings UI (:func:`describe`) renders itself from the specs, which
  is why adding a knob does not require touching React;
* :func:`runtime_snapshot` produces the effective values the analysis pipeline,
  the risk engine and the alert engine actually read, with the current network
  status profile applied on top of the configured baseline;
* every write records a ``configuration_revisions`` row and an audit entry.

Validation and defaults
-----------------------
Defaults are taken from the SQLAlchemy column default, so the database schema and
the safe fallback can never drift apart.  Where a default is not expressible in a
column (``allowed_file_formats``, ``categories``, ...) it is listed in
:data:`JSON_DEFAULTS`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.core import network_modes
from app.services import audit_service
from app.models.database_models import (
    AlertConfiguration,
    ConfigurationRevision,
    DetectionConfiguration,
    ModelConfiguration,
    NetworkConfiguration,
    NetworkStatus,
    SystemConfiguration,
)

logger = logging.getLogger("ainids.config")

SCOPES = ("network", "detection", "alerts", "model", "system")

MODELS: dict[str, type] = {
    "network": NetworkConfiguration,
    "detection": DetectionConfiguration,
    "alerts": AlertConfiguration,
    "model": ModelConfiguration,
    "system": SystemConfiguration,
}

SCOPE_TITLES: dict[str, str] = {
    "network": "Network",
    "detection": "Detection",
    "alerts": "Alerts",
    "model": "Model",
    "system": "System",
}

#: Console section -> the permission required to change fields in that section.
#:
#: The eleven console sections do not map one-to-one onto the five storage
#: scopes: "Security", "Data Retention", "API" and "Dashboard" all live inside the
#: ``system`` scope. Without this map a single ``system`` write would be allowed by
#: ``settings.system`` alone and the specific settings.security / settings.retention /
#: settings.api permissions would never be enforced by anything.
SECTION_PERMISSIONS: dict[str, str] = {
    "Network": "network.configure",
    "Automatic status": "network.configure",
    "Detection": "detection.configure",
    "Alerts": "alerts.configure",
    "Severity thresholds": "alerts.configure",
    "Escalation": "alerts.configure",
    "Notifications": "alerts.configure",
    "Model": "model.configure",
    "Security": "settings.security",
    # The "Users" section is session/password/lockout *policy*, not account
    # management - changing the password rules must not require users.manage.
    "Users": "settings.security",
    "Data Retention": "settings.retention",
    "API": "settings.api",
    "System": "settings.system",
    "Logging": "settings.system",
    "Dashboard": "settings.system",
}

#: Keys whose storage section does not reflect their real sensitivity: a retention
#: window filed under "Alerts" still purges rows, so it needs the retention
#: permission rather than the alerting one.
KEY_PERMISSION_OVERRIDES: dict[str, str] = {
    "retention_days": "settings.retention",
    "alert_retention_days": "settings.retention",
    "log_retention_days": "settings.retention",
}


def required_permissions(scope: str, keys: Iterable[str]) -> list[str]:
    """
    Permissions a write of ``keys`` in ``scope`` must satisfy.

    A payload spanning several console sections needs every one of them; a payload
    that touches no section with its own permission needs nothing beyond the
    scope-level guard the caller already passed.
    """
    specs = {spec.key: spec for spec in SPECS.get(scope, ())}
    needed: list[str] = []
    for key in keys:
        spec = specs.get(key)
        if spec is None:
            continue
        permission = KEY_PERMISSION_OVERRIDES.get(key) or SECTION_PERMISSIONS.get(
            getattr(spec, "section", "") or ""
        )
        if permission and permission not in needed:
            needed.append(permission)
    return needed


SCOPE_DESCRIPTIONS: dict[str, str] = {
    "network": "Which network is monitored and the operational parameters applied to it.",
    "detection": "How Random Forest output is turned into risk levels and how often analysis runs.",
    "alerts": "What raises an alert, how duplicates are handled and when alerts escalate.",
    "model": "Runtime behaviour of the detection model and the explanation layer.",
    "system": "Security, retention, logging, API, dashboard and notification settings.",
}

#: Columns whose default is a mutable/derived value the DB default cannot express.
JSON_DEFAULTS: dict[str, dict[str, Any]] = {
    "network": {
        "allowed_file_formats": [".csv", ".tsv", ".txt", ".parquet"],
    },
    "alerts": {
        "categories": [],
        "notify_severities": ["high", "critical"],
    },
    "system": {
        "ip_allowlist": [],
        "notify_severities": ["high", "critical"],
    },
}

SEVERITIES = ("low", "medium", "high", "critical")
SENSITIVITY_LEVELS = ("low", "balanced", "high", "paranoid")

#: Multiplier applied to the configured risk thresholds per sensitivity level.
SENSITIVITY_MULTIPLIERS: dict[str, float] = {
    "low": 1.15,
    "balanced": 1.0,
    "high": 0.90,
    "paranoid": 0.80,
}

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
ENVIRONMENTS = ("production", "staging", "lab", "dmz", "development")
MONITORING_MODES = ("continuous", "sampled", "on_demand")
DUPLICATE_HANDLINGS = ("off", "aggregate", "suppress")
SUPPORTED_UPLOAD_FORMATS = (".csv", ".tsv", ".txt", ".parquet", ".pq")


# --------------------------------------------------------------------------- #
# Specs
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SettingSpec:
    key: str
    label: str
    description: str
    type: str  # integer | number | boolean | text | choice | list | secret-masked
    section: str
    minimum: float | None = None
    maximum: float | None = None
    step: float | None = None
    choices: tuple[str, ...] = ()
    unit: str = ""
    dangerous: bool = False
    runtime_effect: str = ""
    requires_confirmation: bool = False

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "type": self.type,
            "section": self.section,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "step": self.step,
            "choices": list(self.choices),
            "unit": self.unit,
            "dangerous": self.dangerous,
            "runtime_effect": self.runtime_effect,
            "requires_confirmation": self.requires_confirmation or self.dangerous,
        }


def _s(*args, **kwargs) -> SettingSpec:
    return SettingSpec(*args, **kwargs)


SPECS: dict[str, tuple[SettingSpec, ...]] = {
    "network": (
        _s("network_name", "Network name", "Human-readable name of the network being monitored.",
           "text", "Network", runtime_effect="Shown on dashboards, alerts and audit entries."),
        _s("environment", "Environment / type", "Operational context of the monitored network.",
           "choice", "Network", choices=ENVIRONMENTS,
           runtime_effect="Included in alert context and audit records."),
        _s("monitoring_mode", "Monitoring mode", "How continuously traffic is analysed.",
           "choice", "Network", choices=MONITORING_MODES,
           runtime_effect="Reported in the Control Center and used as analysis context."),
        _s("timezone_label", "Timezone label", "Label used when displaying timestamps in the console.",
           "text", "Network", runtime_effect="Display only."),
        _s("detection_sensitivity", "Detection sensitivity", "Baseline sensitivity applied to the risk thresholds.",
           "choice", "Network", choices=SENSITIVITY_LEVELS,
           runtime_effect="Multiplies the configured MEDIUM/HIGH/CRITICAL risk thresholds."),
        _s("alert_threshold", "Alert threshold", "Risk score at or above which a flow is alertable.",
           "number", "Network", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Used as the minimum alertable risk score in addition to the severity floor."),
        _s("risk_threshold", "Risk threshold", "Risk score at or above which a flow is treated as high risk.",
           "number", "Network", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Used by the dashboards and the alert feed to highlight high-risk traffic."),
        _s("analysis_interval_seconds", "Traffic analysis interval", "Seconds between analysis runs.",
           "integer", "Network", minimum=5, maximum=86400, step=5, unit="s",
           runtime_effect="Reported as the monitoring cadence; combined with the current status profile."),
        _s("analysis_batch_size", "Analysis batch size", "Flows scored per inference batch.",
           "integer", "Network", minimum=50, maximum=100000, step=50, unit="rows",
           runtime_effect="Batch size used by the Random Forest inference loop."),
        _s("max_upload_size_mb", "Maximum upload size", "Largest accepted traffic file.",
           "integer", "Network", minimum=1, maximum=2048, step=1, unit="MB",
           runtime_effect="Uploads larger than this are rejected by the API and the middleware."),
        _s("allowed_file_formats", "Allowed file formats", "Extensions accepted by the upload endpoints.",
           "list", "Network", choices=SUPPORTED_UPLOAD_FORMATS,
           runtime_effect="Uploads with any other extension are rejected."),
        _s("alert_retention_days", "Alert retention", "Days alerts are kept before they become eligible for purge.",
           "integer", "Network", minimum=1, maximum=3650, step=1, unit="days",
           runtime_effect="Used by the retention service."),
        _s("log_retention_days", "Log retention", "Days request/audit logs are kept.",
           "integer", "Network", minimum=1, maximum=3650, step=1, unit="days",
           runtime_effect="Used by the retention service."),
        _s("auto_alert_generation", "Automatic alert generation", "Raise alerts automatically after analysis.",
           "boolean", "Network", dangerous=True,
           runtime_effect="When disabled, analysis stores predictions but creates no alerts.",
           requires_confirmation=True),
        _s("auto_incident_creation", "Automatic incident creation", "Open an investigation automatically for qualifying alerts.",
           "boolean", "Network", dangerous=True,
           runtime_effect="Creates an investigation when an alert reaches the configured severity.",
           requires_confirmation=True),
        _s("duplicate_suppression", "Duplicate suppression", "Fold repeated attack/port pairs into one alert.",
           "boolean", "Network",
           runtime_effect="Passes the duplicate handling mode to the alert engine."),
        _s("traffic_volume_threshold", "Traffic volume threshold", "Flows per window that indicate a high-volume condition.",
           "integer", "Automatic status", minimum=0, maximum=10_000_000, step=1000, unit="flows",
           runtime_effect="Input to the automatic network status evaluator."),
        _s("suspicious_percent_threshold", "Suspicious traffic threshold", "Suspicious share (%) that indicates an elevated condition.",
           "number", "Automatic status", minimum=0.0, maximum=100.0, step=0.5, unit="%",
           runtime_effect="Input to the automatic network status evaluator."),
        _s("attack_rate_threshold", "Attack rate threshold", "Attack share (%) that indicates an elevated condition.",
           "number", "Automatic status", minimum=0.0, maximum=100.0, step=0.5, unit="%",
           runtime_effect="Input to the automatic network status evaluator."),
        _s("critical_alert_threshold", "Critical alert threshold", "Open critical alerts that indicate a critical condition.",
           "integer", "Automatic status", minimum=1, maximum=10000, step=1, unit="alerts",
           runtime_effect="Input to the automatic network status evaluator."),
        _s("alert_rate_threshold", "Alert rate threshold", "Alerts per window that indicate an elevated condition.",
           "integer", "Automatic status", minimum=1, maximum=100000, step=1, unit="alerts",
           runtime_effect="Input to the automatic network status evaluator."),
        _s("auto_status_enabled", "Automatic status", "Let the platform evaluate the operational status from traffic and alerts.",
           "boolean", "Automatic status", dangerous=True,
           runtime_effect="Enables automatic status evaluation; see 'suggest only' below.",
           requires_confirmation=True),
        _s("auto_status_window_minutes", "Automatic status window", "Minutes of traffic the evaluator looks at.",
           "integer", "Automatic status", minimum=5, maximum=10080, step=5, unit="min",
           runtime_effect="Window used by the automatic status evaluator."),
        _s("auto_status_suggest_only", "Suggest only", "Recommend a status instead of applying it automatically.",
           "boolean", "Automatic status", dangerous=True,
           runtime_effect="When enabled the evaluator only produces a recommendation for the admin.",
           requires_confirmation=True),
    ),
    "detection": (
        _s("detection_sensitivity", "Detection sensitivity", "Sensitivity applied to the risk thresholds.",
           "choice", "Detection", choices=SENSITIVITY_LEVELS,
           runtime_effect="Multiplier on the risk thresholds below."),
        _s("risk_medium_threshold", "MEDIUM risk threshold", "Risk score at or above which a flow is MEDIUM.",
           "number", "Detection", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Risk engine boundary between LOW and MEDIUM."),
        _s("risk_high_threshold", "HIGH risk threshold", "Risk score at or above which a flow is HIGH.",
           "number", "Detection", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Risk engine boundary between MEDIUM and HIGH."),
        _s("risk_critical_threshold", "CRITICAL risk threshold", "Risk score at or above which a flow is CRITICAL.",
           "number", "Detection", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Risk engine boundary between HIGH and CRITICAL."),
        _s("min_confidence_to_alert", "Minimum confidence to alert", "Model confidence required before a flow can raise an alert.",
           "number", "Detection", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Flows below this confidence never raise an alert."),
        _s("min_confidence_to_store", "Minimum confidence to store", "Model confidence required to persist a flow result.",
           "number", "Detection", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Low-confidence flows are summarised but not stored."),
        _s("analysis_interval_seconds", "Analysis interval", "Seconds between analysis runs.",
           "integer", "Detection", minimum=5, maximum=86400, step=5, unit="s",
           runtime_effect="Monitoring cadence shown in the Control Center."),
        _s("analysis_batch_size", "Batch size", "Flows scored per inference batch.",
           "integer", "Detection", minimum=50, maximum=100000, step=50, unit="rows",
           runtime_effect="Batch size of the Random Forest inference loop."),
        _s("max_rows_per_job", "Maximum rows per job", "Row cap applied to a single analysis run.",
           "integer", "Detection", minimum=100, maximum=2000000, step=100, unit="rows",
           runtime_effect="Larger files are truncated with a warning."),
        _s("store_predictions_limit", "Stored predictions per job", "Row cap for persisted flow results.",
           "integer", "Detection", minimum=100, maximum=500000, step=100, unit="rows",
           runtime_effect="Only the first N analysed flows are written to the database."),
        _s("job_workers", "Analysis workers", "Concurrent background analysis jobs.",
           "integer", "Detection", minimum=1, maximum=16, step=1, unit="workers",
           runtime_effect="The background job pool is resized immediately."),
        _s("sensitive_port_bonus", "Sensitive port bonus", "Risk bonus for traffic aimed at an administrative port.",
           "number", "Detection", minimum=0.0, maximum=0.2, step=0.01,
           runtime_effect="Added to the risk score for flows targeting a sensitive port."),
        _s("highlight_suspicious", "Highlight suspicious traffic", "Emphasise suspicious flows across the console.",
           "boolean", "Detection", runtime_effect="Drives highlighting in the dashboards and tables."),
        _s("enhanced_investigation", "Enhanced investigation mode", "Show extra evidence in the investigation workspace.",
           "boolean", "Detection", runtime_effect="Adds deviation analysis to the investigation payload."),
        _s("preserve_investigation_logs", "Preserve investigation logs", "Keep detailed investigation evidence.",
           "boolean", "Detection", dangerous=True,
           runtime_effect="Investigations retain the full feature snapshot at creation time.",
           requires_confirmation=True),
    ),
    "alerts": (
        _s("alerts_enabled", "Alerts enabled", "Master switch for automatic alert generation.",
           "boolean", "Alerts", dangerous=True,
           runtime_effect="When disabled no alerts are created, existing alerts are untouched.",
           requires_confirmation=True),
        _s("min_severity_to_alert", "Minimum severity to alert", "Lowest severity that may raise an alert.",
           "choice", "Alerts", choices=SEVERITIES, dangerous=True,
           runtime_effect="Flows below this severity never raise an alert.",
           requires_confirmation=True),
        _s("severity_low_max", "LOW severity ceiling", "Risk score at or below which a flow stays LOW.",
           "number", "Severity thresholds", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Displayed severity boundary used by the alert engine and dashboards."),
        _s("severity_medium_max", "MEDIUM severity ceiling", "Risk score at or below which a flow stays MEDIUM or lower.",
           "number", "Severity thresholds", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Displayed severity boundary."),
        _s("severity_high_max", "HIGH severity ceiling", "Risk score at or below which a flow stays HIGH or lower.",
           "number", "Severity thresholds", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Displayed severity boundary."),
        _s("categories", "Alert categories", "Categories alerts may be tagged with.",
           "list", "Alerts", runtime_effect="Available categories in the alert UI."),
        _s("notify_severities", "Notify on severities", "Severities that produce a notification.",
           "list", "Notifications", choices=SEVERITIES,
           runtime_effect="Alerts at these severities create a notification entry."),
        _s("retention_days", "Alert retention", "Days alerts are kept before purge eligibility.",
           "integer", "Alerts", minimum=1, maximum=3650, step=1, unit="days",
           runtime_effect="Used by the retention service."),
        _s("duplicate_handling", "Duplicate handling", "How repeated attack/port pairs are handled.",
           "choice", "Alerts", choices=DUPLICATE_HANDLINGS, dangerous=True,
           runtime_effect="Controls aggregation and suppression in the alert engine.",
           requires_confirmation=True),
        _s("duplicate_window_seconds", "Duplicate window", "Seconds used to group duplicates.",
           "integer", "Alerts", minimum=0, maximum=86400, step=30, unit="s",
           runtime_effect="Window applied when duplicate handling is 'suppress'."),
        _s("max_alerts_per_job", "Maximum alerts per job", "Hard ceiling on alerts produced by one analysis run.",
           "integer", "Alerts", minimum=1, maximum=5000, step=10, unit="alerts",
           runtime_effect="Caps the number of alert pairs per job."),
        _s("max_individual_alerts", "Maximum individual alerts", "Alerts kept in single-flow form per job.",
           "integer", "Alerts", minimum=0, maximum=1000, step=5, unit="alerts",
           runtime_effect="Remaining flows are folded into aggregated burst alerts."),
        _s("auto_incident_severity", "Auto-create incident at", "Severity that opens an investigation automatically.",
           "choice", "Escalation", choices=SEVERITIES, dangerous=True,
           runtime_effect="Alerts at or above this severity open an investigation.",
           requires_confirmation=True),
        _s("escalation_enabled", "Escalation", "Escalate alerts that stay unresolved.",
           "boolean", "Escalation", dangerous=True,
           runtime_effect="Marks aged alerts as escalated.",
           requires_confirmation=True),
        _s("escalate_after_minutes", "Escalate after", "Minutes before an unresolved alert escalates.",
           "integer", "Escalation", minimum=1, maximum=10080, step=5, unit="min",
           runtime_effect="Age threshold for escalation."),
        _s("escalate_to_severity", "Escalate to severity", "Severity assigned to an escalated alert.",
           "choice", "Escalation", choices=SEVERITIES,
           runtime_effect="Severity written when an alert escalates."),
        _s("notify_admins_on_critical", "Notify admins on CRITICAL", "Create an admin notification for CRITICAL alerts.",
           "boolean", "Notifications", runtime_effect="Adds an admin-targeted notification."),
    ),
    "model": (
        _s("enabled", "Model enabled", "Allow the model to score traffic.",
           "boolean", "Model", dangerous=True,
           runtime_effect="When disabled the analysis pipeline refuses to run.",
           requires_confirmation=True),
        _s("active_version", "Active model version", "Model version used for scoring.",
           "text", "Model", dangerous=True,
           runtime_effect="Reported on every analysis job and prediction record.",
           requires_confirmation=True),
        _s("prediction_threshold", "Prediction threshold", "Minimum probability required to accept a class prediction.",
           "number", "Model", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Used to qualify the accepted class of a prediction."),
        _s("batch_size", "Inference batch size", "Rows per inference batch.",
           "integer", "Model", minimum=50, maximum=100000, step=50, unit="rows",
           runtime_effect="Batch size of the Random Forest inference loop."),
        _s("min_confidence_to_store", "Minimum confidence to store", "Confidence required to persist a flow result.",
           "number", "Model", minimum=0.0, maximum=1.0, step=0.01,
           runtime_effect="Low-confidence flows are summarised but not stored."),
        _s("explanations_enabled", "Explanations", "Enable the explanation layer.",
           "boolean", "Model", runtime_effect="Adds explanation payloads to prediction detail."),
        _s("shap_enabled", "TreeSHAP", "Use per-record TreeSHAP instead of global importance.",
           "boolean", "Model", runtime_effect="Falls back to global feature importance when disabled."),
        _s("explanation_top_k", "Explanation features", "Number of features shown in an explanation.",
           "integer", "Model", minimum=1, maximum=70, step=1, unit="features",
           runtime_effect="Number of contributing features returned per record."),
        _s("retraining_enabled", "Retraining", "Allow admins to start a retraining run.",
           "boolean", "Model", dangerous=True,
           runtime_effect="Enables the retraining endpoints; runs still require approval before deployment.",
           requires_confirmation=True),
        _s("require_approval", "Approval before deployment", "A retrained model must be approved before it goes live.",
           "boolean", "Model", dangerous=True,
           runtime_effect="Blocks model deployment until an admin approves the candidate.",
           requires_confirmation=True),
        _s("notes", "Notes", "Free-form note stored with the model configuration.",
           "text", "Model", runtime_effect="Displayed in model management."),
    ),
    "system": (
        # -- Users ---------------------------------------------------------- #
        _s("session_timeout_minutes", "Session timeout", "Lifetime of an issued JWT.",
           "integer", "Users", minimum=5, maximum=10080, step=5, unit="min",
           runtime_effect="Applied to every token issued after the change."),
        _s("password_min_length", "Minimum password length", "Shortest accepted password.",
           "integer", "Users", minimum=8, maximum=128, step=1, unit="chars",
           runtime_effect="Enforced when creating or resetting a user."),
        _s("enforce_strong_password", "Require mixed passwords", "Passwords must contain letters and numbers.",
           "boolean", "Users", dangerous=True,
           runtime_effect="Strength validation applied on create and reset.",
           requires_confirmation=True),
        _s("max_failed_logins", "Failed logins before lockout", "Failed attempts allowed before an account is disabled.",
           "integer", "Users", minimum=3, maximum=100, step=1, unit="attempts",
           runtime_effect="Evaluated by the login endpoint."),
        _s("lockout_minutes", "Lockout duration", "How long an account stays locked.",
           "integer", "Users", minimum=1, maximum=1440, step=1, unit="min",
           runtime_effect="Evaluated by the login endpoint."),
        # -- Security ------------------------------------------------------- #
        _s("ip_allowlist_enabled", "IP allowlist", "Restrict the console to allowlisted addresses.",
           "boolean", "Security", dangerous=True,
           runtime_effect="Requests from non-allowlisted addresses are rejected.",
           requires_confirmation=True),
        _s("ip_allowlist", "Allowed addresses", "Addresses permitted to use the console.",
           "list", "Security", runtime_effect="Checked when the IP allowlist is enabled."),
        # -- Data retention ------------------------------------------------- #
        _s("prediction_retention_days", "Prediction retention", "Days flow results are kept.",
           "integer", "Data Retention", minimum=1, maximum=3650, step=1, unit="days",
           runtime_effect="Used by the retention service."),
        _s("alert_retention_days", "Alert retention", "Days alerts are kept.",
           "integer", "Data Retention", minimum=1, maximum=3650, step=1, unit="days",
           runtime_effect="Used by the retention service."),
        _s("investigation_retention_days", "Investigation retention", "Days investigations are kept.",
           "integer", "Data Retention", minimum=1, maximum=3650, step=1, unit="days",
           runtime_effect="Used by the retention service."),
        _s("audit_retention_days", "Audit retention", "Days audit entries are kept.",
           "integer", "Data Retention", minimum=30, maximum=3650, step=30, unit="days",
           runtime_effect="Used by the retention service; audit history is never deleted below 30 days."),
        _s("dataset_retention_days", "Dataset retention", "Days datasets are kept (0 keeps them forever).",
           "integer", "Data Retention", minimum=0, maximum=3650, step=1, unit="days",
           runtime_effect="0 disables automatic dataset deletion."),
        _s("auto_purge_enabled", "Automatic purge", "Purge expired records on a schedule.",
           "boolean", "Data Retention", dangerous=True,
           runtime_effect="Enables the retention sweep.",
           requires_confirmation=True),
        # -- System / logging ----------------------------------------------- #
        _s("log_level", "Log level", "Verbosity of the application log.",
           "choice", "System", choices=LOG_LEVELS, runtime_effect="Applied to the logger immediately."),
        _s("log_retention_days", "Log retention", "Days request logs are kept.",
           "integer", "System", minimum=1, maximum=3650, step=1, unit="days",
           runtime_effect="Used by the retention service."),
        _s("log_requests", "Log requests", "Write an access log entry per request.",
           "boolean", "System", runtime_effect="Toggles the request logging middleware."),
        _s("maintenance_message", "Maintenance message", "Message shown while the platform is in maintenance mode.",
           "text", "System", runtime_effect="Displayed in the console header."),
        # -- API ------------------------------------------------------------ #
        _s("api_docs_enabled", "API documentation", "Serve /docs and /redoc.",
           "boolean", "API", dangerous=True,
           runtime_effect="Hides the interactive documentation when disabled.",
           requires_confirmation=True),
        _s("api_rate_limit_default", "Default rate limit", "Requests per minute allowed per client.",
           "text", "API", runtime_effect="Default limit applied to unlisted API routes."),
        _s("cors_origins", "CORS origins", "Comma-separated list of allowed browser origins.",
           "text", "API", runtime_effect="Applied to the CORS middleware on restart."),
        # -- Dashboard ------------------------------------------------------ #
        _s("dashboard_refresh_seconds", "Dashboard refresh", "Auto-refresh interval for dashboards.",
           "integer", "Dashboard", minimum=10, maximum=3600, step=5, unit="s",
           runtime_effect="Client polling interval."),
        _s("dashboard_default_window_hours", "Default dashboard window", "Time window pre-selected on dashboards.",
           "integer", "Dashboard", minimum=1, maximum=720, step=1, unit="h",
           runtime_effect="Default statistics window."),
        _s("show_data_provenance", "Show data provenance", "Label simulated and uploaded data in the UI.",
           "boolean", "Dashboard", runtime_effect="Shows live/simulated labels on the dashboards."),
        # -- Notifications -------------------------------------------------- #
        _s("notifications_enabled", "Notifications", "Master switch for in-app notifications.",
           "boolean", "Notifications", runtime_effect="When disabled no notifications are created.",
           requires_confirmation=True),
        _s("notify_severities", "Notify on severities", "Severities that produce a notification.",
           "list", "Notifications", choices=SEVERITIES,
           runtime_effect="Alerts at these severities create a notification entry."),
        _s("notify_admins_on_critical", "Notify admins on CRITICAL", "Notify admins when a CRITICAL alert is raised.",
           "boolean", "Notifications", runtime_effect="Adds an admin-targeted notification."),
        _s("notify_email", "Notification email", "Address notified about critical events.",
           "text", "Notifications", runtime_effect="Included in the notification payload."),
        _s("notify_webhook_url", "Notification webhook", "Webhook notified about critical events.",
           "text", "Notifications", runtime_effect="Included in the notification payload."),
        _s("notification_digest_minutes", "Digest interval", "Minutes between notification digests.",
           "integer", "Notifications", minimum=5, maximum=1440, step=5, unit="min",
           runtime_effect="Digest cadence."),
    ),
}

#: Specs that are cross-linked: changing one also changes the other so the two
#: configuration scopes can never disagree.
CROSS_LINKS: dict[str, dict[str, str]] = {
    "network": {
        "detection_sensitivity": "detection.detection_sensitivity",
        "analysis_interval_seconds": "detection.analysis_interval_seconds",
        "analysis_batch_size": "detection.analysis_batch_size",
    },
    "detection": {
        "detection_sensitivity": "network.detection_sensitivity",
        "analysis_interval_seconds": "network.analysis_interval_seconds",
        "analysis_batch_size": "network.analysis_batch_size",
    },
}

SPEC_INDEX: dict[str, SettingSpec] = {spec.key: spec for specs in SPECS.values() for spec in specs}


# --------------------------------------------------------------------------- #
# Read / write
# --------------------------------------------------------------------------- #
def get_row(db: Session, scope: str):
    model = MODELS[scope]
    return model.load(db)


def defaults(scope: str) -> dict[str, Any]:
    """The safe default for every field of ``scope`` (never touches the database)."""
    model = MODELS[scope]
    json_defaults = JSON_DEFAULTS.get(scope, {})
    out: dict[str, Any] = {}
    for key in (spec.key for spec in SPECS[scope]):
        if key in json_defaults:
            out[key] = list(json_defaults[key])
            continue
        column = model.__table__.columns.get(key)
        if column is None:
            continue
        default = getattr(column, "default", None)
        out[key] = default.arg if default is not None and hasattr(default, "arg") else None
    return out


def read(db: Session, scope: str) -> dict[str, Any]:
    """Current persisted values merged over the defaults."""
    row = get_row(db, scope)
    values = defaults(scope)
    for key in values:
        value = getattr(row, key, None)
        if value is None and key in JSON_DEFAULTS.get(scope, {}):
            value = list(JSON_DEFAULTS[scope][key])
        values[key] = value
    values["_updated_at"] = row.updated_at.isoformat() if row.updated_at else None
    values["_updated_by"] = row.updated_by
    return values


def read_all(db: Session) -> dict[str, dict[str, Any]]:
    return {scope: read(db, scope) for scope in SCOPES}


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
class ConfigValidationError(ValueError):
    """Raised with a field -> message mapping when a payload is invalid."""

    def __init__(self, errors: dict[str, str]):
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def validate_value(scope: str, key: str, value: Any) -> tuple[Any, str | None]:
    """Coerce and range-check a single value. Returns ``(value, error)``."""
    spec = SPEC_INDEX.get(key)
    if spec is None:
        return value, f"Unknown setting '{key}'."

    try:
        if spec.type == "integer":
            coerced: Any = int(round(float(value)))
            if spec.minimum is not None and coerced < spec.minimum:
                return None, f"must be at least {_fmt(spec.minimum)}"
            if spec.maximum is not None and coerced > spec.maximum:
                return None, f"must be at most {_fmt(spec.maximum)}"
        elif spec.type == "number":
            coerced = float(value)
            if coerced != coerced:  # NaN
                return None, "must be a number"
            if spec.minimum is not None and coerced < spec.minimum:
                return None, f"must be at least {_fmt(spec.minimum)}"
            if spec.maximum is not None and coerced > spec.maximum:
                return None, f"must be at most {_fmt(spec.maximum)}"
        elif spec.type == "boolean":
            if isinstance(value, bool):
                coerced = value
            elif isinstance(value, str) and value.strip().lower() in {"true", "false", "1", "0", "on", "off"}:
                coerced = value.strip().lower() in {"true", "1", "on"}
            elif isinstance(value, (int, float)) and value in (0, 1):
                coerced = bool(value)
            else:
                return None, "must be true or false"
        elif spec.type == "list":
            if value is None:
                coerced = []
            elif isinstance(value, str):
                coerced = [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
            elif isinstance(value, (list, tuple, set)):
                coerced = [str(item).strip() for item in value if str(item).strip()]
            else:
                return None, "must be a list of values"
            if spec.choices:
                invalid = [item for item in coerced if item not in spec.choices]
                if invalid:
                    return None, f"contains unsupported value(s): {', '.join(invalid)}"
        elif spec.type == "choice":
            coerced = str(value).strip()
            if spec.choices and coerced not in spec.choices:
                return None, f"must be one of: {', '.join(spec.choices)}"
        else:  # text
            coerced = "" if value is None else str(value)
            if len(coerced) > 512:
                return None, "must be at most 512 characters"
            if spec.key in {"network_name", "active_version"} and not coerced.strip():
                return None, "must not be empty"
        return coerced, None
    except (TypeError, ValueError):
        return None, f"is not a valid {spec.type}"


def _fmt(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


def validate(scope: str, payload: dict[str, Any], db: Session | None = None) -> dict[str, Any]:
    """
    Validate a partial payload for ``scope``; raises :class:`ConfigValidationError`.

    Pass ``db`` so cross-field invariants are checked against the *stored* values
    rather than only the fields present in ``payload``.
    """
    if scope not in MODELS:
        raise ConfigValidationError({"scope": f"unknown configuration scope '{scope}'"})
    if db is not None:
        for name in SCOPES:
            _current_cache[name] = read(db, name)
    errors: dict[str, str] = {}
    cleaned: dict[str, Any] = {}
    for key, value in (payload or {}).items():
        if key.startswith("_"):
            continue
        if key not in SPEC_INDEX:
            errors[key] = "Unknown setting."
            continue
        coerced, error = validate_value(scope, key, value)
        if error:
            errors[key] = error
        else:
            cleaned[key] = coerced
    if errors:
        raise ConfigValidationError(errors)

    _validate_relations(scope, cleaned, errors)
    if errors:
        raise ConfigValidationError(errors)
    return cleaned


def _validate_relations(scope: str, cleaned: dict[str, Any], errors: dict[str, str]) -> None:
    """Cross-field invariants - these are what keep a configuration coherent."""
    current = {**_cached_current(scope), **cleaned}
    if scope in {"detection", "network"}:
        medium = current.get("risk_medium_threshold")
        high = current.get("risk_high_threshold")
        critical = current.get("risk_critical_threshold")
        if None not in (medium, high) and medium >= high:
            errors["risk_medium_threshold"] = "must be lower than the HIGH threshold"
        if None not in (high, critical) and high >= critical:
            errors["risk_high_threshold"] = "must be lower than the CRITICAL threshold"
    if scope == "alerts":
        low_max = current.get("severity_low_max")
        medium_max = current.get("severity_medium_max")
        high_max = current.get("severity_high_max")
        if None not in (low_max, medium_max) and low_max >= medium_max:
            errors["severity_low_max"] = "must be lower than the MEDIUM ceiling"
        if None not in (medium_max, high_max) and medium_max >= high_max:
            errors["severity_medium_max"] = "must be lower than the HIGH ceiling"
        if current.get("max_individual_alerts") and current.get("max_individual_alerts") > current.get("max_alerts_per_job", 0):
            errors["max_individual_alerts"] = "cannot exceed the maximum alerts per job"
    if scope == "model":
        if not str(current.get("active_version") or "").strip():
            errors["active_version"] = "must not be empty"


_current_cache: dict[str, dict[str, Any]] = {}


def _cached_current(scope: str) -> dict[str, Any]:
    """Last known values for a scope, used only for cross-field validation."""
    return _current_cache.get(scope, {})


def prime_cache(db: Session) -> None:
    """Warm the cross-field validation cache (called once at startup)."""
    for scope in SCOPES:
        try:
            _current_cache[scope] = read(db, scope)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("could not prime config cache for %s: %s", scope, exc)


def update(
    db: Session,
    scope: str,
    payload: dict[str, Any],
    *,
    user: Any = None,
    request: Any = None,
    note: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Validate, persist and audit a configuration change.

    Validation happens first, so a rejected payload never reaches the database.
    On success the change is committed together with its revision history and
    audit entries, and the returned payload carries the applied values plus the
    per-field before/after diff.
    """
    cleaned = validate(scope, payload, db=db)

    dangerous = [key for key in cleaned if SPEC_INDEX[key].requires_confirmation]
    if dangerous and not confirm:
        raise ConfigValidationError(
            {
                "__confirm__": (
                    "This change affects alerting or detection behaviour and needs explicit "
                    f"confirmation: {', '.join(sorted(dangerous))}"
                )
            }
        )

    model = MODELS[scope]
    row = get_row(db, scope)
    before = read(db, scope)

    changes: dict[str, dict[str, Any]] = {}
    for key, value in cleaned.items():
        previous = before.get(key)
        if _equal(previous, value):
            continue
        setattr(row, key, value)
        changes[key] = {"previous": previous, "new": value}

    if not changes:
        return {"scope": scope, "changed": {}, "unchanged": list(cleaned), "values": before}

    row.updated_by = getattr(user, "id", None)
    db.flush()

    now = datetime.now(timezone.utc)
    for key, change in changes.items():
        db.add(
            ConfigurationRevision(
                scope=scope,
                key=key,
                previous_value={"value": change["previous"]},
                new_value={"value": change["new"]},
                changed_by=getattr(user, "id", None),
                changed_by_email=getattr(user, "email", None),
                changed_by_role=getattr(user, "role", None),
                ip_address=audit_service.client_ip(request),
                note=note,
                changed_at=now,
            )
        )

    audit_service.record_change(
        db,
        scope=scope,
        changes=changes,
        user=user,
        request=request,
        resource=f"configuration:{scope}",
        note=note,
    )

    for linked_scope, links in CROSS_LINKS.items():
        for key, target in links.items():
            if target != f"{scope}.{key}" or key not in changes:
                continue
            target_scope, target_key = target.split(".", 1)
            _propagate(db, target_scope, target_key, changes[key]["new"], user=user, request=request)

    db.commit()
    _current_cache[scope] = read(db, scope)
    invalidate_runtime_cache()
    logger.info("configuration %s updated by %s: %s", scope, getattr(user, "email", "system"), sorted(changes))
    return {"scope": scope, "changed": changes, "unchanged": [], "values": read(db, scope), "model": model.__name__}


def _propagate(db: Session, scope: str, key: str, value: Any, *, user: Any, request: Any) -> None:
    """Keep a cross-linked setting identical in its sibling scope."""
    row = get_row(db, scope)
    current = getattr(row, key, None)
    if _equal(current, value):
        return
    setattr(row, key, value)
    row.updated_by = getattr(user, "id", None)
    db.add(
        ConfigurationRevision(
            scope=scope,
            key=key,
            previous_value={"value": current},
            new_value={"value": value},
            changed_by=getattr(user, "id", None),
            changed_by_email=getattr(user, "email", None),
            changed_by_role=getattr(user, "role", None),
            ip_address=audit_service.client_ip(request),
            note="synchronised from a linked setting",
        )
    )
    audit_service.record(
        db,
        action=f"{scope}.{key}_synchronised",
        user=user,
        request=request,
        category=audit_service.CAT_SETTINGS,
        resource=f"configuration:{scope}",
        previous_value={"value": current},
        new_value={"value": value},
        detail={"reason": "cross-linked setting"},
    )


def _equal(a: Any, b: Any) -> bool:
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return list(a) == list(b)
    if isinstance(a, float) or isinstance(b, float):
        try:
            return abs(float(a) - float(b)) < 1e-9
        except (TypeError, ValueError):
            return False
    return a == b


# --------------------------------------------------------------------------- #
# Describe (settings UI contract)
# --------------------------------------------------------------------------- #
def describe(db: Session, scope: str | None = None) -> dict[str, Any]:
    """Field metadata + current values, grouped into the UI sections."""
    scopes = [scope] if scope in MODELS else list(SCOPES)
    payload_scopes: dict[str, Any] = {}
    sections: list[dict] = []

    for name in scopes:
        values = read(db, name)
        fields = [
            {**spec.to_dict(), "value": values.get(spec.key), "default": defaults(name).get(spec.key)}
            for spec in SPECS[name]
        ]
        payload_scopes[name] = {
            "scope": name,
            "title": SCOPE_TITLES[name],
            "description": SCOPE_DESCRIPTIONS[name],
            "updated_at": values.get("_updated_at"),
            "updated_by": values.get("_updated_by"),
            "fields": fields,
            "values": {k: v for k, v in values.items() if not k.startswith("_")},
        }

    if scope in MODELS:
        return payload_scopes[scope]

    ordered_sections: list[str] = []
    for name in scopes:
        for spec in SPECS[name]:
            if spec.section not in ordered_sections:
                ordered_sections.append(spec.section)
    for section_name in ordered_sections:
        section_fields: list[dict] = []
        for name in scopes:
            section_fields.extend(f for f in payload_scopes[name]["fields"] if f["section"] == section_name)
        if section_fields:
            sections.append(
                {
                    "name": section_name,
                    "fields": section_fields,
                    "scopes": sorted({f_scope for f_scope in scopes for f in SPECS[f_scope] if f.section == section_name}),
                }
            )
    return {"scopes": payload_scopes, "sections": sections}


def revision_history(db: Session, scope: str | None = None, limit: int = 100) -> list[dict]:
    from sqlalchemy import select

    stmt = select(ConfigurationRevision).order_by(ConfigurationRevision.changed_at.desc()).limit(min(limit, 500))
    if scope:
        stmt = stmt.where(ConfigurationRevision.scope == scope)
    return [row.to_dict() for row in db.scalars(stmt).all()]


# --------------------------------------------------------------------------- #
# Runtime snapshot
# --------------------------------------------------------------------------- #
@dataclass
class RuntimeConfig:
    """Effective values the running application uses, status profile applied."""

    status: str = "normal"
    status_source: str = "automatic"
    profile: dict[str, Any] = field(default_factory=dict)
    detection_sensitivity: str = "balanced"
    risk_medium_threshold: float = 0.65
    risk_high_threshold: float = 0.85
    risk_critical_threshold: float = 0.96
    alert_threshold: float = 0.65
    risk_threshold: float = 0.85
    min_confidence_to_alert: float = 0.5
    min_confidence_to_store: float = 0.0
    prediction_threshold: float = 0.5
    sensitive_port_bonus: float = 0.05
    alerts_enabled: bool = True
    min_severity_to_alert: str = "medium"
    duplicate_handling: str = "aggregate"
    max_alerts_per_job: int = 300
    max_individual_alerts: int = 50
    auto_incident_creation: bool = True
    auto_incident_severity: str = "critical"
    escalation_enabled: bool = True
    escalate_after_minutes: int = 30
    escalate_to_severity: str = "high"
    analysis_interval_seconds: int = 60
    analysis_batch_size: int = 2000
    max_rows_per_job: int = 200000
    store_predictions_limit: int = 50000
    job_workers: int = 2
    max_upload_size_mb: int = 25
    allowed_file_formats: list[str] = field(default_factory=lambda: list(JSON_DEFAULTS["network"]["allowed_file_formats"]))
    highlight_suspicious: bool = False
    enhanced_investigation: bool = False
    preserve_investigation_logs: bool = False
    model_enabled: bool = True
    explanations_enabled: bool = True
    shap_enabled: bool = True
    explanation_top_k: int = 8
    notifications_enabled: bool = True
    network_name: str = "Primary Network"
    banner: str | None = None
    banner_tone: str | None = None
    banner_label: str | None = None
    traffic_load_warning: bool = False
    admin_notification: bool = False
    maintenance_message: str | None = None

    @property
    def max_upload_size_bytes(self) -> int:
        return int(self.max_upload_size_mb) * 1024 * 1024

    def risk_thresholds(self) -> dict[str, float]:
        return {
            "medium": round(self.risk_medium_threshold, 6),
            "high": round(self.risk_high_threshold, 6),
            "critical": round(self.risk_critical_threshold, 6),
        }

    def alertable_levels(self) -> set[str]:
        """Severity levels that may raise an alert under the current configuration."""
        if not self.alerts_enabled:
            return set()
        floor = SEVERITIES.index(self.min_severity_to_alert) if self.min_severity_to_alert in SEVERITIES else 1
        return set(SEVERITIES[floor:])

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "status_source": self.status_source,
            "detection_sensitivity": self.detection_sensitivity,
            "risk_thresholds": self.risk_thresholds(),
            "alert_threshold": round(self.alert_threshold, 6),
            "risk_threshold": round(self.risk_threshold, 6),
            "min_confidence_to_alert": round(self.min_confidence_to_alert, 6),
            "min_confidence_to_store": round(self.min_confidence_to_store, 6),
            "prediction_threshold": round(self.prediction_threshold, 6),
            "sensitive_port_bonus": round(self.sensitive_port_bonus, 6),
            "alerts_enabled": self.alerts_enabled,
            "min_severity_to_alert": self.min_severity_to_alert,
            "alertable_levels": sorted(self.alertable_levels()),
            "duplicate_handling": self.duplicate_handling,
            "max_alerts_per_job": self.max_alerts_per_job,
            "max_individual_alerts": self.max_individual_alerts,
            "auto_incident_creation": self.auto_incident_creation,
            "auto_incident_severity": self.auto_incident_severity,
            "escalation_enabled": self.escalation_enabled,
            "escalate_after_minutes": self.escalate_after_minutes,
            "escalate_to_severity": self.escalate_to_severity,
            "analysis_interval_seconds": self.analysis_interval_seconds,
            "analysis_batch_size": self.analysis_batch_size,
            "max_rows_per_job": self.max_rows_per_job,
            "store_predictions_limit": self.store_predictions_limit,
            "job_workers": self.job_workers,
            "max_upload_size_mb": self.max_upload_size_mb,
            "max_upload_size_bytes": self.max_upload_size_bytes,
            "allowed_file_formats": list(self.allowed_file_formats),
            "highlight_suspicious": self.highlight_suspicious,
            "enhanced_investigation": self.enhanced_investigation,
            "preserve_investigation_logs": self.preserve_investigation_logs,
            "model_enabled": self.model_enabled,
            "explanations_enabled": self.explanations_enabled,
            "shap_enabled": self.shap_enabled,
            "explanation_top_k": self.explanation_top_k,
            "notifications_enabled": self.notifications_enabled,
            "network_name": self.network_name,
            "banner": self.banner,
            "banner_tone": self.banner_tone,
            "banner_label": self.banner_label,
            "traffic_load_warning": self.traffic_load_warning,
            "admin_notification": self.admin_notification,
            "maintenance_message": self.maintenance_message,
        }


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def runtime_snapshot(db: Session, status: str | None = None, source: str | None = None) -> RuntimeConfig:
    """
    Build the effective configuration for this request.

    Order of operations (all values come from the database):

    1. configured baseline;
    2. sensitivity multiplier on the risk thresholds;
    3. the current network status profile (threshold deltas + cadence multipliers);
    4. clamping so the result is always a valid, ordered threshold set.
    """
    network = read(db, "network")
    detection = read(db, "detection")
    alerts = read(db, "alerts")
    model = read(db, "model")
    system = read(db, "system")

    if status is None or source is None:
        row = db.get(NetworkStatus, NetworkStatus.SINGLETON_ID)
        status = status or (row.status if row else network_modes.STATUS_NORMAL)
        source = source or (row.source if row else network_modes.SOURCE_SYSTEM)

    profile = network_modes.profile(status)

    sensitivity = profile.get("sensitivity_override") or detection.get("detection_sensitivity") or "balanced"
    multiplier = SENSITIVITY_MULTIPLIERS.get(sensitivity, 1.0)

    medium = _clamp(float(detection.get("risk_medium_threshold") or 0.65) * multiplier, 0.0, 1.0)
    high = _clamp(float(detection.get("risk_high_threshold") or 0.85) * multiplier, 0.0, 1.0)
    critical = _clamp(float(detection.get("risk_critical_threshold") or 0.96) * multiplier, 0.0, 1.0)
    high = max(high, medium + 0.01)
    critical = max(critical, high + 0.01)
    critical = min(critical, 1.0)

    alert_threshold = _clamp(
        float(network.get("alert_threshold") or 0.65) + float(profile.get("alert_threshold_delta") or 0.0), 0.0, 1.0
    )
    risk_threshold = _clamp(
        float(network.get("risk_threshold") or 0.85) + float(profile.get("risk_threshold_delta") or 0.0), 0.0, 1.0
    )

    interval = max(5, int(round(float(detection.get("analysis_interval_seconds") or 60) * float(profile.get("analysis_interval_multiplier") or 1.0))))
    batch = max(50, int(round(float(detection.get("analysis_batch_size") or 2000) * float(profile.get("batch_size_multiplier") or 1.0))))

    # ``duplicate_handling`` is the setting the admin console edits, so it wins.  The
    # legacy ``network.duplicate_suppression`` boolean is consulted only when the
    # mode is genuinely unset: it defaults to True, and letting it override the
    # mode silently forced "suppress" and ignored whatever the admin picked.
    mode = str(alerts.get("duplicate_handling") or "").strip()
    if mode not in DUPLICATE_HANDLINGS:
        duplicate = profile.get("duplicate_suppression")
        if duplicate is None:
            duplicate = bool(network.get("duplicate_suppression", True))
        mode = "suppress" if duplicate else "aggregate"

    return RuntimeConfig(
        status=status,
        status_source=source,
        profile=profile,
        detection_sensitivity=sensitivity,
        risk_medium_threshold=medium,
        risk_high_threshold=high,
        risk_critical_threshold=critical,
        alert_threshold=alert_threshold,
        risk_threshold=risk_threshold,
        min_confidence_to_alert=float(detection.get("min_confidence_to_alert") or 0.0),
        min_confidence_to_store=max(
            float(detection.get("min_confidence_to_store") or 0.0), float(model.get("min_confidence_to_store") or 0.0)
        ),
        prediction_threshold=float(model.get("prediction_threshold") or 0.5),
        sensitive_port_bonus=float(detection.get("sensitive_port_bonus") or 0.0),
        alerts_enabled=bool(alerts.get("alerts_enabled", True)) and bool(network.get("auto_alert_generation", True)),
        min_severity_to_alert=str(alerts.get("min_severity_to_alert") or "medium"),
        duplicate_handling=mode,
        max_alerts_per_job=int(alerts.get("max_alerts_per_job") or 300),
        max_individual_alerts=int(alerts.get("max_individual_alerts") or 0),
        auto_incident_creation=bool(network.get("auto_incident_creation", True)),
        auto_incident_severity=str(alerts.get("auto_incident_severity") or "critical"),
        escalation_enabled=bool(alerts.get("escalation_enabled", True)),
        escalate_after_minutes=int(alerts.get("escalate_after_minutes") or 30),
        escalate_to_severity=str(alerts.get("escalate_to_severity") or "high"),
        analysis_interval_seconds=interval,
        analysis_batch_size=batch,
        max_rows_per_job=int(detection.get("max_rows_per_job") or 200000),
        store_predictions_limit=int(detection.get("store_predictions_limit") or 50000),
        job_workers=int(detection.get("job_workers") or 2),
        max_upload_size_mb=int(network.get("max_upload_size_mb") or 25),
        allowed_file_formats=list(network.get("allowed_file_formats") or JSON_DEFAULTS["network"]["allowed_file_formats"]),
        highlight_suspicious=bool(detection.get("highlight_suspicious")) or bool(profile.get("highlight_suspicious")),
        enhanced_investigation=bool(detection.get("enhanced_investigation")) or bool(profile.get("enhanced_investigation")),
        preserve_investigation_logs=bool(detection.get("preserve_investigation_logs"))
        or bool(profile.get("preserve_investigation_logs")),
        model_enabled=bool(model.get("enabled", True)),
        explanations_enabled=bool(model.get("explanations_enabled", True)),
        shap_enabled=bool(model.get("shap_enabled", True)),
        explanation_top_k=int(model.get("explanation_top_k") or 8),
        notifications_enabled=bool(system.get("notifications_enabled", True)),
        network_name=str(network.get("network_name") or "Primary Network"),
        banner=profile.get("banner"),
        banner_tone=profile.get("banner_tone"),
        banner_label=profile.get("label"),
        traffic_load_warning=bool(profile.get("traffic_load_warning")),
        admin_notification=bool(profile.get("admin_notification")),
        maintenance_message=system.get("maintenance_message"),
    )


def status_configuration_snapshot(db: Session) -> dict[str, Any]:
    """The subset of configuration stored alongside a status change."""
    runtime = runtime_snapshot(db)
    values = read(db, "network")
    return {
        "status": runtime.status,
        "status_source": runtime.status_source,
        "mode_label": runtime.profile.get("label"),
        "detection_sensitivity": runtime.detection_sensitivity,
        "risk_thresholds": runtime.risk_thresholds(),
        "alert_threshold": round(runtime.alert_threshold, 6),
        "analysis_interval_seconds": runtime.analysis_interval_seconds,
        "analysis_batch_size": runtime.analysis_batch_size,
        "min_severity_to_alert": runtime.min_severity_to_alert,
        "alerts_enabled": runtime.alerts_enabled,
        "duplicate_handling": runtime.duplicate_handling,
        "traffic_load_warning": runtime.traffic_load_warning,
        "enhanced_investigation": runtime.enhanced_investigation,
        "network_name": values.get("network_name"),
        "environment": values.get("environment"),
    }


def sections_for_frontend() -> list[dict]:
    """Section ordering used by the admin settings page (no database needed)."""
    seen: list[str] = []
    for scope in SCOPES:
        for spec in SPECS[scope]:
            if spec.section not in seen:
                seen.append(spec.section)
    return [{"name": name} for name in seen]


# --------------------------------------------------------------------------- #
# Process-level cache
# --------------------------------------------------------------------------- #
# Middleware and background workers have no request-scoped session, so they read
# the effective configuration through this short-lived cache.  It is invalidated
# explicitly on every write (and on status changes), which is what makes an admin
# change take effect immediately rather than "on the next restart".
_RUNTIME_CACHE: dict[str, Any] = {"value": None, "at": -1.0}
_RUNTIME_TTL_SECONDS = 5.0


def invalidate_runtime_cache() -> None:
    """Force the next :func:`get_runtime` call to re-read the database."""
    _RUNTIME_CACHE["value"] = None
    _RUNTIME_CACHE["at"] = -1.0


def get_runtime(max_age: float = _RUNTIME_TTL_SECONDS, db: Session | None = None) -> RuntimeConfig:
    """Effective configuration for callers without a request-scoped session."""
    import time

    cached = _RUNTIME_CACHE["value"]
    if cached is not None and (time.monotonic() - _RUNTIME_CACHE["at"]) < max_age:
        return cached
    if db is not None:
        snapshot = runtime_snapshot(db)
    else:
        from app.db.session import SessionLocal

        session = SessionLocal()
        try:
            snapshot = runtime_snapshot(session)
        finally:
            session.close()
    _RUNTIME_CACHE["value"] = snapshot
    _RUNTIME_CACHE["at"] = time.monotonic()
    return snapshot


def supported_upload_extensions() -> tuple[str, ...]:
    return SUPPORTED_UPLOAD_FORMATS


def known_scopes() -> Iterable[str]:
    return SCOPES
