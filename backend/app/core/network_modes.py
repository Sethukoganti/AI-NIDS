"""
Operational network statuses and the behaviour each one applies.

Two separate concerns live here, and keeping them apart is deliberate:

1. :data:`STATUSES` describes the *operational state* an admin can put the NIDS
   into (``normal``, ``high_traffic``, ...).  A status is a declaration made by an
   operator or by the threshold evaluator - it is never a claim that the platform
   observed a specific attack.

2. :data:`MODE_PROFILES` describes how the *configuration* changes in each state.
   Every entry is a set of multipliers/deltas applied to the values the admin
   configured, plus presentation flags.  Nothing here invents thresholds: a mode
   can only shift the configured baseline, and the baseline itself always comes
   from the database.

The ``source`` of a status (``manual`` / ``automatic`` / ``system``) is stored
with it so the UI can always show how the current state was reached.
"""

from __future__ import annotations

STATUS_NORMAL = "normal"
STATUS_HIGH_TRAFFIC = "high_traffic"
STATUS_UNDER_INVESTIGATION = "under_investigation"
STATUS_ELEVATED_THREAT = "elevated_threat"
STATUS_CRITICAL_THREAT = "critical_threat"
STATUS_MAINTENANCE = "maintenance"

VALID_STATUSES: tuple[str, ...] = (
    STATUS_NORMAL,
    STATUS_HIGH_TRAFFIC,
    STATUS_UNDER_INVESTIGATION,
    STATUS_ELEVATED_THREAT,
    STATUS_CRITICAL_THREAT,
    STATUS_MAINTENANCE,
)

#: Ascending order of operational urgency (used for sorting and "at least" checks).
STATUS_SEVERITY_ORDER: dict[str, int] = {
    STATUS_MAINTENANCE: 0,
    STATUS_NORMAL: 1,
    STATUS_UNDER_INVESTIGATION: 2,
    STATUS_HIGH_TRAFFIC: 3,
    STATUS_ELEVATED_THREAT: 4,
    STATUS_CRITICAL_THREAT: 5,
}

SOURCE_MANUAL = "manual"
SOURCE_AUTOMATIC = "automatic"
SOURCE_SYSTEM = "system"
VALID_SOURCES: tuple[str, ...] = (SOURCE_MANUAL, SOURCE_AUTOMATIC, SOURCE_SYSTEM)

#: Statuses the automatic evaluator is allowed to select.  ``maintenance`` and
#: ``under_investigation`` are human decisions and are never auto-applied.
AUTO_ASSIGNABLE: tuple[str, ...] = (
    STATUS_NORMAL,
    STATUS_HIGH_TRAFFIC,
    STATUS_ELEVATED_THREAT,
    STATUS_CRITICAL_THREAT,
)

STATUS_DEFINITIONS: dict[str, dict] = {
    STATUS_NORMAL: {
        "label": "Normal",
        "description": "Normal monitoring operation with the configured baseline detection profile.",
        "tone": "success",
        "evaluable": True,
    },
    STATUS_HIGH_TRAFFIC: {
        "label": "High Traffic",
        "description": (
            "High-volume traffic operating condition: batch processing is optimised, the analysis "
            "interval may be widened and duplicate alerts are suppressed to protect the queue."
        ),
        "tone": "info",
        "evaluable": True,
    },
    STATUS_UNDER_INVESTIGATION: {
        "label": "Under Investigation",
        "description": "Analysts or admins are actively investigating suspicious activity.",
        "tone": "warning",
        "evaluable": False,
    },
    STATUS_ELEVATED_THREAT: {
        "label": "Elevated Threat",
        "description": (
            "Configured indicators require increased monitoring: monitoring frequency rises, "
            "alert thresholds are lowered where configured and suspicious traffic is highlighted."
        ),
        "tone": "warning",
        "evaluable": True,
    },
    STATUS_CRITICAL_THREAT: {
        "label": "Critical Threat",
        "description": (
            "Configured rules indicate a critical condition: high-priority alerts, prominent "
            "security warnings, preserved investigation logs and admin notifications."
        ),
        "tone": "danger",
        "evaluable": True,
    },
    STATUS_MAINTENANCE: {
        "label": "Maintenance",
        "description": "The NIDS is undergoing maintenance or reconfiguration.",
        "tone": "neutral",
        "evaluable": False,
    },
}

# --------------------------------------------------------------------------- #
# Behaviour profiles
# --------------------------------------------------------------------------- #
# Multipliers/deltas are applied to the admin-configured baseline, e.g.
#     effective_alert_threshold = clamp(baseline + alert_threshold_delta)
#     effective_interval        = round(baseline * analysis_interval_multiplier)
#
# ``banner`` drives the visible security warning, ``highlight_suspicious`` /
# ``enhanced_investigation`` / ``preserve_investigation_logs`` drive the analyst
# experience, and ``traffic_load_warning`` flags a high-volume condition.
MODE_PROFILES: dict[str, dict] = {
    STATUS_NORMAL: {
        "label": "NORMAL MODE",
        "headline": "Standard detection sensitivity, normal alert threshold, standard logging.",
        "alert_threshold_delta": 0.0,
        "risk_threshold_delta": 0.0,
        "sensitivity_override": None,
        "analysis_interval_multiplier": 1.0,
        "batch_size_multiplier": 1.0,
        "log_verbosity": None,
        "duplicate_suppression": None,
        "highlight_suspicious": False,
        "enhanced_investigation": False,
        "preserve_investigation_logs": False,
        "traffic_load_warning": False,
        "banner": None,
        "banner_tone": None,
        "admin_notification": False,
    },
    STATUS_HIGH_TRAFFIC: {
        "label": "HIGH TRAFFIC MODE",
        "headline": (
            "Batch processing is optimised, the analysis interval is widened and duplicate "
            "alerts are suppressed so the pipeline keeps up with the traffic volume."
        ),
        "alert_threshold_delta": 0.05,
        "risk_threshold_delta": 0.0,
        "sensitivity_override": None,
        "analysis_interval_multiplier": 2.0,
        "batch_size_multiplier": 2.0,
        "log_verbosity": None,
        "duplicate_suppression": True,
        "highlight_suspicious": False,
        "enhanced_investigation": False,
        "preserve_investigation_logs": False,
        "traffic_load_warning": True,
        "banner": "High traffic volume detected - batch processing optimised, expect slower alert cadence.",
        "banner_tone": "info",
        "admin_notification": False,
    },
    STATUS_UNDER_INVESTIGATION: {
        "label": "UNDER INVESTIGATION",
        "headline": "An investigation is in progress: evidence and notes are preserved.",
        "alert_threshold_delta": 0.0,
        "risk_threshold_delta": 0.0,
        "sensitivity_override": None,
        "analysis_interval_multiplier": 1.0,
        "batch_size_multiplier": 1.0,
        "log_verbosity": None,
        "duplicate_suppression": None,
        "highlight_suspicious": True,
        "enhanced_investigation": True,
        "preserve_investigation_logs": True,
        "traffic_load_warning": False,
        "banner": "Investigation in progress - detailed investigation logging is preserved.",
        "banner_tone": "warning",
        "admin_notification": False,
    },
    STATUS_ELEVATED_THREAT: {
        "label": "ELEVATED THREAT MODE",
        "headline": (
            "Monitoring frequency is increased, alert thresholds are lowered where configured "
            "and suspicious traffic is highlighted across the console."
        ),
        "alert_threshold_delta": -0.10,
        "risk_threshold_delta": -0.05,
        "sensitivity_override": "high",
        "analysis_interval_multiplier": 0.5,
        "batch_size_multiplier": 1.0,
        "log_verbosity": "more",
        "duplicate_suppression": True,
        "highlight_suspicious": True,
        "enhanced_investigation": True,
        "preserve_investigation_logs": True,
        "traffic_load_warning": False,
        "banner": "Elevated threat - monitoring frequency increased and alert thresholds lowered.",
        "banner_tone": "warning",
        "admin_notification": False,
    },
    STATUS_CRITICAL_THREAT: {
        "label": "CRITICAL THREAT MODE",
        "headline": (
            "Monitoring priority is at maximum, high-priority alerts are generated according "
            "to the configured rules, detailed investigation logs are preserved and configured "
            "administrators are notified."
        ),
        "alert_threshold_delta": -0.20,
        "risk_threshold_delta": -0.10,
        "sensitivity_override": "paranoid",
        "analysis_interval_multiplier": 0.25,
        "batch_size_multiplier": 1.0,
        "log_verbosity": "maximum",
        "duplicate_suppression": True,
        "highlight_suspicious": True,
        "enhanced_investigation": True,
        "preserve_investigation_logs": True,
        "traffic_load_warning": False,
        "banner": (
            "CRITICAL THREAT - monitoring priority maximised. Active incidents are shown "
            "prominently and detailed investigation logs are preserved."
        ),
        "banner_tone": "danger",
        "admin_notification": True,
    },
    STATUS_MAINTENANCE: {
        "label": "MAINTENANCE MODE",
        "headline": "The platform is under maintenance: analysis cadence is relaxed.",
        "alert_threshold_delta": 0.10,
        "risk_threshold_delta": 0.05,
        "sensitivity_override": None,
        "analysis_interval_multiplier": 4.0,
        "batch_size_multiplier": 1.0,
        "log_verbosity": None,
        "duplicate_suppression": True,
        "highlight_suspicious": False,
        "enhanced_investigation": False,
        "preserve_investigation_logs": False,
        "traffic_load_warning": False,
        "banner": "Maintenance in progress - detection cadence is relaxed until the mode changes.",
        "banner_tone": "neutral",
        "admin_notification": False,
    },
}


def is_valid_status(status: str | None) -> bool:
    return bool(status) and status in VALID_STATUSES


def is_valid_source(source: str | None) -> bool:
    return bool(source) and source in VALID_SOURCES


def definition(status: str) -> dict:
    return STATUS_DEFINITIONS.get(
        status,
        {"label": str(status), "description": "Unknown status.", "tone": "neutral", "evaluable": False},
    )


def profile(status: str) -> dict:
    return dict(MODE_PROFILES.get(status, MODE_PROFILES[STATUS_NORMAL]))


def severity_of(status: str) -> int:
    return STATUS_SEVERITY_ORDER.get(status, 0)


def is_at_least(status: str, minimum: str) -> bool:
    return severity_of(status) >= severity_of(minimum)


def catalogue() -> list[dict]:
    """Every status with its definition and the behaviour it applies."""
    return [
        {
            "status": status,
            "label": definition(status)["label"],
            "description": definition(status)["description"],
            "tone": definition(status)["tone"],
            "severity": severity_of(status),
            "auto_assignable": status in AUTO_ASSIGNABLE,
            "profile": profile(status),
        }
        for status in VALID_STATUSES
    ]
