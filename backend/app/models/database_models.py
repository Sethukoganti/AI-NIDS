"""
SQLAlchemy ORM models - the AI-NIDS persistence schema.

Tables
------
users                  accounts + roles (admin / analyst)
roles                  role definitions + database-backed permission overrides
datasets               uploaded (or referenced) traffic datasets and their profile
dataset_versions       immutable revisions of a dataset (schema/size history)
analysis_jobs          one row per "Analyze Traffic" run (progress + summary)
predictions            per-flow model output, risk level and key flow features
alerts                 security alerts raised from suspicious predictions
investigations         analyst workspace records built around an alert/flow
detection_statistics   hourly rollup used by the dashboard charts
model_versions         trained model artifacts with approval/deployment state
training_runs          retraining jobs (dataset selection -> approval -> deploy)
network_status         the single row describing the current operational status
network_status_history every status transition with duration, actor and reason
network_configuration  singleton: monitored network + operational parameters
detection_configuration singleton: sensitivity, risk thresholds, analysis cadence
alert_configuration    singleton: alert policy, escalation, de-duplication
model_configuration    singleton: runtime behaviour of the detection model
system_configuration   singleton: security, retention, logging, API, notifications
configuration_revisions append-only history of every configuration change
notifications          in-app notification feed for admins and analysts
audit_logs             authentication / analysis / admin activity trail
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


# --------------------------------------------------------------------------- #
class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="analyst", nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    access_reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    datasets = relationship(
        "Dataset", back_populates="owner", cascade="all, delete-orphan", foreign_keys="Dataset.uploaded_by"
    )
    jobs = relationship("AnalysisJob", back_populates="owner", cascade="all, delete-orphan")

    @property
    def is_active_session(self) -> bool:
        """A session is only usable while the account is enabled."""
        return bool(self.is_active)

    def to_public_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "disabled_at": self.disabled_at.isoformat() if self.disabled_at else None,
            "access_reset_at": self.access_reset_at.isoformat() if self.access_reset_at else None,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
class Role(Base, TimestampMixin):
    """
    A platform role.

    ``permissions`` holds optional, database-backed overrides of the code-defined
    role definition (see ``app.core.rbac``)::

        {"add": ["audit.view"], "remove": ["assistant.use"]}
        {"allow": ["dashboard.view", "alerts.view", "assistant.use"]}

    ``NULL`` permissions means "use the built-in definition unchanged", which
    keeps the default installation free of configuration drift.
    """

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(20), primary_key=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    permissions: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "permissions": self.permissions or {},
            "is_system": self.is_system,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "updated_by": self.updated_by,
        }



# --------------------------------------------------------------------------- #
class Dataset(Base, TimestampMixin):
    __tablename__ = "datasets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    uploaded_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    rows: Mapped[int] = mapped_column(Integer, default=0)
    columns: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="ready")  # ready | invalid | analyzable
    source: Mapped[str] = mapped_column(String(20), default="upload")  # upload | reference | sample

    target_column: Mapped[str | None] = mapped_column(String(120), nullable=True)
    attack_categories: Mapped[list | None] = mapped_column(JSON, nullable=True)
    missing_values: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_rows: Mapped[int] = mapped_column(Integer, default=0)
    numerical_columns: Mapped[int] = mapped_column(Integer, default=0)
    categorical_columns: Mapped[int] = mapped_column(Integer, default=0)
    feature_coverage: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0..1
    schema_matched: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    columns_meta: Mapped[list | None] = mapped_column(JSON, nullable=True)
    class_distribution: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sample_rows: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # --- admin dataset management ----------------------------------------- #
    version: Mapped[int] = mapped_column(Integer, default=1)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    marked_for_training: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    training_note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    owner = relationship("User", back_populates="datasets", foreign_keys=[uploaded_by])
    jobs = relationship("AnalysisJob", back_populates="dataset", cascade="all, delete-orphan")
    versions = relationship(
        "DatasetVersion", back_populates="dataset", cascade="all, delete-orphan", order_by="DatasetVersion.version"
    )

    def to_dict(self, include_meta: bool = False) -> dict:
        data = {
            "id": self.id,
            "filename": self.filename,
            "rows": self.rows,
            "columns": self.columns,
            "size_bytes": self.size_bytes,
            "status": self.status,
            "source": self.source,
            "uploaded_by": self.uploaded_by,
            "upload_time": self.created_at.isoformat() if self.created_at else None,
            "target_column": self.target_column,
            "attack_categories": self.attack_categories or [],
            "missing_values": self.missing_values,
            "duplicate_rows": self.duplicate_rows,
            "numerical_columns": self.numerical_columns,
            "categorical_columns": self.categorical_columns,
            "feature_coverage": self.feature_coverage,
            "schema_matched": self.schema_matched,
            "class_distribution": self.class_distribution or {},
            "version": self.version,
            "checksum": self.checksum,
            "marked_for_training": self.marked_for_training,
            "training_note": self.training_note,
        }
        if include_meta:
            data["columns_meta"] = self.columns_meta or []
            data["sample_rows"] = self.sample_rows or []
        return data


# --------------------------------------------------------------------------- #
class AnalysisJob(Base, TimestampMixin):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    dataset_id: Mapped[str] = mapped_column(String(36), ForeignKey("datasets.id"), index=True)
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    stage: Mapped[str] = mapped_column(String(80), default="queued")
    total_rows: Mapped[int] = mapped_column(Integer, default=0)
    processed_rows: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    warnings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    dataset = relationship("Dataset", back_populates="jobs")
    owner = relationship("User", back_populates="jobs")
    predictions = relationship("Prediction", back_populates="job", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "dataset_id": self.dataset_id,
            "dataset_filename": self.dataset.filename if self.dataset else None,
            "status": self.status,
            "progress": round(self.progress, 2),
            "stage": self.stage,
            "total_rows": self.total_rows,
            "processed_rows": self.processed_rows,
            "error": self.error,
            "warnings": self.warnings or [],
            "summary": self.summary or {},
            "model_version": self.model_version,
            "duration_ms": self.duration_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


# --------------------------------------------------------------------------- #
class Prediction(Base, TimestampMixin):
    __tablename__ = "predictions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    dataset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("datasets.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("analysis_jobs.id"), index=True)

    record_index: Mapped[int] = mapped_column(Integer, default=0, index=True)
    prediction: Mapped[str] = mapped_column(String(60), index=True)
    is_attack: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(12), default="low", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # key flow features kept alongside the prediction so a record can be
    # inspected later without re-reading the uploaded file
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    flow_duration: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_length_mean: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_fwd_packets: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_bwd_packets: Mapped[float | None] = mapped_column(Float, nullable=True)
    flow_bytes_per_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ground_truth: Mapped[str | None] = mapped_column(String(60), nullable=True)
    source: Mapped[str] = mapped_column(String(20), default="upload")  # upload | simulation
    features: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    top_factors: Mapped[list | None] = mapped_column(JSON, nullable=True)

    job = relationship("AnalysisJob", back_populates="predictions")
    alerts = relationship("Alert", back_populates="prediction", cascade="all, delete-orphan")

    def to_dict(self, include_features: bool = True) -> dict:
        data = {
            "id": self.id,
            "dataset_id": self.dataset_id,
            "job_id": self.job_id,
            "record_index": self.record_index,
            "prediction": self.prediction,
            "is_attack": self.is_attack,
            "confidence": round(self.confidence, 6),
            "risk_level": self.risk_level,
            "risk_score": round(self.risk_score, 6),
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "flow_duration": self.flow_duration,
            "packet_rate": self.packet_rate,
            "packet_length_mean": self.packet_length_mean,
            "total_fwd_packets": self.total_fwd_packets,
            "total_bwd_packets": self.total_bwd_packets,
            "flow_bytes_per_s": self.flow_bytes_per_s,
            "timestamp": self.event_time.isoformat() if self.event_time else None,
            "ground_truth": self.ground_truth,
            "source": self.source,
            "top_factors": self.top_factors or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_features:
            data["features"] = self.features or {}
        return data


# --------------------------------------------------------------------------- #
class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    prediction_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("predictions.id"), index=True, nullable=True
    )
    job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("analysis_jobs.id"), index=True)
    dataset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("datasets.id"), index=True)

    alert_type: Mapped[str] = mapped_column(String(80), index=True)
    attack_type: Mapped[str] = mapped_column(String(60), index=True)
    severity: Mapped[str] = mapped_column(String(12), index=True)  # low | medium | high | critical
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)  # new|acknowledged|reviewed|investigating|resolved|false_positive
    message: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    record_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # plain (not FK) reference to avoid a circular constraint alerts -> investigations
    investigation_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    prediction = relationship("Prediction", back_populates="alerts")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "prediction_id": self.prediction_id,
            "job_id": self.job_id,
            "dataset_id": self.dataset_id,
            "alert_type": self.alert_type,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "status": self.status,
            "message": self.message,
            "confidence": round(self.confidence, 6),
            "risk_score": round(self.risk_score, 6),
            "source_ip": self.source_ip,
            "destination_port": self.destination_port,
            "record_index": self.record_index,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "reviewed_by": self.reviewed_by,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "escalated": self.escalated,
            "escalated_at": self.escalated_at.isoformat() if self.escalated_at else None,
            "investigation_id": self.investigation_id,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
class DetectionStatistic(Base):
    """Hourly rollup so the dashboard does not scan the predictions table."""

    __tablename__ = "detection_statistics"
    __table_args__ = (UniqueConstraint("bucket_start", name="uq_detection_bucket"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    total: Mapped[int] = mapped_column(Integer, default=0)
    normal: Mapped[int] = mapped_column(Integer, default=0)
    suspicious: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    alerts: Mapped[int] = mapped_column(Integer, default=0)
    attack_counts: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# --------------------------------------------------------------------------- #
class AuditLog(Base):
    """
    Append-only audit trail.

    Every field the platform promises to record for an audited action is a first
    class column: who (``user_id`` + ``user_role``), what (``action`` +
    ``category`` + ``resource``), when (``created_at``), from where
    (``ip_address``), what changed (``previous_value`` / ``new_value``) and how
    it ended (``result``).  ``detail`` carries anything else worth keeping.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_user_created", "user_id", "created_at"),
        Index("ix_audit_category_created", "category", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    user_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(40), default="general", index=True)
    resource: Mapped[str | None] = mapped_column(String(120), nullable=True)
    previous_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result: Mapped[str] = mapped_column(String(20), default="success", index=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user = relationship("User", foreign_keys=[user_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "user_role": self.user_role,
            "action": self.action,
            "category": self.category,
            "resource": self.resource,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "result": self.result,
            "detail": self.detail or {},
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# --------------------------------------------------------------------------- #
# Configuration singletons
#
# Each configuration table holds exactly one row whose primary key is the literal
# ``"current"``.  A singleton keeps the schema explicit and typed (better query
# plans, real NULL/CHECK semantics, self-documenting columns) while the
# ``configuration_revisions`` table preserves the full change history.
# --------------------------------------------------------------------------- #
class _Singleton:
    """Mixin for the single-row configuration tables."""

    SINGLETON_ID = "current"

    @classmethod
    def load(cls, db):
        """Fetch (or lazily create) the single row of this configuration table."""
        row = db.get(cls, cls.SINGLETON_ID)
        if row is None:
            row = cls(id=cls.SINGLETON_ID)
            db.add(row)
            db.flush()
        return row


class NetworkConfiguration(Base, TimestampMixin, _Singleton):
    """What network is monitored and how the NIDS behaves on it."""

    __tablename__ = "network_configuration"

    id: Mapped[str] = mapped_column(String(20), primary_key=True, default=_Singleton.SINGLETON_ID)

    network_name: Mapped[str] = mapped_column(String(120), default="Primary Network")
    environment: Mapped[str] = mapped_column(String(40), default="production")  # production|staging|lab|dmz
    monitoring_mode: Mapped[str] = mapped_column(String(40), default="continuous")  # continuous|sampled|on_demand
    timezone_label: Mapped[str] = mapped_column(String(60), default="UTC")

    detection_sensitivity: Mapped[str] = mapped_column(String(20), default="balanced")  # low|balanced|high|paranoid
    alert_threshold: Mapped[float] = mapped_column(Float, default=0.65)
    risk_threshold: Mapped[float] = mapped_column(Float, default=0.85)

    analysis_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    analysis_batch_size: Mapped[int] = mapped_column(Integer, default=2000)
    max_upload_size_mb: Mapped[int] = mapped_column(Integer, default=25)
    allowed_file_formats: Mapped[list | None] = mapped_column(JSON, default=list)

    alert_retention_days: Mapped[int] = mapped_column(Integer, default=90)
    log_retention_days: Mapped[int] = mapped_column(Integer, default=30)

    auto_alert_generation: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_incident_creation: Mapped[bool] = mapped_column(Boolean, default=True)
    duplicate_suppression: Mapped[bool] = mapped_column(Boolean, default=True)

    traffic_volume_threshold: Mapped[int] = mapped_column(Integer, default=50000)
    suspicious_percent_threshold: Mapped[float] = mapped_column(Float, default=15.0)
    attack_rate_threshold: Mapped[float] = mapped_column(Float, default=10.0)
    critical_alert_threshold: Mapped[int] = mapped_column(Integer, default=5)
    alert_rate_threshold: Mapped[int] = mapped_column(Integer, default=50)

    auto_status_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_status_window_minutes: Mapped[int] = mapped_column(Integer, default=60)
    auto_status_suggest_only: Mapped[bool] = mapped_column(Boolean, default=True)

    updated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    SCOPE = "network"

    def to_dict(self) -> dict:
        return {
            "scope": self.SCOPE,
            "network_name": self.network_name,
            "environment": self.environment,
            "monitoring_mode": self.monitoring_mode,
            "timezone_label": self.timezone_label,
            "detection_sensitivity": self.detection_sensitivity,
            "alert_threshold": round(float(self.alert_threshold), 6),
            "risk_threshold": round(float(self.risk_threshold), 6),
            "analysis_interval_seconds": self.analysis_interval_seconds,
            "analysis_batch_size": self.analysis_batch_size,
            "max_upload_size_mb": self.max_upload_size_mb,
            "allowed_file_formats": list(self.allowed_file_formats or []),
            "alert_retention_days": self.alert_retention_days,
            "log_retention_days": self.log_retention_days,
            "auto_alert_generation": self.auto_alert_generation,
            "auto_incident_creation": self.auto_incident_creation,
            "duplicate_suppression": self.duplicate_suppression,
            "traffic_volume_threshold": self.traffic_volume_threshold,
            "suspicious_percent_threshold": round(float(self.suspicious_percent_threshold), 4),
            "attack_rate_threshold": round(float(self.attack_rate_threshold), 4),
            "critical_alert_threshold": self.critical_alert_threshold,
            "alert_rate_threshold": self.alert_rate_threshold,
            "auto_status_enabled": self.auto_status_enabled,
            "auto_status_window_minutes": self.auto_status_window_minutes,
            "auto_status_suggest_only": self.auto_status_suggest_only,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "updated_by": self.updated_by,
        }


class DetectionConfiguration(Base, TimestampMixin, _Singleton):
    """How the Random Forest output is turned into risk levels."""

    __tablename__ = "detection_configuration"

    id: Mapped[str] = mapped_column(String(20), primary_key=True, default=_Singleton.SINGLETON_ID)

    detection_sensitivity: Mapped[str] = mapped_column(String(20), default="balanced")
    risk_medium_threshold: Mapped[float] = mapped_column(Float, default=0.65)
    risk_high_threshold: Mapped[float] = mapped_column(Float, default=0.85)
    risk_critical_threshold: Mapped[float] = mapped_column(Float, default=0.96)
    min_confidence_to_alert: Mapped[float] = mapped_column(Float, default=0.50)
    min_confidence_to_store: Mapped[float] = mapped_column(Float, default=0.00)

    analysis_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    analysis_batch_size: Mapped[int] = mapped_column(Integer, default=2000)
    max_rows_per_job: Mapped[int] = mapped_column(Integer, default=200000)
    store_predictions_limit: Mapped[int] = mapped_column(Integer, default=50000)
    job_workers: Mapped[int] = mapped_column(Integer, default=2)

    sensitive_port_bonus: Mapped[float] = mapped_column(Float, default=0.05)
    highlight_suspicious: Mapped[bool] = mapped_column(Boolean, default=True)
    enhanced_investigation: Mapped[bool] = mapped_column(Boolean, default=False)
    preserve_investigation_logs: Mapped[bool] = mapped_column(Boolean, default=False)

    updated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    SCOPE = "detection"

    def to_dict(self) -> dict:
        return {
            "scope": self.SCOPE,
            "detection_sensitivity": self.detection_sensitivity,
            "risk_medium_threshold": round(float(self.risk_medium_threshold), 6),
            "risk_high_threshold": round(float(self.risk_high_threshold), 6),
            "risk_critical_threshold": round(float(self.risk_critical_threshold), 6),
            "min_confidence_to_alert": round(float(self.min_confidence_to_alert), 6),
            "min_confidence_to_store": round(float(self.min_confidence_to_store), 6),
            "analysis_interval_seconds": self.analysis_interval_seconds,
            "analysis_batch_size": self.analysis_batch_size,
            "max_rows_per_job": self.max_rows_per_job,
            "store_predictions_limit": self.store_predictions_limit,
            "job_workers": self.job_workers,
            "sensitive_port_bonus": round(float(self.sensitive_port_bonus), 6),
            "highlight_suspicious": self.highlight_suspicious,
            "enhanced_investigation": self.enhanced_investigation,
            "preserve_investigation_logs": self.preserve_investigation_logs,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "updated_by": self.updated_by,
        }


class AlertConfiguration(Base, TimestampMixin, _Singleton):
    """Alert policy: what raises an alert, how it is de-duplicated and escalated."""

    __tablename__ = "alert_configuration"

    id: Mapped[str] = mapped_column(String(20), primary_key=True, default=_Singleton.SINGLETON_ID)

    alerts_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity_to_alert: Mapped[str] = mapped_column(String(12), default="medium")
    severity_low_max: Mapped[float] = mapped_column(Float, default=0.6499)
    severity_medium_max: Mapped[float] = mapped_column(Float, default=0.8499)
    severity_high_max: Mapped[float] = mapped_column(Float, default=0.9599)

    categories: Mapped[list | None] = mapped_column(JSON, default=list)
    notify_severities: Mapped[list | None] = mapped_column(JSON, default=list)

    retention_days: Mapped[int] = mapped_column(Integer, default=90)
    duplicate_handling: Mapped[str] = mapped_column(String(20), default="aggregate")  # off|aggregate|suppress
    duplicate_window_seconds: Mapped[int] = mapped_column(Integer, default=300)
    max_alerts_per_job: Mapped[int] = mapped_column(Integer, default=300)
    max_individual_alerts: Mapped[int] = mapped_column(Integer, default=50)

    auto_incident_severity: Mapped[str] = mapped_column(String(12), default="critical")
    escalation_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    escalate_after_minutes: Mapped[int] = mapped_column(Integer, default=30)
    escalate_to_severity: Mapped[str] = mapped_column(String(12), default="high")
    notify_admins_on_critical: Mapped[bool] = mapped_column(Boolean, default=True)

    updated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    SCOPE = "alerts"

    def to_dict(self) -> dict:
        return {
            "scope": self.SCOPE,
            "alerts_enabled": self.alerts_enabled,
            "min_severity_to_alert": self.min_severity_to_alert,
            "severity_low_max": round(float(self.severity_low_max), 6),
            "severity_medium_max": round(float(self.severity_medium_max), 6),
            "severity_high_max": round(float(self.severity_high_max), 6),
            "categories": list(self.categories or []),
            "notify_severities": list(self.notify_severities or []),
            "retention_days": self.retention_days,
            "duplicate_handling": self.duplicate_handling,
            "duplicate_window_seconds": self.duplicate_window_seconds,
            "max_alerts_per_job": self.max_alerts_per_job,
            "max_individual_alerts": self.max_individual_alerts,
            "auto_incident_severity": self.auto_incident_severity,
            "escalation_enabled": self.escalation_enabled,
            "escalate_after_minutes": self.escalate_after_minutes,
            "escalate_to_severity": self.escalate_to_severity,
            "notify_admins_on_critical": self.notify_admins_on_critical,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "updated_by": self.updated_by,
        }


class ModelConfiguration(Base, TimestampMixin, _Singleton):
    """
    Runtime behaviour of the detection model.

    Deliberately limited to switches that cannot corrupt inference: the trained
    artifact itself is versioned in ``model_versions`` and can only be swapped
    through the approval workflow, never through a free-form field here.
    """

    __tablename__ = "model_configuration"

    id: Mapped[str] = mapped_column(String(20), primary_key=True, default=_Singleton.SINGLETON_ID)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    active_version: Mapped[str] = mapped_column(String(40), default="rf-cicids2017-v1")
    algorithm: Mapped[str] = mapped_column(String(60), default="RandomForestClassifier")
    prediction_threshold: Mapped[float] = mapped_column(Float, default=0.50)
    batch_size: Mapped[int] = mapped_column(Integer, default=2000)
    min_confidence_to_store: Mapped[float] = mapped_column(Float, default=0.00)

    explanations_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    shap_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    explanation_top_k: Mapped[int] = mapped_column(Integer, default=8)

    retraining_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    SCOPE = "model"

    def to_dict(self) -> dict:
        return {
            "scope": self.SCOPE,
            "enabled": self.enabled,
            "active_version": self.active_version,
            "algorithm": self.algorithm,
            "prediction_threshold": round(float(self.prediction_threshold), 6),
            "batch_size": self.batch_size,
            "min_confidence_to_store": round(float(self.min_confidence_to_store), 6),
            "explanations_enabled": self.explanations_enabled,
            "shap_enabled": self.shap_enabled,
            "explanation_top_k": self.explanation_top_k,
            "retraining_enabled": self.retraining_enabled,
            "require_approval": self.require_approval,
            "notes": self.notes,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "updated_by": self.updated_by,
        }


class SystemConfiguration(Base, TimestampMixin, _Singleton):
    """Security, retention, logging, API, dashboard and notification settings."""

    __tablename__ = "system_configuration"

    id: Mapped[str] = mapped_column(String(20), primary_key=True, default=_Singleton.SINGLETON_ID)

    # --- security ---------------------------------------------------------- #
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, default=480)
    password_min_length: Mapped[int] = mapped_column(Integer, default=8)
    enforce_strong_password: Mapped[bool] = mapped_column(Boolean, default=True)
    max_failed_logins: Mapped[int] = mapped_column(Integer, default=10)
    lockout_minutes: Mapped[int] = mapped_column(Integer, default=15)
    ip_allowlist: Mapped[list | None] = mapped_column(JSON, default=list)
    ip_allowlist_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- retention --------------------------------------------------------- #
    prediction_retention_days: Mapped[int] = mapped_column(Integer, default=180)
    alert_retention_days: Mapped[int] = mapped_column(Integer, default=90)
    investigation_retention_days: Mapped[int] = mapped_column(Integer, default=365)
    audit_retention_days: Mapped[int] = mapped_column(Integer, default=730)
    dataset_retention_days: Mapped[int] = mapped_column(Integer, default=0)  # 0 = keep forever
    auto_purge_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- logging ----------------------------------------------------------- #
    log_level: Mapped[str] = mapped_column(String(10), default="INFO")
    log_retention_days: Mapped[int] = mapped_column(Integer, default=30)
    log_requests: Mapped[bool] = mapped_column(Boolean, default=True)

    # --- api --------------------------------------------------------------- #
    api_docs_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    api_rate_limit_default: Mapped[str] = mapped_column(String(20), default="300/minute")
    cors_origins: Mapped[str] = mapped_column(String(512), default="")

    # --- dashboard --------------------------------------------------------- #
    dashboard_refresh_seconds: Mapped[int] = mapped_column(Integer, default=60)
    dashboard_default_window_hours: Mapped[int] = mapped_column(Integer, default=24)
    show_data_provenance: Mapped[bool] = mapped_column(Boolean, default=True)

    # --- notifications ----------------------------------------------------- #
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_severities: Mapped[list | None] = mapped_column(JSON, default=list)
    notify_admins_on_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notify_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    notification_digest_minutes: Mapped[int] = mapped_column(Integer, default=60)

    # --- notifications ----------------------------------------------------- #
    maintenance_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    updated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    SCOPE = "system"

    def to_dict(self) -> dict:
        return {
            "scope": self.SCOPE,
            "session_timeout_minutes": self.session_timeout_minutes,
            "password_min_length": self.password_min_length,
            "enforce_strong_password": self.enforce_strong_password,
            "max_failed_logins": self.max_failed_logins,
            "lockout_minutes": self.lockout_minutes,
            "ip_allowlist_enabled": self.ip_allowlist_enabled,
            "ip_allowlist": list(self.ip_allowlist or []),
            "prediction_retention_days": self.prediction_retention_days,
            "alert_retention_days": self.alert_retention_days,
            "investigation_retention_days": self.investigation_retention_days,
            "audit_retention_days": self.audit_retention_days,
            "dataset_retention_days": self.dataset_retention_days,
            "auto_purge_enabled": self.auto_purge_enabled,
            "log_level": self.log_level,
            "log_retention_days": self.log_retention_days,
            "log_requests": self.log_requests,
            "api_docs_enabled": self.api_docs_enabled,
            "api_rate_limit_default": self.api_rate_limit_default,
            "cors_origins": self.cors_origins,
            "dashboard_refresh_seconds": self.dashboard_refresh_seconds,
            "dashboard_default_window_hours": self.dashboard_default_window_hours,
            "show_data_provenance": self.show_data_provenance,
            "notifications_enabled": self.notifications_enabled,
            "notify_severities": list(self.notify_severities or []),
            "notify_admins_on_critical": self.notify_admins_on_critical,
            "notify_email": self.notify_email,
            "notify_webhook_url": self.notify_webhook_url,
            "notification_digest_minutes": self.notification_digest_minutes,
            "maintenance_message": self.maintenance_message,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "updated_by": self.updated_by,
        }


class ConfigurationRevision(Base):
    """Append-only history of every configuration change (previous -> new)."""

    __tablename__ = "configuration_revisions"
    __table_args__ = (Index("ix_revision_scope_changed", "scope", "changed_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scope: Mapped[str] = mapped_column(String(40), index=True)
    key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    previous_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    changed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    changed_by_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    changed_by_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scope": self.scope,
            "key": self.key,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "changed_by": self.changed_by,
            "changed_by_email": self.changed_by_email,
            "changed_by_role": self.changed_by_role,
            "ip_address": self.ip_address,
            "note": self.note,
            "changed_at": self.changed_at.isoformat() if self.changed_at else None,
        }


# --------------------------------------------------------------------------- #
# Network status
# --------------------------------------------------------------------------- #
class NetworkStatus(Base, TimestampMixin, _Singleton):
    """
    The single row describing the current operational status.

    ``source`` records *how* the status was set - ``manual`` (an admin pressed a
    button), ``automatic`` (the threshold evaluator decided) or ``system``
    (startup / maintenance defaults) - so the UI never claims a condition the
    system did not actually observe.
    """

    __tablename__ = "network_status"

    id: Mapped[str] = mapped_column(String(20), primary_key=True, default=_Singleton.SINGLETON_ID)

    status: Mapped[str] = mapped_column(String(32), default="normal", index=True)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="system")  # manual|automatic|system
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    configuration_applied: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    triggers: Mapped[list | None] = mapped_column(JSON, default=list)

    SCOPE = "network_status"

    def to_dict(self) -> dict:
        now = datetime.now(timezone.utc)
        started = self.started_at
        if started is not None and started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        return {
            "status": self.status,
            "previous_status": self.previous_status,
            "source": self.source,
            "reason": self.reason,
            "changed_by": self.changed_by,
            "started_at": started.isoformat() if started else None,
            "duration_seconds": int((now - started).total_seconds()) if started else 0,
            "duration_label": _duration_label(now - started) if started else "0s",
            "configuration_applied": self.configuration_applied or {},
            "triggers": list(self.triggers or []),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class NetworkStatusHistory(Base):
    """Every status transition, with who/why and how long the status lasted."""

    __tablename__ = "network_status_history"
    __table_args__ = (Index("ix_status_history_started", "started_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(32), index=True)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="manual")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    changed_by_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    configuration_applied: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    triggers: Mapped[list | None] = mapped_column(JSON, default=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "previous_status": self.previous_status,
            "source": self.source,
            "reason": self.reason,
            "changed_by": self.changed_by,
            "changed_by_email": self.changed_by_email,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "duration_label": _duration_label_seconds(self.duration_seconds),
            "configuration_applied": self.configuration_applied or {},
            "triggers": list(self.triggers or []),
        }


class DemoIpRule(Base, TimestampMixin):
    """Persistent IP rules for the explicitly simulated demo firewall."""

    __tablename__ = "demo_ip_rules"
    __table_args__ = (UniqueConstraint("ip", name="uq_demo_ip_rules_ip"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    policy: Mapped[str] = mapped_column(String(8), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    changed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "policy": self.policy,
            "comment": self.reason,
            "changed_by": self.changed_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# --------------------------------------------------------------------------- #
# Model lifecycle
# --------------------------------------------------------------------------- #
class ModelVersion(Base, TimestampMixin):
    """A trained model artifact and its lifecycle state."""

    __tablename__ = "model_versions"
    __table_args__ = (UniqueConstraint("version", name="uq_model_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    version: Mapped[str] = mapped_column(String(40), index=True)
    algorithm: Mapped[str] = mapped_column(String(60), default="RandomForestClassifier")
    status: Mapped[str] = mapped_column(String(24), default="active", index=True)
    # active | candidate | pending_approval | approved | retired | rejected
    artifact_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_core_detector: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    n_features: Mapped[int | None] = mapped_column(Integer, nullable=True)
    n_classes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    classes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    training_dataset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("datasets.id"), nullable=True)
    training_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    feature_importance: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    dataset_info: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "version": self.version,
            "algorithm": self.algorithm,
            "status": self.status,
            "artifact_path": self.artifact_path,
            "is_core_detector": self.is_core_detector,
            "n_features": self.n_features,
            "n_classes": self.n_classes,
            "classes": list(self.classes or []),
            "training_dataset_id": self.training_dataset_id,
            "training_config": self.training_config or {},
            "metrics": self.metrics or {},
            "dataset_info": self.dataset_info or {},
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "deployed_at": self.deployed_at.isoformat() if self.deployed_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
            "retired_at": self.retired_at.isoformat() if self.retired_at else None,
            "created_by": self.created_by,
        }


class TrainingRun(Base, TimestampMixin):
    """Retraining request: dataset -> configuration -> evaluation -> approval."""

    __tablename__ = "training_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    dataset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("datasets.id"), nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    # pending | queued | training | evaluation | awaiting_approval | approved | rejected | failed
    stage: Mapped[str] = mapped_column(String(80), default="pending")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    configuration: Mapped[dict | None] = mapped_column(JSON, default=dict)
    split_config: Mapped[dict | None] = mapped_column(JSON, default=dict)
    evaluation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    dataset = relationship("Dataset")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "dataset_id": self.dataset_id,
            "dataset_filename": self.dataset.filename if self.dataset else None,
            "requested_by": self.requested_by,
            "status": self.status,
            "stage": self.stage,
            "progress": round(float(self.progress or 0.0), 2),
            "configuration": self.configuration or {},
            "split_config": self.split_config or {},
            "evaluation": self.evaluation,
            "result_version": self.result_version,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
        }


class DatasetVersion(Base):
    """Immutable revision record for a dataset (schema, size, target classes)."""

    __tablename__ = "dataset_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    dataset_id: Mapped[str] = mapped_column(String(36), ForeignKey("datasets.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    rows: Mapped[int] = mapped_column(Integer, default=0)
    columns: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    columns_meta: Mapped[list | None] = mapped_column(JSON, nullable=True)
    target_classes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    class_distribution: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    preprocessing: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    dataset = relationship("Dataset")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "dataset_id": self.dataset_id,
            "version": self.version,
            "rows": self.rows,
            "columns": self.columns,
            "size_bytes": self.size_bytes,
            "checksum": self.checksum,
            "columns_meta": list(self.columns_meta or []),
            "target_classes": list(self.target_classes or []),
            "class_distribution": self.class_distribution or {},
            "preprocessing": self.preprocessing or {},
            "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# --------------------------------------------------------------------------- #
# Investigation workspace / notifications
# --------------------------------------------------------------------------- #
class Investigation(Base, TimestampMixin):
    """Analyst-owned investigation record linked to an alert and/or a flow."""

    __tablename__ = "investigations"
    __table_args__ = (Index("ix_investigation_status_updated", "status", "updated_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    reference: Mapped[str] = mapped_column(String(24), index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    # open | in_progress | pending | escalated | closed
    priority: Mapped[str] = mapped_column(String(12), default="medium", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    alert_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("alerts.id"), index=True, nullable=True)
    prediction_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("predictions.id"), index=True, nullable=True)
    job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("analysis_jobs.id"), nullable=True)
    dataset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("datasets.id"), nullable=True)

    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings: Mapped[list | None] = mapped_column(JSON, default=list)
    notes: Mapped[list | None] = mapped_column(JSON, default=list)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(12), nullable=True, index=True)
    attack_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)

    assignee = relationship("User", foreign_keys=[assigned_to])
    creator = relationship("User", foreign_keys=[created_by])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "reference": self.reference,
            "title": self.title,
            "status": self.status,
            "priority": self.priority,
            "assigned_to": self.assigned_to,
            "assigned_to_name": self.assignee.name if self.assignee else None,
            "created_by": self.created_by,
            "alert_id": self.alert_id,
            "prediction_id": self.prediction_id,
            "job_id": self.job_id,
            "dataset_id": self.dataset_id,
            "summary": self.summary,
            "findings": list(self.findings or []),
            "notes": list(self.notes or []),
            "evidence": self.evidence or {},
            "risk_level": self.risk_level,
            "attack_type": self.attack_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "closed_by": self.closed_by,
        }


class Notification(Base):
    """In-app notification feed (admins and analysts)."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notification_created_read", "created_at", "is_read"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    severity: Mapped[str] = mapped_column(String(12), default="info", index=True)
    category: Mapped[str] = mapped_column(String(40), default="general", index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource: Mapped[str | None] = mapped_column(String(120), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target_role: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    target_user: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "message": self.message,
            "resource": self.resource,
            "resource_id": self.resource_id,
            "target_role": self.target_role,
            "is_read": self.is_read,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _duration_label(delta: "datetime") -> str:
    return _duration_label_seconds(int(delta.total_seconds()))


def _duration_label_seconds(seconds: int | None) -> str:
    seconds = max(0, int(seconds or 0))
    days, remainder = divmod(seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts[:3])
