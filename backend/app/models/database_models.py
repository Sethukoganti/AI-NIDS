"""
SQLAlchemy ORM models - the AI-NIDS persistence schema.

Tables
------
users                  accounts + roles (admin / analyst)
datasets               uploaded (or referenced) traffic datasets and their profile
analysis_jobs          one row per "Analyze Traffic" run (progress + summary)
predictions            per-flow model output, risk level and key flow features
alerts                 security alerts raised from suspicious predictions
detection_statistics   hourly rollup used by the dashboard charts
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
    role: Mapped[str] = mapped_column(String(20), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    datasets = relationship("Dataset", back_populates="owner", cascade="all, delete-orphan")
    jobs = relationship("AnalysisJob", back_populates="owner", cascade="all, delete-orphan")

    def to_public_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
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

    owner = relationship("User", back_populates="datasets")
    jobs = relationship("AnalysisJob", back_populates="dataset", cascade="all, delete-orphan")

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
    status: Mapped[str] = mapped_column(String(12), default="new", index=True)  # new|reviewed|resolved
    message: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    record_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_user_created", "user_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource: Mapped[str | None] = mapped_column(String(120), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "resource": self.resource,
            "detail": self.detail or {},
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
