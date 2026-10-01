"""Pydantic request/response schemas (FastAPI request validation)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.config import settings


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class UserCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str
    role: Literal["admin", "analyst"] = "analyst"

    @field_validator("password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        if len(value) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long."
            )
        if value.isalpha() or value.isdigit():
            raise ValueError("Password must contain both letters and numbers.")
        return value


class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: str | None = None
    last_login_at: str | None = None


# --------------------------------------------------------------------------- #
# Datasets
# --------------------------------------------------------------------------- #
class DatasetOut(BaseModel):
    id: str
    filename: str
    rows: int
    columns: int
    size_bytes: int
    status: str
    source: str
    uploaded_by: str | None = None
    upload_time: str | None = None
    target_column: str | None = None
    attack_categories: list[str] = []
    missing_values: int = 0
    duplicate_rows: int = 0
    numerical_columns: int = 0
    categorical_columns: int = 0
    feature_coverage: float | None = None
    schema_matched: bool | None = None
    class_distribution: dict[str, int] = {}


class DatasetDetailOut(DatasetOut):
    columns_meta: list[dict] = []
    sample_rows: list[dict] = []


class DatasetPage(BaseModel):
    items: list[DatasetOut]
    total: int
    page: int
    page_size: int
    pages: int


class SampleDatasetRequest(BaseModel):
    sample: Literal["sample_traffic", "simulation_stream"] = "sample_traffic"


# --------------------------------------------------------------------------- #
# Predictions
# --------------------------------------------------------------------------- #
class AnalyzeRequest(BaseModel):
    dataset_id: str
    force_sync: bool = Field(
        default=False, description="Run inline even for large files (not recommended)"
    )


class PredictionOut(BaseModel):
    id: str
    dataset_id: str | None = None
    job_id: str | None = None
    record_index: int
    prediction: str
    is_attack: bool
    confidence: float
    risk_level: str
    risk_score: float
    source_port: int | None = None
    destination_port: int | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    flow_duration: float | None = None
    packet_rate: float | None = None
    packet_length_mean: float | None = None
    total_fwd_packets: float | None = None
    total_bwd_packets: float | None = None
    flow_bytes_per_s: float | None = None
    timestamp: str | None = None
    ground_truth: str | None = None
    source: str
    top_factors: list[dict] = []
    created_at: str | None = None


class PredictionPage(BaseModel):
    items: list[PredictionOut]
    total: int
    page: int
    page_size: int
    pages: int
    sort_by: str
    sort_dir: str


class JobOut(BaseModel):
    id: str
    dataset_id: str
    dataset_filename: str | None = None
    status: str
    progress: float
    stage: str
    total_rows: int
    processed_rows: int
    error: str | None = None
    warnings: list[str] = []
    summary: dict[str, Any] = {}
    model_version: str | None = None
    duration_ms: int | None = None
    created_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    alert_count: int = 0


class SimulateRequest(BaseModel):
    """Process N sample flows sequentially (stateless demo of the pipeline)."""

    rows: int = Field(default=50, ge=1, le=2000)
    sample: Literal["sample_traffic", "simulation_stream"] = "simulation_stream"
    persist: bool = False


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
class AlertUpdateRequest(BaseModel):
    status: Literal["new", "reviewed", "resolved", "open"] | None = None
    notes: str | None = Field(default=None, max_length=2000)


class AlertOut(BaseModel):
    id: str
    prediction_id: str | None = None
    job_id: str | None = None
    dataset_id: str | None = None
    alert_type: str
    attack_type: str
    severity: str
    status: str
    message: str
    confidence: float
    risk_score: float
    source_ip: str | None = None
    destination_port: int | None = None
    record_index: int | None = None
    created_at: str | None = None
    resolved_at: str | None = None
    reviewed_by: str | None = None
    notes: str | None = None


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
    pages: int


# --------------------------------------------------------------------------- #
# Assistant
# --------------------------------------------------------------------------- #
class AssistantRequest(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
    prediction_id: str | None = None
    include_evidence: bool = False


class AssistantResponse(BaseModel):
    provider: str
    answer: str
    facts: dict[str, Any] = {}
    sources: list[str] = []
    evidence: dict[str, Any] | None = None


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    uptime_seconds: float
    checks: dict[str, Any]
    model: dict[str, Any]
    ai: dict[str, Any]
