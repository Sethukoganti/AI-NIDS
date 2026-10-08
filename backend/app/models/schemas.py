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
    blocklist_network: str | None = None
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
    """Process flows sequentially (stateless demo of the pipeline)."""

    rows: int = Field(default=50, ge=1, le=2000)
    sample: Literal["sample_traffic", "simulation_stream"] = "simulation_stream"
    dataset_id: str | None = None
    persist: bool = False


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
class AlertUpdateRequest(BaseModel):
    status: (
        Literal[
            "new",
            "acknowledged",
            "reviewed",
            "investigating",
            "resolved",
            "false_positive",
            "open",
        ]
        | None
    ) = None
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
    blocklist_network: str | None = None
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


# --------------------------------------------------------------------------- #
# Administration
# --------------------------------------------------------------------------- #
class ConfigUpdateRequest(BaseModel):
    """
    A settings write.

    ``values`` holds only the keys the admin actually changed, so an unchanged
    field is never rewritten.  ``confirm_dangerous`` is required by the backend
    whenever any field in the payload is flagged dangerous, which is what stops a
    stale browser tab from silently weakening detection.
    """

    values: dict[str, Any]
    note: str | None = Field(default=None, max_length=500)
    confirm_dangerous: bool = False


class ConfigUpdateResponse(BaseModel):
    changed: list[str] = []
    revision_ids: list[str] = []
    values: dict[str, Any] = {}
    effective_configuration: dict[str, Any] | None = None
    warnings: list[str] = []


class NetworkStatusChangeRequest(BaseModel):
    status: str = Field(min_length=1, max_length=40)
    reason: str = Field(min_length=5, max_length=500)
    confirm: bool = False


class NetworkBlockRequest(BaseModel):
    network: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=500)
    alert_id: str | None = Field(default=None, max_length=36)

    @field_validator("reason", mode="before")
    @classmethod
    def _trim_reason(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class UserUpdateRequest(BaseModel):
    """Partial update of a user account; ``None`` fields are left untouched."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    role: Literal["admin", "analyst"] | None = None
    is_active: bool | None = None
    password: str | None = None

    @field_validator("password")
    @classmethod
    def _password_strength(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long."
            )
        if value.isalpha() or value.isdigit():
            raise ValueError("Password must contain both letters and numbers.")
        return value


class RoleUpdateRequest(BaseModel):
    """Optional per-role permission override (``allow`` replaces the whole set)."""

    description: str | None = Field(default=None, max_length=300)
    add: list[str] = []
    remove: list[str] = []
    allow: list[str] | None = None


class RoleOut(BaseModel):
    name: str
    description: str | None = None
    permissions: list[str] = []
    effective_permissions: list[str] = []
    protected: list[str] = []
    is_system: bool = True
    user_count: int = 0


class AuditLogOut(BaseModel):
    id: str
    created_at: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    user_role: str | None = None
    action: str
    category: str
    resource: str | None = None
    result: str
    previous_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    detail: dict[str, Any] = {}
    ip_address: str | None = None
    user_agent: str | None = None


class AuditLogPage(BaseModel):
    items: list[AuditLogOut] = []
    total: int = 0
    page: int = 1
    page_size: int = 50
    pages: int = 1
    summary: dict[str, Any] = {}


class NotificationOut(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    message: str | None = None
    resource: str | None = None
    resource_id: str | None = None
    target_role: str | None = None
    is_read: bool = False
    read_at: str | None = None
    created_at: str | None = None


class NotificationPage(BaseModel):
    items: list[NotificationOut] = []
    total: int = 0
    unread: int = 0
    page: int = 1
    page_size: int = 25
    pages: int = 1
    categories: list[str] = []
    severities: list[str] = []


class NotificationPreferences(BaseModel):
    categories: list[Literal["alert", "network", "model", "system", "user", "dataset"]] = Field(
        default_factory=lambda: ["alert", "network", "model", "system", "user", "dataset"]
    )
    minimum_severity: Literal["info", "low", "medium", "high", "critical"] = "info"


class ModelDeployRequest(BaseModel):
    version: str = Field(min_length=1, max_length=64)
    note: str | None = Field(default=None, max_length=500)
    confirm: bool = False


class TrainingRunRequest(BaseModel):
    dataset_id: str
    config: dict[str, Any] = {}
    note: str | None = Field(default=None, max_length=500)


# --------------------------------------------------------------------------- #
# Investigations
# --------------------------------------------------------------------------- #
class InvestigationCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    alert_id: str | None = None
    prediction_id: str | None = None
    summary: str | None = Field(default=None, max_length=4000)
    priority: Literal["low", "medium", "high", "critical"] = "medium"


class InvestigationUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    summary: str | None = Field(default=None, max_length=4000)
    status: Literal["open", "in_progress", "pending", "escalated", "closed"] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    assigned_to: str | None = None
    note: str | None = Field(default=None, max_length=4000)
    finding: str | None = Field(default=None, max_length=4000)


class InvestigationOut(BaseModel):
    id: str
    reference: str
    title: str
    status: str
    priority: str
    assigned_to: str | None = None
    created_by: str | None = None
    alert_id: str | None = None
    prediction_id: str | None = None
    job_id: str | None = None
    dataset_id: str | None = None
    summary: str | None = None
    findings: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    risk_level: str | None = None
    attack_type: str | None = None
    closed_at: str | None = None
    closed_by: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class InvestigationPage(BaseModel):
    items: list[InvestigationOut] = []
    total: int = 0
    page: int = 1
    page_size: int = 25
    pages: int = 1
    statuses: list[str] = []
    priorities: list[str] = []
