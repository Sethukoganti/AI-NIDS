"""
Application configuration.

Every tunable lives here and is overridable through environment variables or a
``.env`` file - no secrets are ever hard-coded.  See ``.env.example``.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
# The repository root.  Docker images relocate the project to /app, so the root
# can be overridden with AINIDS_PROJECT_ROOT; everything else is derived from it.
_env_root = os.environ.get("AINIDS_PROJECT_ROOT", "").strip()
PROJECT_ROOT = Path(_env_root).resolve() if _env_root else BACKEND_DIR.parent
ML_DIR = Path(__file__).resolve().parent.parent / "ml"

# settings that hold filesystem paths and are resolved against PROJECT_ROOT
_PATH_FIELDS = (
    "MODEL_PATH",
    "FEATURE_COLUMNS_PATH",
    "MODEL_METADATA_PATH",
    "EVALUATION_PATH",
    "FEATURE_IMPORTANCE_PATH",
    "LABEL_CODES_PATH",
    "LABEL_MAPPING_PATH",
    "PREPROCESSING_CONFIG_PATH",
    "DATASET_STATS_PATH",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ app --
    APP_NAME: str = "AI-NIDS"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    API_PREFIX: str = "/api"
    LOG_LEVEL: str = "INFO"

    # ------------------------------------------------------------- database --
    # SQLite by default so the project runs with zero infrastructure; PostgreSQL
    # is used by docker-compose and in production (see .env.example).
    DATABASE_URL: str = f"sqlite:///{PROJECT_ROOT / 'data' / 'ainids.db'}"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10

    # ----------------------------------------------------------- auth / jwt --
    JWT_SECRET: str = "change-me-in-env-dev-only-secret"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    PASSWORD_MIN_LENGTH: int = 8

    # ---------------------------------------------------------------- model --
    MODEL_PATH: str = str(ML_DIR / "random_forest_model.joblib")
    FEATURE_COLUMNS_PATH: str = str(ML_DIR / "feature_columns.json")
    MODEL_METADATA_PATH: str = str(ML_DIR / "model_metadata.json")
    EVALUATION_PATH: str = str(ML_DIR / "evaluation.json")
    FEATURE_IMPORTANCE_PATH: str = str(ML_DIR / "feature_importance.json")
    LABEL_CODES_PATH: str = str(ML_DIR / "label_codes.json")
    LABEL_MAPPING_PATH: str = str(ML_DIR / "label_mapping.json")
    PREPROCESSING_CONFIG_PATH: str = str(ML_DIR / "preprocessing_config.json")
    DATASET_STATS_PATH: str = str(ML_DIR / "dataset_stats.json")

    # ------------------------------------------------------------ uploads ----
    MAX_UPLOAD_SIZE: int = Field(default=25 * 1024 * 1024)  # bytes (25 MB)
    MAX_ROWS_PER_JOB: int = 200_000  # hard cap per analysis job
    SYNC_ANALYSIS_ROW_LIMIT: int = 2_000  # <= this many rows -> respond inline
    STORE_PREDICTIONS_LIMIT: int = 50_000  # per job, keeps the DB lean
    SHAP_MAX_RECORDS: int = 2_000  # cap for batch SHAP explanation
    JOB_WORKERS: int = 2

    # --------------------------------------------------------- rate limits ---
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_PREDICT: str = "30/minute"
    RATE_LIMIT_UPLOAD: str = "20/minute"
    RATE_LIMIT_DEFAULT: str = "300/minute"

    # -------------------------------------------------------------- cors -----
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173"
    CORS_ALLOW_ORIGIN_REGEX: str = r"https://([a-z0-9-]+\.)?e2b\.app|http://(localhost|127\.0\.0\.1)(:\d+)?"

    # ------------------------------------------------------- ai explanation --
    # none | openai | ollama   ("openai" covers any OpenAI-compatible endpoint)
    AI_PROVIDER: str = "none"
    AI_API_KEY: str = ""
    AI_MODEL: str = "gpt-4o-mini"
    AI_BASE_URL: str = "https://api.openai.com/v1"
    AI_TIMEOUT_SECONDS: float = 30.0
    AI_MAX_TOKENS: int = 700

    # ----------------------------------------------------------- demo data ---
    SEED_DEMO_DATA: bool = True
    DEMO_USER_EMAIL: str = "analyst@ainids.dev"
    DEMO_USER_PASSWORD: str = "Analyst@123"
    DEMO_ADMIN_EMAIL: str = "admin@ainids.dev"
    DEMO_ADMIN_PASSWORD: str = "Admin@1234"

    @field_validator("CORS_ORIGINS")
    @classmethod
    def _strip_origins(cls, v: str) -> str:
        return v.strip()

    @model_validator(mode="after")
    def _anchor_relative_paths(self) -> "Settings":
        """
        Anchor relative artifact paths at the project root.

        ``.env`` documents paths as ``backend/app/ml/...`` which only resolve when
        the process happens to be started from the repository root.  Resolving them
        here means the API behaves identically whether it is launched from the repo
        root, from ``backend/``, by pytest, or inside a container.
        """
        for field_name in _PATH_FIELDS:
            value = getattr(self, field_name, None)
            if value and not Path(value).is_absolute():
                setattr(self, field_name, str((PROJECT_ROOT / value).resolve()))

        # sqlite:///./data/ainids.db -> absolute file URL (postgres URLs are untouched)
        if self.DATABASE_URL.startswith("sqlite:///./"):
            tail = self.DATABASE_URL[len("sqlite:///./") :]
            setattr(self, "DATABASE_URL", f"sqlite:///{(PROJECT_ROOT / tail).resolve()}")
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def ai_enabled(self) -> bool:
        return self.AI_PROVIDER.lower() not in {"", "none", "disabled", "off"}

    @property
    def data_dir(self) -> Path:
        d = PROJECT_ROOT / "data"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def upload_dir(self) -> Path:
        d = self.data_dir / "uploads"
        d.mkdir(parents=True, exist_ok=True)
        return d


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
