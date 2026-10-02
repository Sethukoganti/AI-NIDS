"""Health / system-status API - drives the sidebar 'System Status' indicator."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import P_SYSTEM_HEALTH
from app.core.security import require_admin
from app.db.session import check_connection, get_db
from app.middleware.rate_limit_middleware import limiter
from app.services.ml_service import model_service

router = APIRouter(prefix="/health", tags=["health"])
STARTED_AT = time.time()


def _uptime() -> float:
    return round(time.time() - STARTED_AT, 3)


def _checks(db: Session | None = None) -> dict:
    """Component checks shared by the public, admin and system-health payloads."""
    db_ok, db_error = check_connection()
    model_ok = model_service.is_loaded
    return {
        "database": {
            "ok": db_ok,
            "detail": db_error,
            "driver": "sqlite" if settings.is_sqlite else "postgresql",
        },
        "model": {
            "ok": model_ok,
            "detail": model_service.load_error,
            "algorithm": model_service.metadata.get("algorithm"),
            "classes": len(model_service.classes_) if model_ok else 0,
        },
        "ai_explanation": {
            "ok": True,
            "provider": settings.AI_PROVIDER,
            "mode": "external LLM" if settings.ai_enabled else "local explanation engine",
        },
    }


def _overall_status(checks: dict) -> str:
    values = [bool(checks[key]["ok"]) for key in ("database", "model")]
    if all(values):
        return "healthy"
    return "degraded" if any(values) else "unhealthy"


def _model_payload() -> dict:
    ok = model_service.is_loaded
    return {
        "loaded": ok,
        "algorithm": model_service.metadata.get("algorithm"),
        "n_estimators": model_service.metadata.get("n_estimators"),
        "test_accuracy": model_service.evaluation.get("accuracy"),
        "n_features": len(model_service.feature_names()) if ok else 0,
        "classes": model_service.classes_ if ok else [],
        "version": model_service.metadata.get("version"),
        "load_seconds": model_service.load_seconds,
        "loaded_at": model_service.loaded_at,
    }


def _uploads_payload() -> dict:
    upload_dir = settings.upload_dir
    files = list(upload_dir.glob("*")) if upload_dir.exists() else []
    return {
        "upload_dir": str(upload_dir),
        "upload_files": len(files),
        "upload_bytes": sum(f.stat().st_size for f in files if f.is_file()),
    }


def _counts(db: Session) -> dict:
    from app.models.database_models import (
        Alert,
        AnalysisJob,
        Dataset,
        Investigation,
        Notification,
        Prediction,
        User,
    )

    def count(model) -> int:
        return int(db.scalar(select(func.count()).select_from(model)) or 0)

    return {
        "users": count(User),
        "datasets": count(Dataset),
        "jobs": count(AnalysisJob),
        "predictions": count(Prediction),
        "alerts": count(Alert),
        "investigations": count(Investigation),
        "notifications": count(Notification),
    }


def _runtime_payload(db: Session) -> dict:
    """The effective, database-managed configuration the process is running with."""
    from app.services import config_service

    runtime = config_service.runtime_snapshot(db)
    return {
        "effective_configuration": runtime.to_dict(),
        "environment_defaults": {
            "job_workers": settings.JOB_WORKERS,
            "max_upload_mb": round(settings.MAX_UPLOAD_SIZE / 1e6, 1),
            "max_rows_per_job": settings.MAX_ROWS_PER_JOB,
            "store_predictions_limit": settings.STORE_PREDICTIONS_LIMIT,
        },
        "note": (
            "The effective configuration combines the admin-managed settings in the database "
            "with the operational status profile. It overrides the environment defaults shown "
            "above."
        ),
    }


def _system_payload(db: Session) -> dict:
    """Everything ``GET /api/health/system`` and ``/api/admin/system/health`` share."""
    db_ok, db_error = check_connection()
    checks = _checks(db)
    return {
        "status": "healthy" if db_ok and model_service.is_loaded else "degraded",
        "uptime_seconds": _uptime(),
        "checks": checks,
        "database": {
            "ok": db_ok,
            "error": db_error,
            "url_scheme": settings.DATABASE_URL.split("://")[0],
            "counts": _counts(db) if db_ok else {},
        },
        "model": model_service.info(),
        "rate_limiter": {
            "enabled": settings.RATE_LIMIT_ENABLED,
            "limits": {
                "login": settings.RATE_LIMIT_LOGIN,
                "predict": settings.RATE_LIMIT_PREDICT,
                "upload": settings.RATE_LIMIT_UPLOAD,
                "default": settings.RATE_LIMIT_DEFAULT,
            },
            "tracked": limiter.stats()["tracked_keys"],
        },
        "uploads": _uploads_payload(),
        "environment": {
            "python": os.sys.version.split()[0],
            "environment": settings.ENVIRONMENT,
            "debug_sql": settings.DB_ECHO,
        },
        "ai": {
            "provider": settings.AI_PROVIDER,
            "enabled": settings.ai_enabled,
            "model": settings.AI_MODEL if settings.ai_enabled else None,
            "api_key_configured": bool(settings.AI_API_KEY),
        },
    }


@router.get("", summary="Public liveness/readiness summary")
def health(db: Session = Depends(get_db)):
    checks = _checks(db)
    return {
        "status": _overall_status(checks),
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "uptime_seconds": _uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "model": _model_payload(),
        "ai": {"provider": settings.AI_PROVIDER, "enabled": settings.ai_enabled},
    }


@router.get("/live", summary="Minimal liveness probe (no DB access)")
def live():
    return {"status": "ok", "uptime_seconds": _uptime()}


@router.get("/system", summary="Detailed system information (admin only)")
def system_info(
    user=Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _system_payload(db)


@router.get("/runtime", summary="The effective runtime configuration (admin only)")
def runtime_configuration(
    user=Depends(require_admin),
    db: Session = Depends(get_db),
):
    from app.services import network_status_service

    return {
        **_runtime_payload(db),
        "network_status": network_status_service.current_dict(db),
        "permissions_required": P_SYSTEM_HEALTH,
    }