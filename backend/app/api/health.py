"""Health / system-status API - drives the sidebar 'System Status' indicator."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_current_user, require_admin
from app.db.session import check_connection, get_db
from app.middleware.rate_limit_middleware import limiter
from app.services.ml_service import model_service

router = APIRouter(prefix="/health", tags=["health"])
STARTED_AT = time.time()


def _uptime() -> float:
    return round(time.time() - STARTED_AT, 3)


@router.get("", summary="Public liveness/readiness summary")
def health(db: Session = Depends(get_db)):
    db_ok, db_error = check_connection()
    model_ok = model_service.is_loaded
    status = "healthy" if (db_ok and model_ok) else ("degraded" if db_ok or model_ok else "unhealthy")
    return {
        "status": status,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "uptime_seconds": _uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {
            "database": {"ok": db_ok, "detail": None if db_ok else "connection failed", "driver": "sqlite" if settings.is_sqlite else "postgresql"},
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
        },
        "model": {
            "loaded": model_ok,
            "algorithm": model_service.metadata.get("algorithm"),
            "n_estimators": model_service.metadata.get("n_estimators"),
            "test_accuracy": model_service.evaluation.get("accuracy"),
            "n_features": len(model_service.feature_names()),
            "load_seconds": model_service.load_seconds,
        },
        "ai": {"provider": settings.AI_PROVIDER, "enabled": settings.ai_enabled},
    }


@router.get("/live", summary="Minimal liveness probe (no DB access)")
def live():
    return {"status": "ok", "uptime_seconds": _uptime()}


@router.get("/system", summary="Detailed system information (admin only)")
def system_info(user=Depends(require_admin), db: Session = Depends(get_db)):
    from app.models.database_models import Alert, AnalysisJob, Dataset, Prediction

    db_ok, db_error = check_connection()
    counts = {}
    if db_ok:
        counts = {
            "users": int(db.scalar(select(func.count()).select_from(__import__("app.models.database_models", fromlist=["User"]).User)) or 0),
            "datasets": int(db.scalar(select(func.count(Dataset.id))) or 0),
            "jobs": int(db.scalar(select(func.count(AnalysisJob.id))) or 0),
            "predictions": int(db.scalar(select(func.count(Prediction.id))) or 0),
            "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
        }

    upload_dir = settings.upload_dir
    disk = {
        "upload_dir": str(upload_dir),
        "upload_files": len(list(upload_dir.glob("*"))) if upload_dir.exists() else 0,
        "upload_bytes": sum(f.stat().st_size for f in upload_dir.glob("*")) if upload_dir.exists() else 0,
    }

    return {
        "status": "healthy" if db_ok and model_service.is_loaded else "degraded",
        "uptime_seconds": _uptime(),
        "database": {"ok": db_ok, "error": db_error, "url_scheme": settings.DATABASE_URL.split("://")[0], "counts": counts},
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
        "uploads": disk,
        "environment": {
            "python": os.sys.version.split()[0],
            "environment": settings.ENVIRONMENT,
            "debug_sql": settings.DB_ECHO,
            "job_workers": settings.JOB_WORKERS,
            "max_upload_mb": round(settings.MAX_UPLOAD_SIZE / 1e6, 1),
            "max_rows_per_job": settings.MAX_ROWS_PER_JOB,
        },
        "ai": {
            "provider": settings.AI_PROVIDER,
            "enabled": settings.ai_enabled,
            "model": settings.AI_MODEL if settings.ai_enabled else None,
            "api_key_configured": bool(settings.AI_API_KEY),
        },
    }
