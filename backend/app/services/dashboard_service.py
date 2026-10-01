"""
Dashboard aggregation service.

Every number the dashboard renders comes from SQL aggregation over the
predictions / alerts tables (plus the hourly rollup for the time series) - no
placeholder values, and no giant result sets sent to the browser.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.database_models import Alert, AnalysisJob, Dataset, DetectionStatistic, Prediction
from app.services.ml_service import model_service


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _since(hours: int | None) -> datetime | None:
    return None if hours in (None, 0) else _now() - timedelta(hours=hours)


def metrics(db: Session, hours: int | None = None) -> dict:
    since = _since(hours)
    base = select(
        func.count(Prediction.id),
        func.sum(case((Prediction.is_attack.is_(True), 1), else_=0)),
        func.avg(Prediction.confidence),
    )
    if since is not None:
        base = base.where(Prediction.created_at >= since)
    total, suspicious, avg_conf = db.execute(base).one()
    total = int(total or 0)
    suspicious = int(suspicious or 0)

    alert_query = select(func.count(Alert.id)).where(Alert.status != "resolved")
    if since is not None:
        alert_query = alert_query.where(Alert.created_at >= since)
    active_alerts = int(db.scalar(alert_query) or 0)

    alert_total_query = select(func.count(Alert.id))
    if since is not None:
        alert_total_query = alert_total_query.where(Alert.created_at >= since)
    alerts_total = int(db.scalar(alert_total_query) or 0)

    return {
        "total_traffic": total,
        "normal_traffic": total - suspicious,
        "suspicious_traffic": suspicious,
        "detection_rate": round(suspicious / total, 6) if total else 0.0,
        "active_alerts": active_alerts,
        "alerts_total": alerts_total,
        "average_confidence": round(float(avg_conf or 0.0), 6),
        "window_hours": hours,
    }


def attack_distribution(db: Session, hours: int | None = None, limit: int = 12) -> dict[str, int]:
    since = _since(hours)
    stmt = (
        select(Prediction.prediction, func.count())
        .where(Prediction.is_attack.is_(True))
        .group_by(Prediction.prediction)
        .order_by(func.count().desc())
        .limit(limit)
    )
    if since is not None:
        stmt = stmt.where(Prediction.created_at >= since)
    return {str(name): int(count) for name, count in db.execute(stmt).all()}


def risk_distribution(db: Session, hours: int | None = None) -> dict[str, int]:
    since = _since(hours)
    stmt = select(Prediction.risk_level, func.count()).group_by(Prediction.risk_level)
    if since is not None:
        stmt = stmt.where(Prediction.created_at >= since)
    counts = {level: 0 for level in ("low", "medium", "high", "critical")}
    for level, count in db.execute(stmt).all():
        counts[str(level)] = int(count)
    return counts


def traffic_timeline(db: Session, hours: int = 24, bucket: str = "hour") -> list[dict]:
    """
    Traffic over time.

    Uses the hourly rollup table (fast). Falls back to grouping the predictions
    table directly when a bucket has not been rolled up yet.
    """
    since = _now() - timedelta(hours=hours)
    rows = db.scalars(
        select(DetectionStatistic)
        .where(DetectionStatistic.bucket_start >= since)
        .order_by(DetectionStatistic.bucket_start.asc())
    ).all()
    points = [
        {
            "bucket": row.bucket_start.isoformat(),
            "label": row.bucket_start.strftime("%d %b %H:%M"),
            "total": row.total,
            "normal": row.normal,
            "suspicious": row.suspicious,
            "alerts": row.alerts,
        }
        for row in rows
    ]
    if points:
        return points

    # fallback: aggregate raw predictions per hour
    dialect_hour = func.strftime("%Y-%m-%d %H:00:00", Prediction.created_at) if _is_sqlite(db) else func.date_trunc("hour", Prediction.created_at)
    raw = db.execute(
        select(
            dialect_hour,
            func.count(Prediction.id),
            func.sum(case((Prediction.is_attack.is_(True), 1), else_=0)),
        )
        .where(Prediction.created_at >= since)
        .group_by(dialect_hour)
        .order_by(dialect_hour)
    ).all()
    return [
        {
            "bucket": str(bucket_value),
            "label": str(bucket_value)[:16],
            "total": int(total or 0),
            "normal": int(total or 0) - int(suspicious or 0),
            "suspicious": int(suspicious or 0),
            "alerts": 0,
        }
        for bucket_value, total, suspicious in raw
    ]


def _is_sqlite(db: Session) -> bool:
    return db.bind.dialect.name == "sqlite"  # type: ignore[union-attr]


def recent_alerts(db: Session, limit: int = 10) -> list[dict]:
    rows = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(limit)).all()
    return [a.to_dict() for a in rows]


def verdict_share(db: Session, hours: int | None = None) -> dict:
    m = metrics(db, hours)
    total = m["total_traffic"] or 1
    return {
        "normal_pct": round(100 * m["normal_traffic"] / total, 4),
        "suspicious_pct": round(100 * m["suspicious_traffic"] / total, 4),
    }


def overview(db: Session, hours: int | None = 24, timeline_hours: int = 24, alert_limit: int = 8) -> dict:
    """Everything the dashboard needs in one response."""
    dataset_count = int(db.scalar(select(func.count(Dataset.id))) or 0)
    job_count = int(db.scalar(select(func.count(AnalysisJob.id))) or 0)
    last_job = db.scalars(select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(1)).first()

    evaluation = model_service.evaluation or {}
    metadata = model_service.metadata or {}

    return {
        "metrics": metrics(db, hours),
        "verdict_share": verdict_share(db, hours),
        "risk_distribution": risk_distribution(db, hours),
        "attack_distribution": attack_distribution(db, hours),
        "timeline": traffic_timeline(db, hours=timeline_hours),
        "recent_alerts": recent_alerts(db, alert_limit),
        "model": {
            "algorithm": metadata.get("algorithm"),
            "n_estimators": metadata.get("n_estimators"),
            "dataset": metadata.get("dataset"),
            "test_accuracy": evaluation.get("accuracy"),
            "macro_f1": evaluation.get("macro_f1"),
            "n_test": evaluation.get("n_test"),
            "n_features": len(model_service.feature_names()),
            "classes": model_service.classes_ if model_service.is_loaded else [],
            "loaded": model_service.is_loaded,
            "trained_at": metadata.get("trained_at"),
            "accuracy_label": "Model Test Accuracy (CICIDS2017 held-out split)",
        },
        "datasets": dataset_count,
        "jobs": job_count,
        "last_job": last_job.to_dict() if last_job else None,
        "ai": {
            "provider": settings.AI_PROVIDER,
            "enabled": settings.ai_enabled,
            "mode": "external LLM" if settings.ai_enabled else "local explanation engine",
        },
        "reference_dataset": {
            "name": "CICIDS2017 (MachineLearningCVE)",
            "full_rows": (model_service.reference_stats or {}).get("full_dataset_rows"),
            "full_columns": (model_service.reference_stats or {}).get("full_dataset_columns"),
            "training_rows": metadata.get("training_table", {}).get("rows"),
        },
    }
