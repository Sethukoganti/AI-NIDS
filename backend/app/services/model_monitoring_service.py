"""Operational model-health metrics derived from persisted predictions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.database_models import Prediction


def _day_expression(db: Session):
    if db.bind is not None and db.bind.dialect.name == "sqlite":
        return func.strftime("%Y-%m-%d", Prediction.created_at)
    return func.date_trunc("day", Prediction.created_at)


def _aggregate(db: Session, since: datetime, until: datetime | None = None) -> dict:
    stmt = select(
        func.count(Prediction.id),
        func.avg(Prediction.confidence),
        func.sum(case((Prediction.confidence < 0.6, 1), else_=0)),
        func.sum(case((Prediction.ground_truth.is_not(None), 1), else_=0)),
        func.sum(
            case(
                (
                    Prediction.ground_truth.is_not(None)
                    & (Prediction.ground_truth == Prediction.prediction),
                    1,
                ),
                else_=0,
            )
        ),
    ).where(Prediction.created_at >= since)
    if until is not None:
        stmt = stmt.where(Prediction.created_at < until)
    total, average_confidence, low_confidence, labeled, correct = db.execute(stmt).one()
    return {
        "total": int(total or 0),
        "average_confidence": float(average_confidence or 0.0),
        "low_confidence": int(low_confidence or 0),
        "labeled": int(labeled or 0),
        "correct": int(correct or 0),
    }


def overview(db: Session, hours: int = 168) -> dict:
    """Summarize recent confidence, label coverage, and prediction-class movement."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    previous = _aggregate(db, since - timedelta(hours=hours), since)
    current = _aggregate(db, since)

    day = _day_expression(db)
    rows = db.execute(
        select(
            day,
            func.count(Prediction.id),
            func.avg(Prediction.confidence),
            func.sum(case((Prediction.confidence < 0.6, 1), else_=0)),
        )
        .where(Prediction.created_at >= since)
        .group_by(day)
        .order_by(day)
    ).all()
    points = [
        {
            "day": str(bucket),
            "predictions": int(count or 0),
            "average_confidence": round(float(confidence or 0.0), 4),
            "low_confidence": int(low_confidence or 0),
        }
        for bucket, count, confidence, low_confidence in rows
    ]

    classes = db.execute(
        select(Prediction.prediction, func.count())
        .where(Prediction.created_at >= since)
        .group_by(Prediction.prediction)
        .order_by(func.count().desc())
        .limit(8)
    ).all()

    total = current["total"]
    labeled = current["labeled"]
    prior_confidence = previous["average_confidence"]
    confidence_change = (
        current["average_confidence"] - prior_confidence
        if previous["total"]
        else None
    )
    return {
        "window_hours": hours,
        "total_predictions": total,
        "average_confidence": round(current["average_confidence"], 4),
        "low_confidence_percent": round(current["low_confidence"] / total, 4) if total else 0.0,
        "labeled_predictions": labeled,
        "labeled_accuracy": round(current["correct"] / labeled, 4) if labeled else None,
        "previous_average_confidence": round(prior_confidence, 4) if previous["total"] else None,
        "confidence_change": round(confidence_change, 4) if confidence_change is not None else None,
        "class_distribution": {str(name): int(count) for name, count in classes},
        "daily": points,
    }
