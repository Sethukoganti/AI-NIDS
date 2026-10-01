"""
Alert service - turns suspicious predictions into trackable security alerts.

Flood-control policy (implemented here, documented in docs/ALERTING.md and
exposed verbatim through ``GET /api/alerts/rules``):

1. Alerts are raised only for attack predictions at risk level MEDIUM, HIGH or
   CRITICAL - never for normal traffic, and never "critical" by default.
2. Flows are processed highest-risk first. The first flow of a pair creates that
   pair's alert in single-flow form; every further flow of the same
   (attack type, destination port) is folded into it, which turns it into a
   "(burst)" alert that keeps ``occurrences=N``, the worst severity seen and a
   link to the highest-risk record of the pair. Only the first
   ``MAX_INDIVIDUAL_ALERTS`` created alerts can stay in single-flow form (a pair
   that occurs exactly once) - on real captures almost everything aggregates.
3. At most ``MAX_ALERT_PAIRS`` (300) distinct pairs own an alert per job; flows
   of pairs beyond that ceiling fold into one overflow alert per attack type.

Invariant enforced by this module (and asserted in the tests): at most **one
alert per (attack type, destination port)** per job, therefore the alert queue
never contains two entries for the same attack/port combination.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.database_models import Alert, Prediction, User
from app.services import risk_service

logger = get_logger("ainids.alerts")

MAX_INDIVIDUAL_ALERTS = 50
# Hard ceiling on how many distinct attack/port pairs may own an alert in one job.
# Anything beyond it is folded into a single per-attack overflow alert (port = None).
MAX_ALERT_PAIRS = 300
ALERTABLE_LEVELS = {"medium", "high", "critical"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_alerts_for_job(
    db: Session,
    job_id: str,
    dataset_id: str,
    predictions: list[Prediction],
) -> list[Alert]:
    """
    Turn the suspicious flows of one job into a bounded, one-per-pair alert set.

    Rule (see docs/ALERTING.md): the highest-risk flows each get an individual
    alert; every other suspicious flow is folded into the alert for its
    (attack type, destination port) pair, creating an aggregated alert only when
    that pair does not have one yet.
    """
    candidates = [p for p in predictions if p.is_attack and p.risk_level in ALERTABLE_LEVELS]
    if not candidates:
        return []

    # Highest risk first; confidence breaks ties so the representative record of
    # every group is the one an analyst should look at.
    candidates.sort(key=lambda p: (-p.risk_score, -p.confidence))

    created: list[Alert] = []
    by_pair: dict[tuple[str, int | None], Alert] = {}

    for index, prediction in enumerate(candidates):
        pair: tuple[str, int | None] = (prediction.prediction, prediction.destination_port)
        if pair not in by_pair and len(by_pair) >= MAX_ALERT_PAIRS:
            # ceiling reached: fold this pair's flows into a per-attack overflow
            # alert (destination_port=None, so the pair invariant still holds)
            pair = (prediction.prediction, None)

        existing = by_pair.get(pair)

        if existing is not None:
            # fold into the alert that already covers this attack/port pair
            attack = prediction.prediction
            port = existing.destination_port
            port_txt = f" against port {int(port)}" if port is not None else ""
            best_confidence = max(existing.confidence or 0.0, prediction.confidence)

            existing.notes = _bump_count(existing.notes)
            count = _read_count(existing.notes)
            if not _is_aggregated(existing.alert_type):
                existing.alert_type = f"{attack} (burst)"
            existing.message = (
                f"Potential {attack} detected{port_txt}: {count} flows classified as {attack} "
                f"(highest confidence {best_confidence * 100:.1f}%). Aggregated alert."
            )
            existing.confidence = best_confidence
            if risk_service.LEVEL_ORDER[prediction.risk_level] > risk_service.LEVEL_ORDER[existing.severity]:
                existing.severity = prediction.risk_level
                existing.risk_score = max(existing.risk_score or 0.0, prediction.risk_score)
            continue

        aggregated = index >= MAX_INDIVIDUAL_ALERTS or pair[1] is None
        alert = _build_alert(
            prediction=prediction,
            job_id=job_id,
            dataset_id=dataset_id,
            aggregated=aggregated,
            count=1,
        )
        db.add(alert)
        created.append(alert)
        by_pair[pair] = alert

    db.flush()
    logger.info(
        "job %s: %d alert(s) from %d suspicious flow(s) across %d attack/port pair(s)",
        job_id,
        len(created),
        len(candidates),
        len(by_pair),
    )
    return created


def _build_alert(
    prediction: Prediction,
    job_id: str,
    dataset_id: str,
    aggregated: bool,
    count: int,
) -> Alert:
    attack = prediction.prediction
    confidence_pct = f"{prediction.confidence * 100:.1f}%"
    port = prediction.destination_port
    port_txt = f" against port {int(port)}" if port is not None else ""
    scope = "flows" if aggregated else "flow"

    if aggregated:
        message = (
            f"Potential {attack} detected{port_txt}: {count} {scope} classified as {attack} "
            f"(highest confidence {confidence_pct}). Aggregated alert."
        )
        alert_type = f"{attack} (burst)"
    else:
        message = f"Potential {attack} detected{port_txt} - model confidence {confidence_pct}."
        alert_type = f"{attack} detected"

    return Alert(
        prediction_id=prediction.id,
        job_id=job_id,
        dataset_id=dataset_id,
        alert_type=alert_type,
        attack_type=attack,
        severity=prediction.risk_level,
        status="new",
        message=message,
        confidence=prediction.confidence,
        risk_score=prediction.risk_score,
        source_ip=prediction.source_ip,
        destination_port=prediction.destination_port,
        record_index=prediction.record_index,
        notes=f"occurrences={count}",
    )


def _is_aggregated(alert_type: str | None) -> bool:
    return bool(alert_type) and alert_type.endswith("(burst)")


def _read_count(notes: str | None) -> int:
    if not notes:
        return 1
    try:
        return int(notes.split("=")[1])
    except (IndexError, ValueError):
        return 1


def _bump_count(notes: str | None) -> str:
    return f"occurrences={_read_count(notes) + 1}"


# --------------------------------------------------------------------------- #
# Queries / lifecycle
# --------------------------------------------------------------------------- #
def list_alerts(
    db: Session,
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    job_id: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> dict:
    stmt = select(Alert)
    if status and status != "all":
        if status == "open":  # convenience alias used by the UI
            stmt = stmt.where(Alert.status.in_(["new", "reviewed"]))
        else:
            stmt = stmt.where(Alert.status == status)
    if severity and severity != "all":
        stmt = stmt.where(Alert.severity == severity)
    if attack_type and attack_type != "all":
        stmt = stmt.where(Alert.attack_type == attack_type)
    if job_id:
        stmt = stmt.where(Alert.job_id == job_id)
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            func.lower(Alert.message).like(like) | func.lower(Alert.attack_type).like(like)
        )

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = (
        stmt.order_by(Alert.created_at.desc())
        .offset(max(page - 1, 0) * page_size)
        .limit(page_size)
    )
    rows = db.scalars(stmt).all()
    return {
        "items": [a.to_dict() for a in rows],
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "pages": max(1, (int(total) + page_size - 1) // page_size),
    }


def alert_summary(db: Session) -> dict:
    def count_by(column) -> dict[str, int]:
        rows = db.execute(select(column, func.count()).group_by(column)).all()
        return {str(k): int(v) for k, v in rows}

    return {
        "total": int(db.scalar(select(func.count(Alert.id))) or 0),
        "by_severity": count_by(Alert.severity),
        "by_status": count_by(Alert.status),
        "by_attack_type": count_by(Alert.attack_type),
        "new": int(db.scalar(select(func.count(Alert.id)).where(Alert.status == "new")) or 0),
        "open_high_or_critical": int(
            db.scalar(
                select(func.count(Alert.id)).where(
                    Alert.severity.in_(["high", "critical"]), Alert.status != "resolved"
                )
            )
            or 0
        ),
    }


def update_alert(
    db: Session,
    alert_id: str,
    status: str | None = None,
    notes: str | None = None,
    user: User | None = None,
) -> Alert | None:
    alert = db.get(Alert, alert_id)
    if alert is None:
        return None
    if status:
        alert.status = status
        if status == "resolved":
            alert.resolved_at = _now()
        if status in {"reviewed", "resolved"} and user is not None:
            alert.reviewed_by = user.id
    if notes is not None:
        base = f"occurrences={_read_count(alert.notes)}" if alert.notes else ""
        alert.notes = f"{base} | {notes}".strip(" |")
    db.flush()
    return alert
