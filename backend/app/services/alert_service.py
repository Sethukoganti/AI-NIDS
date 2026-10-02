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
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.database_models import Alert, Prediction, User
from app.services import investigation_service, risk_service

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.services.config_service import RuntimeConfig

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
    runtime: "RuntimeConfig | None" = None,
) -> list[Alert]:
    """
    Turn the suspicious flows of one job into a bounded, one-per-pair alert set.

    Rule (see docs/ALERTING.md): the highest-risk flows each get an individual
    alert; every other suspicious flow is folded into the alert for its
    (attack type, destination port) pair, creating an aggregated alert only when
    that pair does not have one yet.

    ``runtime`` is the admin-configured :class:`config_service.RuntimeConfig`.  It
    decides whether alerts are produced at all, the lowest severity that may raise
    one, the confidence floor, the model configuration's pair ceiling, the
    individual-alert budget and the duplicate-handling mode.  Without it the
    documented defaults apply.
    """
    alertable_levels = ALERTABLE_LEVELS
    min_confidence = 0.0
    max_pairs = MAX_ALERT_PAIRS
    max_individual = MAX_INDIVIDUAL_ALERTS
    duplicate_handling = "aggregate"
    duplicate_window = 0
    enabled = True
    if runtime is not None:
        enabled = runtime.alerts_enabled
        alertable_levels = runtime.alertable_levels() or {"__none__"}
        min_confidence = runtime.min_confidence_to_alert
        max_pairs = max(1, runtime.max_alerts_per_job)
        max_individual = max(0, runtime.max_individual_alerts)
        duplicate_handling = runtime.duplicate_handling or "aggregate"
        duplicate_window = _duplicate_window(db)

    if not enabled:
        logger.info("job %s: alert generation disabled by configuration", job_id)
        return []

    candidates = [
        p
        for p in predictions
        if p.is_attack
        and p.risk_level in alertable_levels
        and (p.confidence or 0.0) >= min_confidence
    ]
    if not candidates:
        return []

    # Highest risk first; confidence breaks ties so the representative record of
    # every group is the one an analyst should look at.
    candidates.sort(key=lambda p: (-p.risk_score, -p.confidence))

    if duplicate_handling == "off":
        # Duplicate handling explicitly disabled: every suspicious flow keeps its
        # own alert.  ``max_alerts_per_job`` remains a hard safety ceiling.
        created = [
            _build_alert(
                prediction=prediction,
                job_id=job_id,
                dataset_id=dataset_id,
                aggregated=False,
                count=1,
            )
            for prediction in candidates[:max_pairs]
        ]
        db.add_all(created)
        db.flush()
        dropped = len(candidates) - len(created)
        logger.info(
            "job %s: duplicate handling 'off' -> %d alert(s) from %d suspicious flow(s)%s",
            job_id,
            len(created),
            len(candidates),
            f" ({dropped} beyond the {max_pairs}-alert ceiling)" if dropped > 0 else "",
        )
        return created

    # Pairs already alerted on inside the duplicate window are suppressed instead
    # of being counted again (only meaningful for 'suppress').
    suppressed_pairs: set[tuple[str, int | None]] = set()
    if duplicate_handling == "suppress" and duplicate_window > 0:
        suppressed_pairs = _recent_pairs(db, duplicate_window, job_id=job_id)

    created: list[Alert] = []
    by_pair: dict[tuple[str, int | None], Alert] = {}

    for index, prediction in enumerate(candidates):
        pair: tuple[str, int | None] = (prediction.prediction, prediction.destination_port)
        if pair in suppressed_pairs:
            continue
        if pair not in by_pair and len(by_pair) >= max_pairs:
            # ceiling reached: fold this pair's flows into a per-attack overflow
            # alert (destination_port=None, so the pair invariant still holds)
            pair = (prediction.prediction, None)

        existing = by_pair.get(pair)

        if existing is not None:
            if duplicate_handling == "suppress":
                # duplicate suppressed: the flow is dropped entirely rather than
                # folded into the existing alert
                continue

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

        aggregated = index >= max_individual or pair[1] is None
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
        "job %s: %d alert(s) from %d suspicious flow(s) across %d attack/port pair(s) "
        "(duplicate handling '%s')",
        job_id,
        len(created),
        len(candidates),
        len(by_pair),
        duplicate_handling,
    )
    return created


def _duplicate_window(db: Session) -> int:
    """``alerts.duplicate_window_seconds`` as read from the persisted configuration."""
    try:
        from app.services import config_service

        return int(config_service.read(db, "alerts").get("duplicate_window_seconds") or 0)
    except Exception:  # pragma: no cover - defensive
        return 0


def _recent_pairs(db: Session, window_seconds: int, job_id: str | None = None) -> set[tuple[str, int | None]]:
    """
    (attack type, destination port) pairs alerted on within the duplicate window.

    Scoped to ``job_id`` when given: the module invariant is one alert per
    (attack type, destination port) *per job*, and an earlier analysis of the
    same traffic must not silence the alerts of a later, unrelated one.  With no
    job the window spans every job, which is what a platform-wide dedupe wants.
    """
    cutoff = _now() - timedelta(seconds=window_seconds)
    stmt = select(Alert.attack_type, Alert.destination_port, Alert.created_at).where(
        Alert.created_at >= cutoff
    )
    if job_id is not None:
        stmt = stmt.where(Alert.job_id == job_id)
    rows = db.execute(stmt.limit(5000)).all()
    return {(str(attack), port) for attack, port, _ in rows}


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
            stmt = stmt.where(Alert.status.in_(["new", "reviewed", "acknowledged", "investigating"]))
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
                    Alert.severity.in_(["high", "critical"]),
                    ~Alert.status.in_(["resolved", "false_positive"]),
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
        if status in {"resolved", "false_positive"}:
            alert.resolved_at = _now()
        if (
            status
            in {
                "reviewed",
                "acknowledged",
                "investigating",
                "resolved",
                "false_positive",
            }
            and user is not None
        ):
            alert.reviewed_by = user.id
        if (
            status in {"reviewed", "acknowledged", "investigating"}
            and alert.acknowledged_at is None
        ):
            alert.acknowledged_at = _now()
            alert.acknowledged_by = user.id if user is not None else None
    if notes is not None:
        base = f"occurrences={_read_count(alert.notes)}" if alert.notes else ""
        alert.notes = f"{base} | {notes}".strip(" |")
    db.flush()
    return alert


def acknowledge_alert(db: Session, alert: Alert, user: User | None = None) -> Alert:
    """Mark an alert as acknowledged without resolving it."""
    alert.status = "reviewed"
    alert.acknowledged_at = _now()
    alert.acknowledged_by = user.id if user is not None else None
    alert.reviewed_by = alert.reviewed_by or (user.id if user is not None else None)
    db.flush()
    return alert


def escalate_stale_alerts(db: Session, runtime: "RuntimeConfig | None" = None) -> int:
    """
    Flag alerts that stayed open past the configured escalation window.

    Returns the number of alerts escalated so the caller can report it; the
    operation is idempotent because ``escalated`` is sticky.
    """
    if runtime is None:
        from app.services import config_service

        runtime = config_service.get_runtime(db=db)
    if not runtime.escalation_enabled:
        return 0

    minutes = max(1, int(runtime.escalate_after_minutes))
    target_severity = runtime.escalate_to_severity
    cutoff = _now() - timedelta(minutes=minutes)

    rows = db.scalars(
        select(Alert).where(
            Alert.escalated.is_(False),
            Alert.status != "resolved",
            Alert.created_at <= cutoff,
        )
    ).all()
    now = _now()
    escalated = 0
    for alert in rows:
        alert.escalated = True
        alert.escalated_at = now
        if risk_service.LEVEL_ORDER.get(target_severity, 0) > risk_service.LEVEL_ORDER.get(alert.severity, 0):
            alert.severity = target_severity
        escalated += 1
        investigation_service.ensure_for_alert(db, alert, runtime=runtime)
    if rows:
        db.flush()
        logger.info("escalated %d alert(s) open for more than %d minute(s)", escalated, minutes)
    return escalated
