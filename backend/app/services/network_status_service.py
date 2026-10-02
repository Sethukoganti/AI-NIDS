"""
Network status management.

The current operational status is a single row (:class:`NetworkStatus`) and every
transition is appended to :class:`NetworkStatusHistory` with who/why/how long.
Statuses come from two places and the ``source`` field always says which:

``manual``
    An admin used the Network Control Center.
``automatic``
    :func:`evaluate` compared recent traffic/alert indicators against the
    thresholds the admin configured and, when auto-status is enabled *and* not in
    "suggest only" mode, applied the resulting status itself.
``system``
    Startup defaults or a maintenance lock.

Nothing in this module invents a security condition: the evaluator only reports
what the stored predictions and alerts actually show, and when it recommends a
status it lists every indicator it used so the admin can judge it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import network_modes
from app.core.network_modes import (
    SOURCE_AUTOMATIC,
    SOURCE_MANUAL,
    SOURCE_SYSTEM,
    STATUS_CRITICAL_THREAT,
    STATUS_ELEVATED_THREAT,
    STATUS_HIGH_TRAFFIC,
    STATUS_NORMAL,
)
from app.models.database_models import NetworkStatus, NetworkStatusHistory
from app.services import audit_service, config_service

logger = logging.getLogger("ainids.network_status")

CATEGORY = audit_service.CAT_NETWORK

#: Indicators the evaluator reads, in the order the UI lists them.
INDICATOR_KEYS = (
    "total_flows",
    "suspicious_percent",
    "attack_percent",
    "open_alerts",
    "critical_alerts",
    "incidents",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def current(db: Session) -> NetworkStatus:
    """Fetch (or lazily create) the single status row."""
    return NetworkStatus.load(db)


def current_dict(db: Session) -> dict:
    """Current status plus its resolved definition - the shape the UI badge needs."""
    row = current(db)
    data = row.to_dict()
    data.update(network_modes.definition(row.status))
    data["status_key"] = row.status
    data["profile"] = network_modes.profile(row.status)
    return data


def history(db: Session, limit: int = 50) -> list[dict]:
    rows = db.scalars(
        select(NetworkStatusHistory)
        .order_by(NetworkStatusHistory.started_at.desc(), NetworkStatusHistory.id.desc())
        .limit(min(limit, 500))
    ).all()
    return [row.to_dict() for row in rows]


# --------------------------------------------------------------------------- #
# Transitions
# --------------------------------------------------------------------------- #
def set_status(
    db: Session,
    status: str,
    *,
    user=None,
    request=None,
    reason: str | None = None,
    source: str = SOURCE_MANUAL,
    triggers: list[dict] | None = None,
    commit: bool = True,
) -> dict:
    """
    Move the platform into ``status``.

    Closes the current history entry, opens a new one, snapshots the
    configuration that is in effect (so the history entry is self-describing) and
    writes the audit entry.  A no-op transition is reported, not recorded twice.
    """
    if not network_modes.is_valid_status(status):
        raise ValueError(
            f"unknown status '{status}'; expected one of: {', '.join(network_modes.VALID_STATUSES)}"
        )
    if not network_modes.is_valid_source(source):
        raise ValueError(f"unknown status source '{source}'")

    row = current(db)
    now = _now()

    if row.status == status and row.source == source:
        return {"changed": False, "status": current_dict(db)}

    previous_status = row.status
    open_entry = db.scalar(
        select(NetworkStatusHistory)
        .where(NetworkStatusHistory.status == previous_status, NetworkStatusHistory.ended_at.is_(None))
        .order_by(NetworkStatusHistory.started_at.desc())
    )
    if open_entry is not None:
        open_entry.ended_at = now
        started = open_entry.started_at
        if started is not None and started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        open_entry.duration_seconds = int((now - started).total_seconds()) if started else None

    row.previous_status = previous_status
    row.status = status
    row.source = source
    row.reason = (reason or "").strip() or None
    row.changed_by = getattr(user, "id", None)
    row.started_at = now
    row.triggers = list(triggers or [])
    db.add(row)

    # The snapshot has to describe the profile of the status we are *entering*,
    # so it is taken after the row carries the new status.
    snapshot = config_service.status_configuration_snapshot(db)
    row.configuration_applied = snapshot

    db.add(
        NetworkStatusHistory(
            status=status,
            previous_status=previous_status,
            source=source,
            reason=row.reason,
            changed_by=getattr(user, "id", None),
            changed_by_email=getattr(user, "email", None),
            started_at=now,
            configuration_applied=snapshot,
            triggers=list(triggers or []),
        )
    )
    db.flush()

    audit_service.record(
        db,
        action="network.status_changed",
        user=user,
        request=request,
        category=CATEGORY,
        resource="network_status",
        previous_value={"status": previous_status},
        new_value={"status": status, "source": source},
        detail={
            "reason": row.reason,
            "triggers": list(triggers or []),
            "configuration_applied": snapshot,
            "mode_label": snapshot.get("mode_label"),
        },
    )

    # Background workers, middleware and the analysis pipeline read the effective
    # configuration through a short-lived process cache, so drop it here: the new
    # status profile has to be live for the very next request.
    config_service.invalidate_runtime_cache()

    if commit:
        db.commit()

    # Run the notification inside a SAVEPOINT.  When ``commit`` is False the
    # caller still owns an open transaction that holds the status transition
    # itself, so a blanket ``rollback()`` here would silently discard the
    # transition we just made - the savepoint confines the damage to the
    # notification insert.
    try:
        from app.services import notification_service

        with db.begin_nested():
            notification_service.notify_network_status(db, current_dict(db))
        if commit:
            db.commit()
    except Exception:  # pragma: no cover - notifications must never break a transition
        logger.warning("could not record the network status notification", exc_info=True)

    logger.info(
        "network status %s -> %s (%s) by %s",
        previous_status,
        status,
        source,
        getattr(user, "email", "system"),
    )
    return {"changed": True, "previous_status": previous_status, "status": current_dict(db)}


def set_status_manual(
    db: Session, status: str, *, user=None, request=None, reason: str | None = None
) -> dict:
    return set_status(db, status, user=user, request=request, reason=reason, source=SOURCE_MANUAL)


# --------------------------------------------------------------------------- #
# Automatic evaluation
# --------------------------------------------------------------------------- #
@dataclass
class Indicator:
    key: str
    label: str
    value: float
    #: ``None`` means the indicator is measured and reported but has no configured
    #: threshold, so it can never trigger a status change on its own.  It stays
    #: ``None`` (rather than infinity) so the payload is strict-JSON serialisable.
    threshold: float | None
    unit: str = ""
    triggered: bool = False

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "threshold": self.threshold,
            "unit": self.unit,
            "triggered": self.triggered,
        }


@dataclass
class Evaluation:
    status: str
    indicators: list[Indicator]
    window_minutes: int
    auto_enabled: bool
    suggest_only: bool
    applied: bool = False

    def to_dict(self) -> dict:
        return {
            "recommended_status": self.status,
            "status": self.status,
            "label": network_modes.definition(self.status)["label"],
            "description": network_modes.definition(self.status)["description"],
            "tone": network_modes.definition(self.status)["tone"],
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "window_minutes": self.window_minutes,
            "auto_enabled": self.auto_enabled,
            "suggest_only": self.suggest_only,
            "applied": self.applied,
            "profile": network_modes.profile(self.status),
            "basis": "measured from stored predictions and alerts",
        }


def collect_indicators(db: Session, window_minutes: int, network: dict) -> list[Indicator]:
    """
    Measure the indicators from stored data.

    Every value is an aggregation over the ``predictions``/``alerts`` tables for
    the configured window - nothing is estimated or assumed.
    """
    from app.models.database_models import Alert, Investigation, Prediction

    since = _now() - timedelta(minutes=max(1, window_minutes))
    total = int(
        db.scalar(select(func.count(Prediction.id)).where(Prediction.created_at >= since)) or 0
    )
    suspicious = int(
        db.scalar(
            select(func.count(Prediction.id)).where(
                Prediction.created_at >= since, Prediction.is_attack.is_(True)
            )
        )
        or 0
    )
    open_alerts = int(
        db.scalar(select(func.count(Alert.id)).where(Alert.created_at >= since, Alert.status != "resolved")) or 0
    )
    critical_alerts = int(
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.created_at >= since, Alert.severity == "critical", Alert.status != "resolved"
            )
        )
        or 0
    )
    incidents = int(
        db.scalar(
            select(func.count(Investigation.id)).where(
                Investigation.created_at >= since, Investigation.status != "closed"
            )
        )
        or 0
    )

    total_for_pct = total or 1
    suspicious_pct = 100.0 * suspicious / total_for_pct
    attack_pct = suspicious_pct

    return [
        Indicator(
            key="total_flows",
            label="Traffic volume",
            value=float(total),
            threshold=_threshold(network, "traffic_volume_threshold"),
            unit="flows",
            triggered=_reached(total, network.get("traffic_volume_threshold")),
        ),
        Indicator(
            key="suspicious_percent",
            label="Suspicious traffic",
            value=round(suspicious_pct, 4),
            threshold=_threshold(network, "suspicious_percent_threshold"),
            unit="%",
            triggered=_reached(suspicious_pct, network.get("suspicious_percent_threshold")),
        ),
        Indicator(
            key="attack_percent",
            label="Attack rate",
            value=round(attack_pct, 4),
            threshold=_threshold(network, "attack_rate_threshold"),
            unit="%",
            triggered=_reached(attack_pct, network.get("attack_rate_threshold")),
        ),
        Indicator(
            key="open_alerts",
            label="Alert frequency",
            value=float(open_alerts),
            threshold=_threshold(network, "alert_rate_threshold"),
            unit="alerts",
            triggered=_reached(open_alerts, network.get("alert_rate_threshold")),
        ),
        Indicator(
            key="critical_alerts",
            label="Critical alerts",
            value=float(critical_alerts),
            threshold=_threshold(network, "critical_alert_threshold"),
            unit="alerts",
            triggered=_reached(critical_alerts, network.get("critical_alert_threshold")),
        ),
        Indicator(
            key="incidents",
            label="Open investigations",
            value=float(incidents),
            threshold=None,
            unit="cases",
            triggered=False,
        ),
    ]


def _threshold(network: dict, key: str) -> float | None:
    """Configured threshold, or ``None`` when the indicator is switched off."""
    try:
        value = float(network.get(key) or 0.0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _reached(value: float, threshold) -> bool:
    """A configured threshold of zero means 'disabled', not 'always exceeded'."""
    if threshold is None:
        return False
    try:
        limit = float(threshold or 0.0)
    except (TypeError, ValueError):
        return False
    return limit > 0 and value >= limit


def _classify(indicators: list[Indicator]) -> str:
    """
    Map measured indicators onto a status.

    Highest matching band wins, so a single critical indicator is enough to reach
    CRITICAL THREAT while everything quiet stays NORMAL.
    """
    by_key = {indicator.key: indicator for indicator in indicators}

    critical = by_key["critical_alerts"].triggered
    elevated = (
        critical
        or by_key["suspicious_percent"].triggered
        or by_key["attack_percent"].triggered
        or by_key["open_alerts"].triggered
    )
    high_traffic = by_key["total_flows"].triggered

    if critical:
        return STATUS_CRITICAL_THREAT
    if elevated:
        return STATUS_ELEVATED_THREAT
    if high_traffic:
        return STATUS_HIGH_TRAFFIC
    return STATUS_NORMAL


def evaluate(db: Session, *, apply: bool | None = None, user=None, request=None) -> Evaluation:
    """
    Evaluate the operational status from stored indicators.

    ``apply`` defaults to the admin's configuration: automatic status has to be
    enabled *and* "suggest only" has to be off for the result to be written.
    """
    network = config_service.read(db, "network")
    window = int(network.get("auto_status_window_minutes") or 60)
    indicators = collect_indicators(db, window, network)
    status = _classify(indicators)

    auto_enabled = bool(network.get("auto_status_enabled"))
    suggest_only = bool(network.get("auto_status_suggest_only", True))
    should_apply = auto_enabled and not suggest_only if apply is None else apply

    evaluation = Evaluation(
        status=status,
        indicators=indicators,
        window_minutes=window,
        auto_enabled=auto_enabled,
        suggest_only=suggest_only,
    )

    row = current(db)
    if should_apply and auto_enabled and status in network_modes.AUTO_ASSIGNABLE and row.status != status:
        triggers = [i.to_dict() for i in indicators if i.triggered]
        reason = _reason_for(status, indicators)
        result = set_status(
            db,
            status,
            user=None,
            request=request,
            reason=reason,
            source=SOURCE_AUTOMATIC,
            triggers=triggers,
        )
        evaluation.status = status
        evaluation.applied = bool(result.get("changed"))
        db.commit()
    return evaluation


def _reason_for(status: str, indicators: list[Indicator]) -> str:
    triggered = [i for i in indicators if i.triggered]
    if not triggered:
        return "Automatic evaluation: no configured indicator threshold was reached."
    parts = [
        f"{i.label} {i.value:g}{(' ' + i.unit) if i.unit else ''} (threshold {_threshold_text(i)})"
        for i in triggered
    ]
    return (
        f"Automatic evaluation reached {network_modes.definition(status)['label']}: "
        + "; ".join(parts)
        + "."
    )


def _threshold_text(indicator: Indicator) -> str:
    if indicator.threshold is None:
        return "n/a"
    return f"{indicator.threshold:g}{(' ' + indicator.unit) if indicator.unit else ''}"


def status_overview(db: Session) -> dict:
    """Everything the Network Control Center needs about the current state."""
    row = current(db)
    network = config_service.read(db, "network")
    evaluation = evaluate(db, apply=False)
    data = current_dict(db)
    data["network"] = network
    data["evaluation"] = evaluation.to_dict()
    data["catalogue"] = network_modes.catalogue()
    data["statuses"] = list(network_modes.VALID_STATUSES)
    data["sources"] = list(network_modes.VALID_SOURCES)
    return data


def ensure_initialised(db: Session) -> None:
    """Create the first status row with ``source='system'`` on a fresh install."""
    row = db.get(NetworkStatus, NetworkStatus.SINGLETON_ID)
    if row is None:
        row = NetworkStatus(
            id=NetworkStatus.SINGLETON_ID,
            status=STATUS_NORMAL,
            source=SOURCE_SYSTEM,
            reason="Initial state created when the platform started.",
            started_at=_now(),
            triggers=[],
        )
        db.add(row)
        snapshot = config_service.status_configuration_snapshot(db)
        row.configuration_applied = snapshot
        db.add(
            NetworkStatusHistory(
                status=STATUS_NORMAL,
                previous_status=None,
                source=SOURCE_SYSTEM,
                reason=row.reason,
                started_at=_now(),
                configuration_applied=snapshot,
            )
        )
        db.commit()
        config_service.invalidate_runtime_cache()
        logger.info("network status initialised to %s", STATUS_NORMAL)


def apply_mode_configuration(db: Session) -> None:
    """
    No-op hook kept for symmetry with :func:`set_status`.

    The status profile is applied at read time by
    :func:`config_service.runtime_snapshot`, so a status change takes effect on
    the next request without rewriting any configuration row.  This documents that
    decision at the call site.
    """
    return None
