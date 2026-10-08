"""
Notification service - the in-app notification feed.

Notifications are generated from things that actually happened (an alert was
raised, the network status changed, a model candidate is waiting for approval)
and are filtered by the admin's configured severities.  There is no delivery
provider wired in: the feed is stored in PostgreSQL and polled by the console, and
the configured email/webhook addresses travel with the notification so an
external notifier can be added without changing this module.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.database_models import Notification, User

logger = get_logger("ainids.notifications")

SEVERITIES = ("info", "low", "medium", "high", "critical")
CATEGORIES = ("alert", "network", "model", "system", "user", "dataset")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def enabled(runtime: Any | None = None) -> bool:
    if runtime is None:
        from app.services import config_service

        runtime = config_service.get_runtime()
    return bool(getattr(runtime, "notifications_enabled", True))


def create(
    db: Session,
    *,
    title: str,
    message: str | None = None,
    severity: str = "info",
    category: str = "general",
    resource: str | None = None,
    resource_id: str | None = None,
    target_role: str | None = None,
    target_user: str | None = None,
    runtime: Any | None = None,
) -> Notification | None:
    """Create one notification, honouring the configured severity filter."""
    if not enabled(runtime):
        return None
    notification = Notification(
        severity=severity if severity in SEVERITIES else "info",
        category=category,
        title=title[:200],
        message=message,
        resource=resource,
        resource_id=resource_id,
        target_role=target_role,
        target_user=target_user,
    )
    db.add(notification)
    db.flush()
    return notification


def create_for_alerts(db: Session, alerts: Iterable, runtime: Any | None = None) -> int:
    """One notification per alert whose severity the admin asked to be notified about."""
    if runtime is None:
        from app.services import config_service

        runtime = config_service.get_runtime(db=db)
    if not runtime.notifications_enabled:
        return 0

    from app.services import config_service

    system = config_service.read(db, "system")
    configured = {str(s) for s in (system.get("notify_severities") or [])}
    admin_on_critical = bool(system.get("notify_admins_on_critical", True))

    created = 0
    for alert in alerts:
        severity = str(alert.severity)
        if configured and severity not in configured:
            continue
        create(
            db,
            title=f"{severity.upper()} alert: {alert.attack_type}",
            message=alert.message,
            severity=severity,
            category="alert",
            resource="alert",
            resource_id=alert.id,
            target_role="admin" if (admin_on_critical and severity == "critical") else None,
            runtime=runtime,
        )
        created += 1
    return created


def get_preferences(user: User) -> dict:
    stored = (user.preferences or {}).get("notifications", {})
    categories = stored.get("categories", list(CATEGORIES))
    if not isinstance(categories, list):
        categories = list(CATEGORIES)
    categories = [category for category in CATEGORIES if category in categories]
    minimum_severity = stored.get("minimum_severity", "info")
    if minimum_severity not in SEVERITIES:
        minimum_severity = "info"
    return {"categories": categories, "minimum_severity": minimum_severity}


def update_preferences(db: Session, user: User, preferences: dict) -> dict:
    existing = dict(user.preferences or {})
    existing["notifications"] = {
        "categories": [category for category in CATEGORIES if category in preferences["categories"]],
        "minimum_severity": preferences["minimum_severity"],
    }
    user.preferences = existing
    db.add(user)
    db.flush()
    return get_preferences(user)


def list_notifications(
    db: Session,
    *,
    user: User,
    is_read: bool | None = None,
    category: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> dict:
    """Notifications visible to ``user``: everything not role-restricted, plus theirs."""
    visible_to_user = and_(
        or_(
            Notification.target_role.is_(None),
            Notification.target_role == user.role,
        ),
        or_(
            Notification.target_user.is_(None),
            Notification.target_user == str(user.id),
        ),
    )
    preferences = get_preferences(user)
    minimum_index = SEVERITIES.index(preferences["minimum_severity"])
    allowed_severities = SEVERITIES[minimum_index:]
    stmt = select(Notification).where(
        visible_to_user,
        Notification.category.in_(preferences["categories"]),
        Notification.severity.in_(allowed_severities),
    )
    count_stmt = select(func.count(Notification.id)).where(
        visible_to_user,
        Notification.category.in_(preferences["categories"]),
        Notification.severity.in_(allowed_severities),
    )
    if is_read is not None:
        stmt = stmt.where(Notification.is_read.is_(is_read))
        count_stmt = count_stmt.where(Notification.is_read.is_(is_read))
    if category and category != "all":
        stmt = stmt.where(Notification.category == category)
        count_stmt = count_stmt.where(Notification.category == category)
    if severity and severity != "all":
        stmt = stmt.where(Notification.severity == severity)
        count_stmt = count_stmt.where(Notification.severity == severity)

    total = int(db.scalar(count_stmt) or 0)
    rows = db.scalars(
        stmt.order_by(Notification.created_at.desc(), Notification.id.desc())
        .offset(max(page - 1, 0) * page_size)
        .limit(min(page_size, 200))
    ).all()
    unread = int(
        db.scalar(
            select(func.count(Notification.id)).where(
                Notification.is_read.is_(False),
                visible_to_user,
                Notification.category.in_(preferences["categories"]),
                Notification.severity.in_(allowed_severities),
            )
        )
        or 0
    )
    return {
        "items": [row.to_dict() for row in rows],
        "total": total,
        "unread": unread,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "categories": list(CATEGORIES),
        "severities": list(SEVERITIES),
    }


def mark_read(db: Session, notification_id: str, user: User) -> Notification | None:
    notification = db.get(Notification, notification_id)
    if notification is None:
        return None
    if notification.target_role and notification.target_role != user.role:
        return None
    if notification.target_user and notification.target_user != str(user.id):
        return None
    notification.is_read = True
    notification.read_at = _now()
    db.flush()
    return notification


def mark_all_read(db: Session, user: User) -> int:
    rows = db.scalars(
        select(Notification).where(
            Notification.is_read.is_(False),
            and_(
                or_(
                    Notification.target_role.is_(None),
                    Notification.target_role == user.role,
                ),
                or_(
                    Notification.target_user.is_(None),
                    Notification.target_user == str(user.id),
                ),
            ),
        )
    ).all()
    now = _now()
    for row in rows:
        row.is_read = True
        row.read_at = now
    if rows:
        db.flush()
    return len(rows)


def notify_network_status(db: Session, status_payload: dict) -> Notification | None:
    """Inform the console about a status change (respects the notification switch)."""
    from app.services import config_service

    runtime = config_service.runtime_snapshot(db)
    if not runtime.notifications_enabled:
        return None
    severity = {"critical_threat": "critical", "elevated_threat": "high"}.get(
        str(status_payload.get("status")), "info"
    )
    return create(
        db,
        title=f"Network status: {status_payload.get('label', status_payload.get('status'))}",
        message=status_payload.get("reason") or status_payload.get("description"),
        severity=severity,
        category="network",
        resource="network_status",
        target_role="admin" if severity in {"high", "critical"} else None,
        runtime=runtime,
    )
