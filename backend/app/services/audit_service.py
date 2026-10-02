"""
Audit service - one place that writes the audit trail.

Every important action (configuration change, status change, user management,
model deployment, ...) goes through :func:`record`, which stamps the full context
the platform promises to keep: who, with which role, what, when, from where,
what changed (``previous_value`` -> ``new_value``) and the result.

The function never commits on its own - it adds the row to the caller's session
so the audit entry and the change it describes commit atomically.  Use
``commit=True`` only where there is nothing else to persist.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.database_models import AuditLog

logger = get_logger("ainids.audit")

# Result values
RESULT_SUCCESS = "success"
RESULT_FAILURE = "failure"
RESULT_DENIED = "denied"
RESULT_VALIDATION_ERROR = "validation_error"

# Categories (kept short so the audit UI can group them)
CAT_AUTH = "auth"
CAT_USER = "user"
CAT_ROLE = "role"
CAT_NETWORK = "network"
CAT_DETECTION = "detection"
CAT_ALERT = "alert"
CAT_MODEL = "model"
CAT_DATASET = "dataset"
CAT_SETTINGS = "settings"
CAT_DATA = "data"
CAT_INVESTIGATION = "investigation"
CAT_GENERAL = "general"


def client_ip(request: Any) -> str | None:
    """Best-effort client IP, honouring a single reverse-proxy hop."""
    if request is None:
        return None
    try:
        headers = getattr(request, "headers", {}) or {}
        forwarded = headers.get("x-forwarded-for") if hasattr(headers, "get") else None
        if forwarded:
            first = str(forwarded).split(",")[0].strip()
            if first:
                return first[:64]
        client = getattr(request, "client", None)
        host = getattr(client, "host", None)
        return str(host)[:64] if host else None
    except Exception:  # pragma: no cover - defensive
        return None


def user_agent(request: Any) -> str | None:
    if request is None:
        return None
    try:
        headers = getattr(request, "headers", {}) or {}
        value = headers.get("user-agent") if hasattr(headers, "get") else None
        return str(value)[:255] if value else None
    except Exception:  # pragma: no cover - defensive
        return None


def record(
    db: Session,
    *,
    action: str,
    user: Any = None,
    request: Any = None,
    category: str = CAT_GENERAL,
    resource: str | None = None,
    previous_value: dict | None = None,
    new_value: dict | None = None,
    result: str = RESULT_SUCCESS,
    detail: dict | None = None,
    commit: bool = False,
) -> AuditLog:
    """
    Append one audit entry.

    ``previous_value`` / ``new_value`` accept any JSON-serialisable mapping; they
    are wrapped in ``{"value": ...}`` only when a raw scalar is supplied, so the
    audit UI can always render a before/after diff.
    """
    user_id = getattr(user, "id", None) if user is not None else None
    user_email = getattr(user, "email", None) if user is not None else None
    user_role = getattr(user, "role", None) if user is not None else None

    entry = AuditLog(
        user_id=user_id,
        user_email=user_email,
        user_role=user_role,
        action=action[:64],
        category=(category or CAT_GENERAL)[:40],
        resource=resource[:120] if resource else None,
        previous_value=_wrap(previous_value),
        new_value=_wrap(new_value),
        result=result[:20],
        detail=detail or {},
        ip_address=client_ip(request),
        user_agent=user_agent(request),
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    if commit:
        db.commit()
    else:
        db.flush()
    return entry


def record_change(
    db: Session,
    *,
    scope: str,
    changes: dict[str, dict[str, Any]],
    user: Any = None,
    request: Any = None,
    category: str | None = None,
    resource: str | None = None,
    note: str | None = None,
    result: str = RESULT_SUCCESS,
    detail: dict | None = None,
    commit: bool = False,
) -> list[AuditLog]:
    """Record one audit entry per changed field (previous -> new)."""
    entries: list[AuditLog] = []
    mapped_category = category or {
        "network": CAT_NETWORK,
        "detection": CAT_DETECTION,
        "alerts": CAT_ALERT,
        "alert": CAT_ALERT,
        "model": CAT_MODEL,
        "system": CAT_SETTINGS,
    }.get(scope, CAT_SETTINGS)
    for key, change in changes.items():
        entries.append(
            record(
                db,
                action=f"{scope}.{key}_changed",
                user=user,
                request=request,
                category=mapped_category,
                resource=resource or scope,
                previous_value=change.get("previous"),
                new_value=change.get("new"),
                result=result,
                detail={"note": note, **(detail or {})} if note else detail,
                commit=False,
            )
        )
    if commit:
        db.commit()
    return entries


def _wrap(value: Any) -> dict | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    return {"value": value}


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #
def list_entries(
    db: Session,
    *,
    user_id: str | None = None,
    category: str | None = None,
    action: str | None = None,
    result: str | None = None,
    resource: str | None = None,
    search: str | None = None,
    since: datetime | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    from sqlalchemy import func, or_, select

    stmt = select(AuditLog)
    count_stmt = select(func.count(AuditLog.id))
    conditions = []
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    if category and category != "all":
        conditions.append(AuditLog.category == category)
    if action and action != "all":
        conditions.append(AuditLog.action == action)
    if result and result != "all":
        conditions.append(AuditLog.result == result)
    if resource:
        conditions.append(AuditLog.resource == resource)
    if since is not None:
        conditions.append(AuditLog.created_at >= since)
    if search:
        like = f"%{search.lower()}%"
        conditions.append(
            or_(
                func.lower(AuditLog.action).like(like),
                func.lower(func.coalesce(AuditLog.resource, "")).like(like),
                func.lower(func.coalesce(AuditLog.user_email, "")).like(like),
                func.lower(func.coalesce(AuditLog.ip_address, "")).like(like),
            )
        )
    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int(db.scalar(count_stmt) or 0)
    stmt = (
        stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(max(page - 1, 0) * page_size)
        .limit(min(page_size, 500))
    )
    rows = db.scalars(stmt).all()
    return {
        "items": [row.to_dict() for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


def summary(db: Session, *, days: int = 7) -> dict:
    """Aggregates used by the admin dashboard / audit page header."""
    from datetime import timedelta

    from sqlalchemy import func, select

    since = datetime.now(timezone.utc) - timedelta(days=days)
    scoped = select(AuditLog).where(AuditLog.created_at >= since)

    by_category = {
        str(k): int(v) for k, v in db.execute(
            select(AuditLog.category, func.count()).where(AuditLog.created_at >= since).group_by(AuditLog.category)
        ).all()
    }
    by_result = {
        str(k): int(v) for k, v in db.execute(
            select(AuditLog.result, func.count()).where(AuditLog.created_at >= since).group_by(AuditLog.result)
        ).all()
    }
    recent_actions = [
        str(k) for k, in db.execute(
            select(AuditLog.action).where(AuditLog.created_at >= since).group_by(AuditLog.action)
        ).all()
    ]
    distinct_users = int(db.scalar(select(func.count(func.distinct(AuditLog.user_id))).where(AuditLog.created_at >= since)) or 0)
    return {
        "window_days": days,
        "total": int(db.scalar(select(func.count()).select_from(scoped.subquery())) or 0),
        "by_category": by_category,
        "by_result": by_result,
        "distinct_users": distinct_users,
        "actions": sorted(recent_actions),
    }
