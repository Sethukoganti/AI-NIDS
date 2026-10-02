"""
Role-Based Access Control (RBAC).

The whole authorisation model of the platform lives here:

* :data:`PERMISSIONS` - the closed catalogue of every checkable capability.  The
  strings are the contract shared with the frontend (see ``frontend/src/lib/
  permissions.ts``), so a typo is visible immediately instead of silently
  denying access.
* :data:`ROLE_PERMISSIONS` - which role holds which capability.  Admin owns the
  platform; Analyst monitors and investigates it.
* :data:`ROLE_CAPABILITIES` - optional, database-backed, per-role overrides.  A
  row in the ``roles`` table can add or remove a permission for a role without a
  code change, which is what "Admin settings should be configurable without
  changing source code" means in practice.

Design rules
------------
1. The *database* is the single source of truth for a user's role.  The JWT only
   carries a hint so the frontend can render the right navigation - the backend
   always re-reads the user row (see ``security.get_current_user``).
2. ``require_permission`` is a FastAPI dependency factory, so authorisation is
   declared next to the route and enforced by the framework before the handler
   body runs.  Hiding a menu item in React is a usability feature, never a
   security control.
3. Every dependency raises ``403 Forbidden`` for an authenticated user without
   the capability (``401`` is reserved for missing/invalid credentials).
4. Denials are auditable: the RBAC dependency records the attempt through
   :mod:`app.services.audit_service` when an audit session is supplied.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable

from fastapi import Depends, HTTPException, Request, status

logger = logging.getLogger("ainids.rbac")

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
VALID_ROLES = (ROLE_ADMIN, ROLE_ANALYST)
DEFAULT_ROLE = ROLE_ANALYST

# --------------------------------------------------------------------------- #
# Permission catalogue
# --------------------------------------------------------------------------- #
P_DASHBOARD_VIEW = "dashboard.view"
P_DASHBOARD_SYSTEM = "dashboard.view_system"
P_TRAFFIC_ANALYZE = "traffic.analyze"
P_TRAFFIC_INVESTIGATE = "traffic.investigate"
P_PREDICTIONS_VIEW = "predictions.view"
P_MODEL_VIEW = "model.view"
P_ALERTS_VIEW = "alerts.view"
P_ALERTS_ACKNOWLEDGE = "alerts.acknowledge"
P_ALERTS_CONFIGURE = "alerts.configure"
P_INVESTIGATIONS_NOTES = "investigations.notes"
P_ASSISTANT_USE = "assistant.use"
P_NOTIFICATIONS_VIEW = "notifications.view"
P_DATASETS_VIEW = "datasets.view"
P_DATASETS_UPLOAD = "datasets.upload"
P_DATASETS_DELETE = "datasets.delete"
P_DATASETS_TRAIN = "datasets.mark_training"
P_USERS_MANAGE = "users.manage"
P_ROLES_MANAGE = "roles.manage"
P_NETWORK_CONFIGURE = "network.configure"
P_NETWORK_STATUS_MANAGE = "network.status.manage"
P_DETECTION_CONFIGURE = "detection.configure"
P_MODEL_CONFIGURE = "model.configure"
P_MODEL_DEPLOY = "model.deploy"
P_MODEL_TRAIN = "model.train"
P_SETTINGS_SYSTEM = "settings.system"
P_SETTINGS_RETENTION = "settings.retention"
P_SETTINGS_SECURITY = "settings.security"
P_SETTINGS_API = "settings.api"
P_AUDIT_VIEW = "audit.view"
P_SYSTEM_HEALTH = "system.health"

#: Human-readable grouping used by the admin UI to render the permission matrix.
PERMISSION_GROUPS: dict[str, tuple[str, ...]] = {
    "Monitoring": (P_DASHBOARD_VIEW, P_ALERTS_VIEW, P_ALERTS_ACKNOWLEDGE),
    "Analysis": (
        P_TRAFFIC_ANALYZE,
        P_PREDICTIONS_VIEW,
        P_TRAFFIC_INVESTIGATE,
        P_INVESTIGATIONS_NOTES,
        P_MODEL_VIEW,
        P_ASSISTANT_USE,
    ),
    "Data": (P_DATASETS_VIEW, P_DATASETS_UPLOAD, P_NOTIFICATIONS_VIEW),
    "Administration": (
        P_DASHBOARD_SYSTEM,
        P_USERS_MANAGE,
        P_ROLES_MANAGE,
        P_NETWORK_CONFIGURE,
        P_NETWORK_STATUS_MANAGE,
        P_DETECTION_CONFIGURE,
        P_ALERTS_CONFIGURE,
        P_DATASETS_DELETE,
        P_DATASETS_TRAIN,
        P_MODEL_CONFIGURE,
        P_MODEL_DEPLOY,
        P_MODEL_TRAIN,
        P_SETTINGS_SYSTEM,
        P_SETTINGS_RETENTION,
        P_SETTINGS_SECURITY,
        P_SETTINGS_API,
        P_AUDIT_VIEW,
        P_SYSTEM_HEALTH,
    ),
}

PERMISSIONS: dict[str, str] = {
    P_DASHBOARD_VIEW: "Open a monitoring dashboard",
    P_DASHBOARD_SYSTEM: "Open the infrastructure-level system dashboard",
    P_TRAFFIC_ANALYZE: "Upload traffic and run Random Forest analysis",
    P_TRAFFIC_INVESTIGATE: "Inspect individual traffic records and explanations",
    P_PREDICTIONS_VIEW: "Read model predictions",
    P_MODEL_VIEW: "Read the model card, metrics and feature importance",
    P_ALERTS_VIEW: "Read the alert queue",
    P_ALERTS_ACKNOWLEDGE: "Acknowledge alerts and change investigation status",
    P_ALERTS_CONFIGURE: "Configure severity thresholds, categories and escalation",
    P_INVESTIGATIONS_NOTES: "Write investigation notes",
    P_ASSISTANT_USE: "Use the AI Security Assistant",
    P_NOTIFICATIONS_VIEW: "Read the notification feed",
    P_DATASETS_VIEW: "Browse datasets and their profiles",
    P_DATASETS_UPLOAD: "Upload new traffic datasets",
    P_DATASETS_DELETE: "Delete datasets permanently",
    P_DATASETS_TRAIN: "Mark datasets as training candidates and manage versions",
    P_USERS_MANAGE: "Create, delete, enable, disable and reset user accounts",
    P_ROLES_MANAGE: "Change user roles and role permission overrides",
    P_NETWORK_CONFIGURE: "Change network configuration",
    P_NETWORK_STATUS_MANAGE: "Change the operational network status",
    P_DETECTION_CONFIGURE: "Change detection sensitivity and thresholds",
    P_MODEL_CONFIGURE: "Change model runtime configuration",
    P_MODEL_DEPLOY: "Activate a model version",
    P_MODEL_TRAIN: "Start and approve model retraining",
    P_SETTINGS_SYSTEM: "Change system, logging and dashboard settings",
    P_SETTINGS_RETENTION: "Change data and log retention",
    P_SETTINGS_SECURITY: "Change security settings",
    P_SETTINGS_API: "Change API configuration",
    P_AUDIT_VIEW: "Read the audit log",
    P_SYSTEM_HEALTH: "Read detailed system health information",
}

ADMIN_PERMISSIONS: tuple[str, ...] = tuple(PERMISSIONS)

ANALYST_PERMISSIONS: tuple[str, ...] = (
    P_DASHBOARD_VIEW,
    P_TRAFFIC_ANALYZE,
    P_TRAFFIC_INVESTIGATE,
    P_PREDICTIONS_VIEW,
    P_MODEL_VIEW,
    P_ALERTS_VIEW,
    P_ALERTS_ACKNOWLEDGE,
    P_INVESTIGATIONS_NOTES,
    P_ASSISTANT_USE,
    P_NOTIFICATIONS_VIEW,
    P_DATASETS_VIEW,
    P_DATASETS_UPLOAD,
)

ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    ROLE_ADMIN: ADMIN_PERMISSIONS,
    ROLE_ANALYST: ANALYST_PERMISSIONS,
}

ROLE_DESCRIPTIONS: dict[str, str] = {
    ROLE_ADMIN: "Manages, configures, secures and maintains the whole NIDS platform.",
    ROLE_ANALYST: "Monitors, analyses and investigates traffic and security events.",
}

#: Permissions that may never be removed from a role, whatever an override says.
#: Without them the platform would lock its own operators out of the console.
PROTECTED_PERMISSIONS: dict[str, tuple[str, ...]] = {
    ROLE_ADMIN: (P_DASHBOARD_VIEW, P_DASHBOARD_SYSTEM, P_USERS_MANAGE, P_ROLES_MANAGE, P_AUDIT_VIEW),
    ROLE_ANALYST: (P_DASHBOARD_VIEW, P_ALERTS_VIEW),
}


# --------------------------------------------------------------------------- #
# Resolution helpers
# --------------------------------------------------------------------------- #
def normalise_role(role: str | None) -> str | None:
    if not role:
        return None
    candidate = str(role).strip().lower()
    return candidate if candidate in VALID_ROLES else None


def is_valid_role(role: str | None) -> bool:
    return normalise_role(role) is not None


def static_permissions_for(role: str | None) -> list[str]:
    """The permissions a role has according to the code (no database involved)."""
    normalised = normalise_role(role)
    if normalised is None:
        return []
    return list(ROLE_PERMISSIONS[normalised])


def _role_overrides(role: str) -> dict[str, Any]:
    """Read the optional DB-backed overrides for ``role``.

    Never raises: authorisation must keep working even if the ``roles`` table is
    missing (e.g. an older database created before RBAC shipped).
    """
    from app.db.session import SessionLocal
    from app.models.database_models import Role

    db = SessionLocal()
    try:
        row = db.get(Role, role)
        if row is None or row.permissions is None:
            return {}
        permissions = row.permissions
        if not isinstance(permissions, dict):
            return {}
        return permissions
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("role overrides unavailable for %s: %s", role, type(exc).__name__)
        return {}
    finally:
        db.close()


def permissions_for(role: str | None) -> list[str]:
    """
    Effective permissions of ``role``.

    Starts from the code-defined set and then applies the ``roles.permissions``
    override, which may hold ``{"add": [...], "remove": [...], "allow": [...]}``.
    ``allow`` replaces the whole set (used when an admin wants to curate a role
    from scratch).  Protected permissions can never be removed.
    """
    normalised = normalise_role(role)
    if normalised is None:
        return []
    effective = set(ROLE_PERMISSIONS[normalised])

    override = _role_overrides(normalised)
    if override:
        allow = override.get("allow")
        if isinstance(allow, list):
            effective = {p for p in allow if p in PERMISSIONS}
        for permission in override.get("add") or []:
            if permission in PERMISSIONS:
                effective.add(permission)
        blocked = set(override.get("remove") or []) - set(PROTECTED_PERMISSIONS[normalised])
        effective -= {p for p in blocked if p in PERMISSIONS}

    effective |= set(PROTECTED_PERMISSIONS[normalised])
    return sorted(p for p in effective if p in PERMISSIONS)


def role_has(role: str | None, permission: str) -> bool:
    return permission in permissions_for(role)


def require_known_permission(permission: str) -> None:
    """Guard against typos in route declarations (development aid)."""
    if permission not in PERMISSIONS:
        raise RuntimeError(f"unknown permission: {permission!r}")


# --------------------------------------------------------------------------- #
# FastAPI dependencies
# --------------------------------------------------------------------------- #
def get_token_claims(request) -> dict[str, Any]:
    return getattr(request.state, "claims", {}) or {}


def permission_matrix() -> dict:
    """The full matrix, used by ``GET /api/auth/permissions`` and the admin UI."""
    return {
        "roles": [
            {
                "role": role,
                "description": ROLE_DESCRIPTIONS[role],
                "permissions": permissions_for(role),
                "protected": list(PROTECTED_PERMISSIONS[role]),
            }
            for role in VALID_ROLES
        ],
        "catalogue": [
            {
                "permission": key,
                "description": value,
                "group": group,
                "roles": [r for r in VALID_ROLES if role_has(r, key)],
            }
            for group, keys in PERMISSION_GROUPS.items()
            for key, value in PERMISSIONS.items()
            if key in keys
        ],
    }


def _forbidden(user: Any, permission: str) -> HTTPException:
    role = getattr(user, "role", None) or "unknown"
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            f"Your role '{role}' is not allowed to perform this action "
            f"(required permission: {permission})."
        ),
    )


def _request_path(request: Any, fallback: str) -> str:
    """
    The endpoint a denial happened on.

    ``request.state.path`` is never populated by the middleware chain, so read the
    path off the URL object itself; without this every denied entry recorded the
    permission name instead of the endpoint the operator actually hit, which makes
    the audit console unable to answer "who tried to reach /admin/users?".
    """
    if request is None:
        return fallback
    for attr in ("path",):
        value = getattr(request, attr, None)
        if isinstance(value, str) and value:
            return value
    url = getattr(request, "url", None)
    path = getattr(url, "path", None)
    return path if isinstance(path, str) and path else fallback


def audit_denial(user: Any, permission: str, request: Any, accepted: Iterable[str] = ()) -> None:
    """
    Record a refused access attempt.

    Uses its own short-lived session so the denial is persisted even though the
    request-scoped session is about to be rolled back by the raised
    ``HTTPException``.  Never raises: auditing must not mask the 403.
    """
    try:
        from app.db.session import SessionLocal
        from app.services import audit_service

        db = SessionLocal()
        try:
            audit_service.record(
                db,
                action="access.denied",
                user=user,
                request=request,
                category=audit_service.CAT_AUTH,
                resource=_request_path(request, permission),
                result=audit_service.RESULT_DENIED,
                detail={
                    "permission": permission,
                    "accepted_permissions": list(accepted) or [permission],
                    "role": getattr(user, "role", None),
                    "method": getattr(request, "method", None),
                    "status_code": 403,
                },
            )
            db.commit()
        finally:
            db.close()
    except Exception as exc:  # pragma: no cover - auditing is best-effort
        logger.warning("could not record the denied access attempt: %s", exc)


def require_role(*roles: str) -> Callable:
    """Dependency factory: any one of ``roles`` is enough."""
    wanted = tuple(r for r in roles if is_valid_role(r))
    unknown = set(roles) - set(wanted)
    if unknown:
        raise RuntimeError(f"unknown role(s) in require_role: {sorted(unknown)}")
    if not wanted:
        raise RuntimeError("require_role() needs at least one valid role")

    def dependency(request: Request, user=Depends(_current_user_dependency())):
        if normalise_role(getattr(user, "role", None)) not in wanted:
            audit_denial(user, f"role:{sorted(wanted)}", request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {', '.join(wanted)}.",
            )
        return user

    dependency.__name__ = f"require_role_{'_or_'.join(wanted)}"
    return dependency


def require_permission(permission: str | None = None, *, any_of: Iterable[str] | None = None) -> Callable:
    """
    Dependency factory enforcing ``permission`` (or any permission in ``any_of``).

    ``require_permission(P_ALERTS_VIEW)`` and
    ``require_permission(any_of=[P_USERS_MANAGE, P_ROLES_MANAGE])`` are both valid.
    A refusal raises ``403`` and is written to the audit log.
    """
    if permission is not None:
        require_known_permission(permission)
    alternatives = tuple(any_of or ())
    for alternative in alternatives:
        require_known_permission(alternative)
    if permission is None and not alternatives:
        raise RuntimeError("require_permission() needs a permission or any_of=[...]")
    accepted = ((permission,) if permission is not None else ()) + alternatives
    primary = permission or alternatives[0]

    def dependency(request: Request, user=Depends(_current_user_dependency())):
        granted = set(permissions_for(getattr(user, "role", None)))
        if granted.isdisjoint(accepted):
            logger.warning(
                "permission denied: user=%s role=%s needs one of %s",
                getattr(user, "id", "?"),
                getattr(user, "role", "?"),
                ", ".join(accepted),
            )
            audit_denial(user, primary, request, accepted)
            raise _forbidden(user, primary)
        return user

    dependency.__name__ = f"require_permission_{primary.replace('.', '_')}"
    return dependency


def _current_user_dependency() -> Callable:
    """
    Resolve ``get_current_user`` lazily to avoid an import cycle.

    Only ever called while a router module is being imported (i.e. when a route
    declares its guard), which is long after both modules finished loading.
    """
    from app.core.security import get_current_user

    return get_current_user


def _require_admin(user: Any) -> Any:
    if normalise_role(getattr(user, "role", None)) != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the 'admin' role.",
        )
    return user


def _require_analyst(user: Any) -> Any:
    if normalise_role(getattr(user, "role", None)) != ROLE_ANALYST:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the 'analyst' role.",
        )
    return user


def _require_analyst_or_admin(user: Any) -> Any:
    if normalise_role(getattr(user, "role", None)) not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an admin or analyst account.",
        )
    return user


# ``require_admin`` / ``require_analyst`` / ``require_analyst_or_admin`` are plain
# FastAPI dependencies rather than factories, so they are assembled in
# ``app.core.security`` (the module that owns ``get_current_user``) to keep the
# import direction one-way: security -> rbac.  ``rbac_admin``, ``rbac_analyst``
# and ``rbac_any`` below are the imported-with-``Depends`` wrappers used there.
