"""
Administration API (``/api/admin``).

Everything in this router is Admin-only and declares an explicit permission, so a
non-admin token is refused with ``403`` before the handler body runs.  The four
logical areas are:

* ``/settings``  - every dynamic setting, validated, revisioned and audited.
* ``/network``   - network configuration plus the operational status machine.
* ``/users``     - accounts and roles.
* ``/audit-logs``, ``/system/health``, ``/notifications`` - oversight.

The Analyst console has no route into any of these; the equivalent monitoring
endpoints live in :mod:`app.api.analyst`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import network_modes, rbac
from app.core.logging import get_logger
from app.core.rbac import (
    P_ALERTS_CONFIGURE,
    P_AUDIT_VIEW,
    P_DATASETS_DELETE,
    P_DETECTION_CONFIGURE,
    P_MODEL_CONFIGURE,
    P_MODEL_DEPLOY,
    P_NETWORK_CONFIGURE,
    P_NETWORK_STATUS_MANAGE,
    P_NOTIFICATIONS_VIEW,
    P_ROLES_MANAGE,
    P_SETTINGS_API,
    P_SETTINGS_RETENTION,
    P_SETTINGS_SECURITY,
    P_SETTINGS_SYSTEM,
    P_SYSTEM_HEALTH,
    P_USERS_MANAGE,
    ROLE_ADMIN,
    require_permission,
)
from app.core.security import get_current_user, hash_password, require_admin  # noqa: F401
from app.db.session import get_db
from app.models.database_models import Role, User
from app.models.schemas import (
    AuditLogPage,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    ModelDeployRequest,
    NetworkStatusChangeRequest,
    NotificationPage,
    RoleUpdateRequest,
    UserCreateRequest,
    UserUpdateRequest,
)
from app.services import (
    audit_service,
    config_service,
    dataset_service,
    investigation_service,
    network_status_service,
    notification_service,
    prediction_service,
)

router = APIRouter(prefix="/admin", tags=["admin"])
logger = get_logger("ainids.api.admin")

#: Which permission guards which configuration scope, so the settings UI and the
#: API agree on who may change what.
SCOPE_PERMISSIONS: dict[str, str] = {
    "network": P_NETWORK_CONFIGURE,
    "detection": P_DETECTION_CONFIGURE,
    "alerts": P_ALERTS_CONFIGURE,
    "model": P_MODEL_CONFIGURE,
    "system": P_SETTINGS_SYSTEM,
    "security": P_SETTINGS_SECURITY,
    "data": P_SETTINGS_RETENTION,
    "api": P_SETTINGS_API,
}

#: The eleven sections the admin console renders, in order.  Internal scopes are
#: mapped onto them so the UI never has to know about storage layout.
SECTION_ORDER = (
    "Network",
    "Detection",
    "Alerts",
    "Model",
    "Dataset",
    "Notifications",
    "Users",
    "Security",
    "Data Retention",
    "System",
    "Audit Logs",
)

#: Internal section -> console section.  Sections not listed here are folded into
#: the closest admin concept.
SECTION_ALIASES = {
    "API": "System",
    "Automatic status": "Network",
    "Severity thresholds": "Alerts",
    "Escalation": "Alerts",
    "Escalation policy": "Alerts",
    "Dashboard": "System",
    "Logging": "System",
    "Audit": "Audit Logs",
    "Audit log": "Audit Logs",
}


def _scope_dependency(scope: str):
    """Permission guard for one configuration scope."""
    permission = SCOPE_PERMISSIONS.get(scope, P_SETTINGS_SYSTEM)
    return require_permission(permission)


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
@router.get("/settings", summary="All settings, grouped into the admin sections")
def read_settings(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    described = config_service.describe(db)
    return {
        **described,
        "section_order": list(SECTION_ORDER),
        "section_aliases": dict(SECTION_ALIASES),
        "scope_permissions": dict(SCOPE_PERMISSIONS),
        "effective_configuration": config_service.runtime_snapshot(db).to_dict(),
    }


@router.get("/settings/{scope}", summary="One configuration scope")
def read_scope(
    scope: str,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _read_scope_body(db, scope)


@router.put(
    "/settings/{scope}",
    response_model=ConfigUpdateResponse,
    summary="Update one configuration scope (validated, revisioned, audited)",
)
def update_scope(
    scope: str,
    payload: ConfigUpdateRequest,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _update_scope_body(db, scope, payload, user=user, request=request)


def _read_scope_body(db: Session, scope: str) -> dict:
    if scope not in config_service.known_scopes():
        raise HTTPException(status_code=404, detail=f"Unknown configuration scope '{scope}'.")
    return config_service.describe(db, scope)


def _update_scope_body(
    db: Session,
    scope: str,
    payload: ConfigUpdateRequest,
    *,
    user: User,
    request: Request,
) -> dict:
    if scope not in config_service.known_scopes():
        raise HTTPException(status_code=404, detail=f"Unknown configuration scope '{scope}'.")

    # The scope guard runs after the handler-level role check, so a request that
    # is somehow both authenticated and authorised for the role still has to
    # hold the specific configuration permission.
    rbac.require_permission(SCOPE_PERMISSIONS.get(scope, P_SETTINGS_SYSTEM))(
        request=request, user=user
    )

    # The eleven console sections do not map one-to-one onto the five storage
    # scopes, so a single write can touch a section guarded by a *different*
    # permission (Security, Data Retention and API all live in the `system`
    # scope). Requiring every applicable permission keeps a revoked
    # settings.security from being bypassed by writing through `system`.
    for permission in config_service.required_permissions(scope, payload.values.keys()):
        rbac.require_permission(permission)(request=request, user=user)

    if scope == "model" and "active_version" in payload.values:
        _guard_active_version(db, str(payload.values["active_version"]))

    try:
        result = config_service.update(
            db,
            scope,
            payload.values,
            user=user,
            request=request,
            note=payload.note,
            confirm=payload.confirm_dangerous,
        )
    except config_service.ConfigValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "The configuration was rejected and nothing was changed.",
                "errors": exc.errors,
                "requires_confirmation": "__confirm__" in exc.errors,
            },
        ) from exc

    runtime = config_service.runtime_snapshot(db)
    return {
        "changed": sorted(result.get("changed", {})),
        "revision_ids": _latest_revision_ids(db, scope, sorted(result.get("changed", {}))),
        "values": result.get("values", {}),
        "effective_configuration": runtime.to_dict(),
        "warnings": _warnings_for(scope, result),
    }


# --------------------------------------------------------------------------- #
# Per-domain configuration aliases
#
# The console addresses each settings page by its own domain path
# (``/admin/network/config``) rather than by the storage scope name, so the
# permission guard differs per route instead of falling back to "any admin".
# --------------------------------------------------------------------------- #
_CONFIG_ALIASES: tuple[tuple[str, str, str], ...] = (
    # (route prefix, config scope, permission)
    ("network", "network", P_NETWORK_CONFIGURE),
    ("detection", "detection", P_DETECTION_CONFIGURE),
    ("alerts", "alerts", P_ALERTS_CONFIGURE),
    ("model", "model", P_MODEL_CONFIGURE),
)


def _register_config_aliases(api: APIRouter) -> None:
    for prefix, scope, permission in _CONFIG_ALIASES:
        guard = require_permission(permission)

        def _make_read(s: str):
            def _read(
                request: Request,
                user: User = Depends(guard),
                db: Session = Depends(get_db),
            ):
                return _read_scope_body(db, s)

            return _read

        def _make_update(s: str):
            def _update(
                payload: ConfigUpdateRequest,
                request: Request,
                user: User = Depends(guard),
                db: Session = Depends(get_db),
            ):
                return _update_scope_body(db, s, payload, user=user, request=request)

            return _update

        api.get(
            f"/{prefix}/config",
            summary=f"Read the {prefix} configuration",
        )(_make_read(scope))
        api.put(
            f"/{prefix}/config",
            response_model=ConfigUpdateResponse,
            summary=f"Update the {prefix} configuration (validated, revisioned, audited)",
        )(_make_update(scope))


_register_config_aliases(router)


def _latest_revision_ids(db: Session, scope: str, keys: list[str]) -> list[str]:
    from app.models.database_models import ConfigurationRevision
    from sqlalchemy import select

    if not keys:
        return []
    rows = db.scalars(
        select(ConfigurationRevision.id)
        .where(ConfigurationRevision.scope == scope, ConfigurationRevision.key.in_(keys))
        .order_by(ConfigurationRevision.changed_at.desc())
        .limit(len(keys))
    ).all()
    return list(rows)


def _warnings_for(scope: str, result: dict) -> list[str]:
    """Plain-language consequences of the change, so the admin is not surprised."""
    changed = set(result.get("changed") or {})
    warnings: list[str] = []
    if scope == "model" and "enabled" in changed and not (result["changed"]["enabled"]["new"]):
        warnings.append(
            "The detection model is now disabled: analysts cannot analyse traffic until it is "
            "re-enabled."
        )
    if scope == "alerts" and "alerts_enabled" in changed and not (
        result["changed"]["alerts_enabled"]["new"]
    ):
        warnings.append("New analyses will no longer raise alerts. Existing alerts are kept.")
    if scope == "detection" and "highlight_suspicious" in changed:
        warnings.append(
            "Suspicious-flow highlighting is a UI aid; it does not change model verdicts."
        )
    if scope == "network" and "auto_status_enabled" in changed:
        warnings.append(
            "Automatic status evaluation compares recent predictions and alerts against the "
            "thresholds in this scope."
        )
    return warnings


# --------------------------------------------------------------------------- #
# Network status
# --------------------------------------------------------------------------- #
@router.get("/network/status", summary="Current network status, indicators and history")
def network_status(
    request: Request,
    user: User = Depends(require_permission(P_NETWORK_STATUS_MANAGE)),
    db: Session = Depends(get_db),
):
    return network_status_service.status_overview(db)


@router.post("/network/status", summary="Change the operational status (manual)")
def change_network_status(
    payload: NetworkStatusChangeRequest,
    request: Request,
    user: User = Depends(require_permission(P_NETWORK_STATUS_MANAGE)),
    db: Session = Depends(get_db),
):
    if not network_modes.is_valid_status(payload.status):
        raise HTTPException(
            status_code=422,
            detail=f"Unknown status '{payload.status}'. Expected one of: "
            + ", ".join(network_modes.VALID_STATUSES),
        )
    if not payload.confirm:
        raise HTTPException(
            status_code=428,
            detail={
                "message": "Changing the operational status needs explicit confirmation.",
                "status": payload.status,
                "status_label": network_modes.definition(payload.status)["label"],
                "requires": "confirm",
            },
        )
    try:
        result = network_status_service.set_status_manual(
            db, payload.status, user=user, request=request, reason=payload.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result


@router.post("/network/status/evaluate", summary="Evaluate the status from stored indicators")
def evaluate_network_status(
    request: Request,
    apply: bool = Query(False, description="Apply the recommendation instead of only reporting it"),
    user: User = Depends(require_permission(P_NETWORK_STATUS_MANAGE)),
    db: Session = Depends(get_db),
):
    if apply:
        evaluation = network_status_service.evaluate(db, apply=True, user=user, request=request)
    else:
        evaluation = network_status_service.evaluate(db, apply=False)
    return evaluation.to_dict()


@router.get("/network/status/history", summary="Status change history")
def network_status_history(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(require_permission(P_NETWORK_STATUS_MANAGE)),
    db: Session = Depends(get_db),
):
    return {"items": network_status_service.history(db, limit=limit)}


# --------------------------------------------------------------------------- #
# Users and roles
# --------------------------------------------------------------------------- #
@router.get("/users", summary="List accounts")
def list_users(
    request: Request,
    search: str | None = None,
    role: str | None = None,
    user: User = Depends(require_permission(P_USERS_MANAGE)),
    db: Session = Depends(get_db),
):
    return _list_users(db, search=search, role=role)


def _list_users(db: Session, search: str | None = None, role: str | None = None) -> dict:
    from sqlalchemy import func, or_, select

    from app.models.database_models import AuditLog

    stmt = select(User)
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(or_(func.lower(User.name).like(like), func.lower(User.email).like(like)))
    if role and role != "all":
        stmt = stmt.where(User.role == role)
    rows = db.scalars(stmt.order_by(User.created_at.desc())).all()

    activity = {
        str(row[0]): int(row[1] or 0)
        for row in db.execute(
            select(AuditLog.user_id, func.count(AuditLog.id)).group_by(AuditLog.user_id)
        ).all()
    }
    return {
        "items": [
            {
                **row.to_public_dict(),
                "disabled_by": row.disabled_by,
                "permissions": rbac.permissions_for(row.role),
                "audit_events": activity.get(row.id, 0),
            }
            for row in rows
        ],
        "total": len(rows),
        "roles": list(rbac.VALID_ROLES),
    }


@router.post("/users", status_code=201, summary="Create a user account (admin)")
def create_user(
    payload: UserCreateRequest,
    request: Request,
    actor: User = Depends(require_permission(P_USERS_MANAGE)),
    db: Session = Depends(get_db),
):
    if payload.role not in rbac.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'analyst'.")
    exists = db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    if exists:
        raise HTTPException(status_code=409, detail="A user with that email already exists.")

    new_user = User(
        name=payload.name,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(new_user)
    db.flush()
    audit_service.record(
        db,
        action="user.created",
        user=actor,
        request=request,
        category=audit_service.CAT_USER,
        resource=f"user:{new_user.id}",
        new_value={"name": new_user.name, "email": new_user.email, "role": new_user.role},
        detail={"created_by": actor.id},
    )
    db.commit()
    db.refresh(new_user)
    return {
        **new_user.to_public_dict(),
        "permissions": rbac.permissions_for(new_user.role),
    }


@router.patch("/users/{user_id}", summary="Update an account (role, state, password)")
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    request: Request,
    actor: User = Depends(require_permission(P_USERS_MANAGE)),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if target.id == actor.id and payload.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot disable your own account.")
    if target.id == actor.id and payload.role is not None and payload.role != target.role:
        raise HTTPException(status_code=400, detail="You cannot change your own role.")

    if payload.role is not None:
        rbac.require_permission(P_ROLES_MANAGE)(request=request, user=actor)

    remaining_admins = 0
    if payload.role is not None and payload.role != ROLE_ADMIN and target.role == ROLE_ADMIN:
        remaining_admins = int(
            db.scalar(
                select(func.count(User.id)).where(
                    User.role == ROLE_ADMIN, User.is_active.is_(True), User.id != target.id
                )
            )
            or 0
        )
        if remaining_admins == 0:
            raise HTTPException(
                status_code=400,
                detail="The platform must keep at least one active admin account.",
            )

    changes: dict[str, dict] = {}
    if payload.name is not None and payload.name != target.name:
        changes["name"] = {"previous": target.name, "new": payload.name}
        target.name = payload.name
    if payload.role is not None and payload.role != target.role:
        changes["role"] = {"previous": target.role, "new": payload.role}
        target.role = payload.role
    if payload.is_active is not None and payload.is_active != target.is_active:
        changes["is_active"] = {"previous": target.is_active, "new": payload.is_active}
        target.is_active = payload.is_active
        if not payload.is_active:
            target.last_login_at = None
    if payload.password:
        target.hashed_password = hash_password(payload.password)
        changes["password"] = {"previous": None, "new": "reset"}
        # Invalidate every session that predates the reset: get_current_user
        # refuses tokens issued before access_reset_at.
        target.access_reset_at = datetime.now(timezone.utc)

    if not changes:
        return {"user": {**target.to_public_dict(), "permissions": rbac.permissions_for(target.role)}}

    db.flush()
    audit_service.record_change(
        db,
        scope="users",
        changes=changes,
        user=actor,
        request=request,
        resource=f"user:{target.id}",
        note="role/permission change" if "role" in changes else "account update",
    )
    db.commit()
    return {"user": {**target.to_public_dict(), "permissions": rbac.permissions_for(target.role)}}


@router.delete("/users/{user_id}", summary="Delete an account")
def delete_user(
    user_id: str,
    request: Request,
    actor: User = Depends(require_permission(P_USERS_MANAGE)),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    admins_left = int(
        db.scalar(
            select(func.count(User.id)).where(
                User.role == ROLE_ADMIN, User.is_active.is_(True), User.id != target.id
            )
        )
        or 0
    )
    if target.role == ROLE_ADMIN and admins_left == 0:
        raise HTTPException(
            status_code=400, detail="The platform must keep at least one active admin account."
        )

    email = target.email
    target.is_active = False
    target.token_version = int(target.token_version or 1) + 1
    audit_service.record(
        db,
        action="user.deactivated",
        user=actor,
        request=request,
        category=audit_service.CAT_USER,
        resource=f"user:{target.id}",
        previous_value={"active": True},
        new_value={"active": False},
        detail={"email": email, "reason": "account deleted"},
    )
    db.commit()
    return {"deleted": target.id, "deactivated": True}


@router.get("/roles", summary="Roles and their effective permissions")
def list_roles(
    request: Request,
    user: User = Depends(require_permission(P_ROLES_MANAGE)),
    db: Session = Depends(get_db),
):
    from sqlalchemy import func

    counts = {
        str(row[0]): int(row[1] or 0)
        for row in db.execute(select(User.role, func.count(User.id)).group_by(User.role)).all()
    }
    return {
        "roles": [
            {
                "name": role,
                "description": rbac.ROLE_DESCRIPTIONS[role],
                "permissions": rbac.permissions_for(role),
                "protected": list(rbac.PROTECTED_PERMISSIONS[role]),
                "is_system": True,
                "user_count": counts.get(role, 0),
                "override": (db.get(Role, role).permissions if db.get(Role, role) else None),
            }
            for role in rbac.VALID_ROLES
        ],
        "catalogue": [
            {"permission": key, "description": value, "group": group}
            for group, keys in rbac.PERMISSION_GROUPS.items()
            for key, value in rbac.PERMISSIONS.items()
            if key in keys
        ],
    }


@router.patch("/roles/{role_name}", summary="Adjust a role's permission override")
def update_role(
    role_name: str,
    payload: RoleUpdateRequest,
    request: Request,
    actor: User = Depends(require_permission(P_ROLES_MANAGE)),
    db: Session = Depends(get_db),
):
    if role_name not in rbac.VALID_ROLES:
        raise HTTPException(status_code=404, detail=f"Unknown role '{role_name}'.")

    row = db.get(Role, role_name)
    if row is None:
        row = Role(name=role_name, description=rbac.ROLE_DESCRIPTIONS[role_name], is_system=True)
        db.add(row)
        db.flush()

    before = dict(row.permissions or {})
    override: dict = {
        "add": sorted(set(payload.add) & set(rbac.PERMISSIONS)),
        "remove": sorted(set(payload.remove) & set(rbac.PERMISSIONS)),
    }
    if payload.allow is not None:
        override["allow"] = sorted(set(payload.allow) & set(rbac.PERMISSIONS))
    if payload.description is not None:
        row.description = payload.description

    blocked = set(override.get("remove") or []) & set(rbac.PROTECTED_PERMISSIONS[role_name])
    if blocked:
        raise HTTPException(
            status_code=400,
            detail=f"These permissions cannot be removed from '{role_name}': "
            + ", ".join(sorted(blocked)),
        )
    if "allow" in override:
        missing = set(rbac.PROTECTED_PERMISSIONS[role_name]) - set(override["allow"])
        if missing:
            raise HTTPException(
                status_code=400,
                detail="A replacement permission list must keep: " + ", ".join(sorted(missing)),
            )

    row.permissions = override
    row.updated_by = actor.id
    db.flush()
    audit_service.record_change(
        db,
        scope="roles",
        changes={"permissions": {"previous": before, "new": override}},
        user=actor,
        request=request,
        resource=f"role:{role_name}",
    )
    db.commit()
    return {
        "role": role_name,
        "override": override,
        "permissions": rbac.permissions_for(role_name),
    }


# --------------------------------------------------------------------------- #
# Oversight
# --------------------------------------------------------------------------- #
@router.get("/audit-logs", response_model=AuditLogPage, summary="Audit log")
def audit_logs(
    request: Request,
    user_id: str | None = None,
    category: str | None = None,
    action: str | None = None,
    result: str | None = None,
    resource: str | None = None,
    search: str | None = None,
    since_days: int = Query(7, ge=1, le=365),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: User = Depends(require_permission(P_AUDIT_VIEW)),
    db: Session = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=since_days)
    return audit_service.list_entries(
        db,
        user_id=user_id,
        category=category if category and category != "all" else None,
        action=action or None,
        result=result if result and result != "all" else None,
        resource=resource or None,
        search=search or None,
        since=since,
        page=page,
        page_size=page_size,
    )


@router.get("/notifications", response_model=NotificationPage, summary="Notification feed")
def notifications(
    request: Request,
    is_read: bool | None = None,
    category: str | None = None,
    severity: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    # The analyst console has its own feed at /api/analyst/notifications, so this
    # admin-namespaced view stays admin-only even though both roles hold
    # notifications.view - the split keeps /api/admin unreachable for analysts.
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return notification_service.list_notifications(
        db,
        user=user,
        is_read=is_read,
        category=category,
        severity=severity,
        page=page,
        page_size=page_size,
    )


@router.get("/system/health", summary="Detailed system health for administrators")
def system_health(
    request: Request,
    user: User = Depends(require_permission(P_SYSTEM_HEALTH)),
    db: Session = Depends(get_db),
):
    from app.api.health import _runtime_payload, _system_payload

    payload = _system_payload(db)
    payload.update(
        {
            **_runtime_payload(db),
            "network_status": network_status_service.current_dict(db),
            "audit_summary": audit_service.summary(db),
            "investigation_stats": investigation_service.investigation_stats(db),
            "runtime_workers": prediction_service.pool_workers(),
        }
    )
    return payload


@router.get("/datasets", summary="All datasets (admin view, includes the delete action)")
def admin_datasets(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str | None = None,
    user: User = Depends(require_permission(P_DATASETS_DELETE)),
    db: Session = Depends(get_db),
):
    payload = dataset_service.list_datasets(db, page=page, page_size=page_size, search=search)
    payload["permissions"] = {"can_delete": True}
    return payload


@router.post("/model/deploy", summary="Activate a registered model version")
def deploy_model(
    payload: ModelDeployRequest,
    request: Request,
    actor: User = Depends(require_permission(P_MODEL_DEPLOY)),
    db: Session = Depends(get_db),
):
    return _deploy_model(db, payload, actor=actor, request=request)


def _deploy_model(db: Session, payload: ModelDeployRequest, *, actor: User, request: Request) -> dict:
    from app.models.database_models import ModelVersion

    version = db.scalar(select(ModelVersion).where(ModelVersion.version == payload.version))
    if version is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Model version '{payload.version}' is not registered. Train and approve it "
                "before activating it."
            ),
        )
    if version.status != "approved":
        raise HTTPException(
            status_code=409,
            detail=f"Model version '{payload.version}' is '{version.status}', not 'approved'.",
        )
    if not payload.confirm:
        raise HTTPException(
            status_code=428,
            detail={
                "message": "Activating a model version replaces the detector used by every "
                "subsequent analysis. Confirm to continue.",
                "version": payload.version,
                "metrics": version.metrics,
                "requires": "confirm",
            },
        )

    from app.services import ml_service

    result = ml_service.activate_version(db, version, user=actor, request=request)
    config_service.update(
        db,
        "model",
        {"active_version": payload.version},
        user=actor,
        request=request,
        note=payload.note or f"Activated model version {payload.version}",
        confirm=True,
    )
    return result


def _guard_active_version(db: Session, version: str) -> None:
    """
    Refuse an ``active_version`` that is not a registered, approved artifact.

    The setting may only ever name a version an admin actually trained and
    approved; typing an arbitrary string must not be able to point the platform
    at a model that does not exist.
    """
    from app.models.database_models import ModelVersion

    known = db.scalar(select(ModelVersion).where(ModelVersion.version == version))
    if known is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"'{version}' is not a registered model version. Use "
                "POST /api/admin/model/deploy to activate an approved version."
            ),
        )
    if known.status != "approved":
        raise HTTPException(
            status_code=409,
            detail=f"Model version '{version}' is '{known.status}', not 'approved'.",
        )