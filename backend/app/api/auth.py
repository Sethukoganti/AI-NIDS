"""Authentication API - real JWT login, session info and user administration."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core import rbac
from app.core.security import (
    ROLE_ADMIN,
    VALID_ROLES,
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    token_expiry_seconds,
    verify_password,
)
from app.db.session import get_db
from app.middleware.auth_middleware import denylist, utc_expiry
from app.middleware.rate_limit_middleware import _client_ip
from app.models.database_models import AuditLog, User
from app.models.schemas import LoginRequest, TokenResponse, UserCreateRequest

router = APIRouter(prefix="/auth", tags=["auth"])
logger = get_logger("ainids.api.auth")


def _audit(db: Session, action: str, user: User | None, request: Request, detail: dict | None = None) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            action=action,
            resource="auth",
            detail=detail or {},
            ip_address=_client_ip(request),
        )
    )
    db.commit()


@router.post("/login", response_model=TokenResponse, summary="Sign in and receive a JWT")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))

    # constant-ish response regardless of which factor failed
    if user is None or not verify_password(payload.password, user.password_hash):
        _audit(db, "login_failed", user, request, {"email": payload.email})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled.")

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token(
        subject=user.id,
        role=user.role,
        extra={"email": user.email, "name": user.name, "jti": uuid.uuid4().hex},
    )
    _audit(db, "login_success", user, request, {"role": user.role})
    logger.info("login ok: %s (%s)", user.email, user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=token_expiry_seconds(),
        user=user.to_public_dict(),
    )


@router.post("/logout", summary="Invalidate the current session token")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    claims = getattr(request.state, "claims", {}) or {}
    jti = claims.get("jti")
    if jti:
        denylist.add(jti, utc_expiry(claims))
    _audit(db, "logout", user, request, {})
    return {
        "signed_out": True,
        "note": "The token is revoked server-side until its natural expiry; the client also "
                "clears it from storage.",
    }


@router.get("/me", summary="Current authenticated user")
def me(user: User = Depends(get_current_user)):
    # The effective permission list is resolved from the database on every call,
    # not read from the token: a role-permission override must reach the client
    # without waiting for the token to expire. It is a hint for rendering only -
    # every route re-checks server-side.
    return {
        **user.to_public_dict(),
        "permissions": sorted(rbac.permissions_for(user.role)),
    }


@router.get("/config", summary="Public auth configuration for the login screen")
def auth_config():
    return {
        "app_name": settings.APP_NAME,
        "demo_accounts_enabled": settings.SEED_DEMO_DATA,
        "demo_accounts": (
            [
                {"role": "analyst", "email": settings.DEMO_USER_EMAIL},
                {"role": "admin", "email": settings.DEMO_ADMIN_EMAIL},
            ]
            if settings.SEED_DEMO_DATA
            else []
        ),
        "password_min_length": settings.PASSWORD_MIN_LENGTH,
    }


@router.post("/users", status_code=201, summary="Create a user (admin only)")
def create_user(
    payload: UserCreateRequest,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if payload.role not in VALID_ROLES:
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
    db.commit()
    db.refresh(new_user)
    return new_user.to_public_dict()


@router.get("/users", summary="List users (admin only)")
def list_users(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.scalars(select(User).order_by(User.created_at.asc())).all()
    return {"items": [u.to_public_dict() for u in rows], "total": len(rows)}


@router.get("/permissions", tags=["auth"], summary="Permission matrix")
def get_permissions():
    return rbac.permission_matrix()
