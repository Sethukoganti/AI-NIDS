"""
Password hashing, JWT issuing/verification and small crypto helpers.

* Passwords: bcrypt (cost factor from ``bcrypt.gensalt()``) - never stored or
  logged in plain text.
* Tokens: signed JWT (HS256 by default) with ``sub`` (user id), ``username``,
  ``role``, ``permissions``, ``exp`` and ``iat``.
* Roles/permissions live in :mod:`app.core.rbac`; this module re-exports the
  role constants so existing imports keep working.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core import rbac
from app.core.config import settings
from app.core.rbac import (  # noqa: F401  (re-exported for existing imports)
    ROLE_ADMIN,
    ROLE_ANALYST,
    VALID_ROLES,
    permissions_for,
)
from app.models.database_models import User

logger = logging.getLogger("ainids.security")

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

#: ``VALID_ROLES`` is a tuple in the RBAC module; keep the historical set-like
#: behaviour for the existing ``in`` checks across the codebase.
VALID_ROLE_SET = set(VALID_ROLES)


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(plain_password: str) -> str:
    if not plain_password:
        raise ValueError("password must not be empty")
    # bcrypt truncates at 72 bytes; encode explicitly and guard the length
    raw = plain_password.encode("utf-8")[:72]
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not plain_password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def create_access_token(
    subject: str,
    role: str,
    extra: dict[str, Any] | None = None,
    expires_minutes: int | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "username": str(extra.get("username") or extra.get("name") or subject) if extra else str(subject),
        "role": role,
        "permissions": permissions_for(role),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": settings.APP_NAME,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Return the token payload or raise ``HTTPException(401)``."""
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.APP_NAME,
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def token_expiry_seconds() -> int:
    return settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


# --------------------------------------------------------------------------- #
# FastAPI dependencies
# --------------------------------------------------------------------------- #
def _load_user(user_id: str):
    """Import lazily to avoid a circular import with the DB layer."""
    from app.db.session import SessionLocal
    from app.models.database_models import User

    db = SessionLocal()
    try:
        return db.get(User, user_id)
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    """
    Resolve the authenticated user from the bearer token, or raise 401.

    The user row is re-read on every request, so a role change or a disabled
    account takes effect immediately even for a token that was issued earlier.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(credentials.credentials)
    user = _load_user(payload.get("sub", ""))
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled.")

    # A password reset stamps access_reset_at; any token minted before that
    # moment is refused, so resetting a compromised password really ends the
    # stolen sessions instead of leaving them valid until they expire.
    if user.access_reset_at is not None:
        issued_at = payload.get("iat")
        if issued_at is not None:
            try:
                issued = datetime.fromtimestamp(float(issued_at), tz=timezone.utc)
            except (TypeError, ValueError, OSError):
                issued = None
            reset_at = user.access_reset_at
            if reset_at.tzinfo is None:
                reset_at = reset_at.replace(tzinfo=timezone.utc)
            if issued is not None and issued < reset_at:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="This session was invalidated by a password reset. Please sign in again.",
                )
    return user


# --------------------------------------------------------------------------- #
# Authorisation guards
# --------------------------------------------------------------------------- #
# The permission catalogue and the pure role resolution live in app.core.rbac;
# the FastAPI dependencies live here because this module owns ``get_current_user``.
# Keeping the import one-way (security -> rbac) avoids a cycle while route modules
# can keep importing ``require_admin`` from either module.
def _deny(request, user, requirement: str) -> None:
    rbac.audit_denial(user, requirement, request)


def require_admin(request: Request, user: User = Depends(get_current_user)) -> User:
    """
    Admin-only guard.

    Deliberately role-based rather than permission-based: administration of users,
    roles and security settings is the hard boundary the platform guarantees, so it
    must hold even if a ``roles`` permission override tried to widen the Admin set.
    """
    try:
        return rbac._require_admin(user)
    except HTTPException:
        _deny(request, user, "role:admin")
        raise


def require_analyst(request: Request, user: User = Depends(get_current_user)) -> User:
    """Analyst-only guard, for endpoints an admin must not reach either."""
    try:
        return rbac._require_analyst(user)
    except HTTPException:
        _deny(request, user, "role:analyst")
        raise


def require_analyst_or_admin(request: Request, user: User = Depends(get_current_user)) -> User:
    """Both platform roles hold operational permissions."""
    try:
        return rbac._require_analyst_or_admin(user)
    except HTTPException:
        _deny(request, user, f"role:{'|'.join(rbac.VALID_ROLES)}")
        raise
