"""
Authentication middleware.

Performs real JWT verification for every ``/api/*`` request before it reaches a
route handler, attaches the decoded identity to ``request.state`` and rejects
unauthenticated calls to protected endpoints.  Route-level dependencies
(``get_current_user`` / ``require_admin``) remain in place as defence in depth.

A small in-process token denylist implements logout for stateless JWTs: the
``jti`` of a logged-out token is refused until its natural expiry.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

import jwt
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("ainids.auth")

# Paths that never require a token (login + health + docs + the assets the UI
# needs before signing in).
PUBLIC_PATHS = {
    f"{settings.API_PREFIX}/health",
    f"{settings.API_PREFIX}/health/live",
    f"{settings.API_PREFIX}/auth/login",
    f"{settings.API_PREFIX}/auth/config",
    # Standalone packet-capture endpoints remain public; simulation routes are
    # protected by their traffic-analysis permission dependencies.
    f"{settings.API_PREFIX}/capture/status",
    f"{settings.API_PREFIX}/capture/interfaces",
    f"{settings.API_PREFIX}/capture/start",
    f"{settings.API_PREFIX}/capture/stop",
    f"{settings.API_PREFIX}/capture/stream",
    f"{settings.API_PREFIX}/capture/inject",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
}
PUBLIC_PREFIXES = (
    f"{settings.API_PREFIX}/health",
    f"{settings.API_PREFIX}/capture",
)


class TokenDenylist:
    """Thread-safe in-memory denylist for logged-out JWTs (per process)."""

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._entries[jti] = expires_at
            self._purge()

    def contains(self, jti: str) -> bool:
        with self._lock:
            self._purge()
            return jti in self._entries

    def _purge(self) -> None:
        now = time.time()
        for key in [k for k, exp in self._entries.items() if exp <= now]:
            self._entries.pop(key, None)

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


denylist = TokenDenylist()


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # SSE / EventSource clients cannot set headers; a query token is accepted
    # for the streaming endpoint only.
    if request.url.path.startswith(f"{settings.API_PREFIX}/live"):
        return request.query_params.get("token")
    return None


def verify_request_token(request: Request) -> tuple[dict | None, JSONResponse | None]:
    """Return (claims, error_response)."""
    token = _extract_token(request)
    if not token:
        return None, JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Not authenticated.", "code": "missing_token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.APP_NAME,
        )
    except jwt.ExpiredSignatureError:
        return None, JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Session expired. Please sign in again.", "code": "token_expired"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        return None, JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Could not validate credentials.", "code": "invalid_token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    if claims.get("jti") and denylist.contains(claims["jti"]):
        return None, JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "This session has been signed out.", "code": "token_revoked"},
        )
    return claims, None


class AuthContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        is_api = path.startswith(settings.API_PREFIX)

        request.state.user_id = None
        request.state.user_role = None
        request.state.claims = None

        if not is_api or path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        claims, error = verify_request_token(request)
        if error is not None:
            return error

        request.state.claims = claims
        request.state.user_id = claims.get("sub")
        request.state.user_role = claims.get("role")
        return await call_next(request)


def utc_expiry(claims: dict) -> float:
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        return float(exp)
    return datetime.now(timezone.utc).timestamp() + settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
