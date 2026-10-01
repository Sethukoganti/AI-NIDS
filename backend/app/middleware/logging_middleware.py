"""
Request logging middleware.

Records method, path, status, duration and identity for every API call.  Bodies
are never read or logged, and the redaction helper in ``core.logging`` scrubs
anything resembling a credential, so passwords and tokens cannot leak into the
log stream.
"""

from __future__ import annotations

import time
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.logging import get_logger

logger = get_logger("ainids.request")

# Paths excluded from the access log to keep it readable.
QUIET_PATHS = {"/favicon.ico", "/api/health", "/api/health/live"}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        request.state.request_id = request_id
        started = time.perf_counter()

        response = await call_next(request)

        duration_ms = (time.perf_counter() - started) * 1000
        path = request.url.path
        if path not in QUIET_PATHS:
            identity = getattr(request.state, "user_id", None) or "anonymous"
            client = request.client.host if request.client else "-"
            logger.info(
                "rid=%s %s %s -> %s in %.1fms user=%s ip=%s",
                request_id,
                request.method,
                path,
                response.status_code,
                duration_ms,
                identity,
                client,
            )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-Ms"] = f"{duration_ms:.1f}"
        return response
