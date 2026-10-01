"""
Rate-limiting middleware.

Sliding-window limiter that protects the expensive ML endpoints and the login
route.  Limits are configurable (``RATE_LIMIT_LOGIN``, ``RATE_LIMIT_PREDICT``,
``RATE_LIMIT_UPLOAD``, ``RATE_LIMIT_DEFAULT``) using the ``"<count>/<period>"``
notation, where period is ``second|minute|hour``.

The counter lives in-process, which is sufficient for a single uvicorn worker
and for the college demonstration; ``docs/ARCHITECTURE.md`` documents the Redis
backed variant needed for a multi-worker deployment.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("ainids.ratelimit")

PERIODS = {"second": 1, "minute": 60, "hour": 3600}


def parse_limit(spec: str) -> tuple[int, int]:
    """'30/minute' -> (30, 60). Falls back to (300, 60) on malformed input."""
    try:
        count, _, period = spec.partition("/")
        return int(count), PERIODS.get(period.strip().lower(), 60)
    except Exception:
        return 300, 60


ROUTE_LIMITS: list[tuple[str, str, str]] = [
    (f"{settings.API_PREFIX}/auth/login", "POST", settings.RATE_LIMIT_LOGIN),
    (f"{settings.API_PREFIX}/predictions/analyze", "POST", settings.RATE_LIMIT_PREDICT),
    (f"{settings.API_PREFIX}/predictions/simulate", "POST", settings.RATE_LIMIT_PREDICT),
    (f"{settings.API_PREFIX}/assistant/ask", "POST", settings.RATE_LIMIT_PREDICT),
    (f"{settings.API_PREFIX}/live/stream", "GET", settings.RATE_LIMIT_PREDICT),
    (f"{settings.API_PREFIX}/datasets/upload", "POST", settings.RATE_LIMIT_UPLOAD),
    (f"{settings.API_PREFIX}/datasets/sample", "POST", settings.RATE_LIMIT_UPLOAD),
]


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: int) -> tuple[bool, int, int]:
        """Return (allowed, remaining, retry_after_seconds)."""
        now = time.time()
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(window - (now - bucket[0])))
                return False, 0, retry_after
            bucket.append(now)
            return True, limit - len(bucket), 0

    def stats(self) -> dict:
        with self._lock:
            now = time.time()
            active = {k: len(v) for k, v in self._hits.items() if v and v[-1] > now - 3600}
        return {"tracked_keys": len(active), "keys": active}


limiter = SlidingWindowLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not settings.RATE_LIMIT_ENABLED or request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        spec = None
        for prefix, method, route_spec in ROUTE_LIMITS:
            if path == prefix and request.method == method:
                spec = route_spec
                break
        if spec is None:
            if not path.startswith(settings.API_PREFIX):
                return await call_next(request)
            spec = settings.RATE_LIMIT_DEFAULT

        limit, window = parse_limit(spec)
        identity = request.state.user_id if getattr(request.state, "user_id", None) else _client_ip(request)
        key = f"{identity}:{path}"

        allowed, remaining, retry_after = limiter.check(key, limit, window)
        if not allowed:
            logger.warning("rate limit hit: %s %s (identity=%s)", request.method, path, identity)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Too many requests. Please slow down and try again shortly.",
                    "code": "rate_limited",
                    "limit": f"{limit}/{window}s",
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
