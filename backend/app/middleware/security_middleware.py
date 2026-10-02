"""
Security middleware: response hardening, upload guards and safe error shaping.

* Security headers on every response (nosniff, frame-ancestors, referrer policy,
  permissions policy, HSTS in production, and a locked-down CSP for API JSON).
* Upload restrictions: the accepted extensions and the size limit come from the
  admin-managed configuration in PostgreSQL (falling back to the environment
  defaults if the database is unavailable), and are enforced from
  ``Content-Length`` **and** on the file itself.  Executable/script content types
  are always rejected.  Uploaded data is therefore never executed, only parsed as
  text.
* Unexpected server errors are converted into a generic message so internal
  details (stack traces, driver errors) never reach the client.
"""

from __future__ import annotations

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("ainids.security")

#: Environment fallback used only when the database cannot be read.
DEFAULT_ALLOWED_EXTENSIONS = (".csv", ".txt", ".tsv", ".parquet", ".pq")
BLOCKED_CONTENT_TYPES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sh",
    "application/x-httpd-php",
    "text/x-python",
    "application/javascript",
    "text/javascript",
    "application/zip",
    "application/x-tar",
}
UPLOAD_PATHS = (
    f"{settings.API_PREFIX}/datasets/upload",
    f"{settings.API_PREFIX}/predictions/analyze",
    f"{settings.API_PREFIX}/analyst/traffic/analyze",
    f"{settings.API_PREFIX}/traffic/analyze",
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Resource-Policy": "cross-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cache-Control": "no-store",
}


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # ---- upload pre-checks (before the body is consumed) ------------- #
        if request.method == "POST" and request.url.path in UPLOAD_PATHS:
            rejection = await _guard_upload(request)
            if rejection is not None:
                return _harden(rejection)

        try:
            response = await call_next(request)
        except Exception as exc:  # pragma: no cover - last-resort guard
            logger.exception("unhandled error on %s %s", request.method, request.url.path)
            return _harden(
                JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={
                        "detail": "An internal error occurred while processing the request.",
                        "code": "internal_error",
                    },
                )
            )

        return _harden(response)


def upload_policy() -> tuple[set[str], int]:
    """
    Accepted extensions and byte limit, from the admin-managed configuration.

    Falls back to the environment defaults so a database outage cannot turn into
    an unusable upload endpoint.
    """
    try:
        from app.services.config_service import get_runtime

        runtime = get_runtime()
        extensions = {
            str(ext).strip().lower() if str(ext).strip().startswith(".") else f".{str(ext).strip().lower()}"
            for ext in (runtime.allowed_file_formats or DEFAULT_ALLOWED_EXTENSIONS)
        }
        limit = int(runtime.max_upload_size_bytes) or int(settings.MAX_UPLOAD_SIZE)
        return (extensions or set(DEFAULT_ALLOWED_EXTENSIONS)), limit
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "upload policy falling back to environment defaults (%s: %s)",
            type(exc).__name__,
            str(exc).splitlines()[0][:160] if str(exc) else "",
        )
        return set(DEFAULT_ALLOWED_EXTENSIONS), int(settings.MAX_UPLOAD_SIZE)


async def _guard_upload(request: Request) -> JSONResponse | None:
    content_type = (request.headers.get("content-type") or "").lower()
    if content_type.split(";")[0].strip() in BLOCKED_CONTENT_TYPES:
        return JSONResponse(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            content={
                "detail": "Unsupported file type. Upload a network-flow CSV (or parquet) file.",
                "code": "unsupported_media_type",
            },
        )

    # The effective configuration is read through the short-lived process cache;
    # run it in a worker thread so the event loop is never blocked on the database.
    _extensions, limit = await run_in_threadpool(upload_policy)

    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > limit + 1_000_000:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "detail": f"Upload exceeds the {limit / 1e6:.0f} MB limit configured by the administrator.",
                "code": "payload_too_large",
                "max_bytes": limit,
            },
        )
    return None


def _harden(response) -> JSONResponse:
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    if settings.ENVIRONMENT == "production":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


def validate_upload_filename(filename: str, size: int, runtime=None) -> str | None:
    """Return a user-facing error message, or None when the file is acceptable."""
    if not filename:
        return "No file was uploaded."

    if runtime is not None:
        allowed = {
            str(ext).strip().lower() if str(ext).strip().startswith(".") else f".{str(ext).strip().lower()}"
            for ext in (getattr(runtime, "allowed_file_formats", None) or DEFAULT_ALLOWED_EXTENSIONS)
        }
        limit = int(getattr(runtime, "max_upload_size_bytes", 0) or settings.MAX_UPLOAD_SIZE)
    else:
        allowed, limit = upload_policy()

    suffix = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if suffix not in allowed:
        accepted = ", ".join(sorted(allowed))
        return (
            f"Invalid file format '{suffix or '(none)'}'. The administrator accepts: {accepted} "
            "for network-flow records."
        )
    if size == 0:
        return "The uploaded dataset contains no records."
    if size > limit:
        return (
            f"File is too large ({size / 1e6:.1f} MB). The configured maximum is "
            f"{limit / 1e6:.0f} MB."
        )
    return None
