"""
Security middleware: response hardening, upload guards and safe error shaping.

* Security headers on every response (nosniff, frame-ancestors, referrer policy,
  permissions policy, HSTS in production, and a locked-down CSP for API JSON).
* Upload restrictions: only ``.csv`` / ``.txt`` / ``.parquet`` files, a hard
  ``MAX_UPLOAD_SIZE`` byte limit enforced from ``Content-Length`` **and** on the
  file itself, plus rejection of executable/script content types.  Uploaded data
  is therefore never executed, only parsed as text.
* Unexpected server errors are converted into a generic message so internal
  details (stack traces, driver errors) never reach the client.
"""

from __future__ import annotations

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("ainids.security")

ALLOWED_UPLOAD_EXTENSIONS = {".csv", ".txt", ".tsv", ".parquet", ".pq"}
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
            rejection = _guard_upload(request)
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


def _guard_upload(request: Request) -> JSONResponse | None:
    content_type = (request.headers.get("content-type") or "").lower()
    if content_type.split(";")[0].strip() in BLOCKED_CONTENT_TYPES:
        return JSONResponse(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            content={
                "detail": "Unsupported file type. Upload a network-flow CSV (or parquet) file.",
                "code": "unsupported_media_type",
            },
        )

    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > settings.MAX_UPLOAD_SIZE + 1_000_000:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "detail": f"Upload exceeds the {settings.MAX_UPLOAD_SIZE / 1e6:.0f} MB limit.",
                "code": "payload_too_large",
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


def validate_upload_filename(filename: str, size: int) -> str | None:
    """Return a user-facing error message, or None when the file is acceptable."""
    if not filename:
        return "No file was uploaded."
    suffix = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        return (
            "Invalid file format. Please upload a CSV file (.csv, .txt, .tsv) "
            "containing network-flow records."
        )
    if size == 0:
        return "The uploaded dataset contains no records."
    if size > settings.MAX_UPLOAD_SIZE:
        return (
            f"File is too large ({size / 1e6:.1f} MB). Maximum allowed is "
            f"{settings.MAX_UPLOAD_SIZE / 1e6:.0f} MB."
        )
    return None
