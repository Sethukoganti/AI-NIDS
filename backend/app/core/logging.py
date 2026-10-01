"""Central logging configuration (never logs secrets)."""

from __future__ import annotations

import logging
import sys

from app.core.config import settings

_CONFIGURED = False

# Anything matching these keys is redacted before it reaches a log sink.
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "password_hash",
    "token",
    "access_token",
    "authorization",
    "api_key",
    "ai_api_key",
    "jwt_secret",
    "secret",
}


def redact(payload: dict) -> dict:
    """Return a copy of *payload* with sensitive values replaced by '***'."""
    safe: dict = {}
    for key, value in (payload or {}).items():
        if str(key).lower() in SENSITIVE_KEYS:
            safe[key] = "***"
        elif isinstance(value, dict):
            safe[key] = redact(value)
        else:
            safe[key] = value
    return safe


def setup_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # noisy third-party loggers
    for noisy in ("uvicorn.access", "watchfiles", "python_multipart"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
