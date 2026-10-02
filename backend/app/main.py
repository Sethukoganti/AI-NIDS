"""
AI-NIDS backend - FastAPI application entrypoint.

Wiring order (outermost first) is chosen so that security headers are attached
to every response, requests are logged, rate limits are enforced, and JWT
verification happens before any route handler runs:

    CORS -> Security headers -> Request logging -> Rate limit -> JWT auth -> routes
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.api import (
    admin,
    alerts,
    analyst,
    assistant,
    auth,
    dashboard,
    datasets,
    health,
    live,
    model as model_api,
    predictions,
)
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.db.session import init_db
from app.middleware.auth_middleware import AuthContextMiddleware
from app.middleware.logging_middleware import RequestLoggingMiddleware
from app.middleware.rate_limit_middleware import RateLimitMiddleware
from app.middleware.security_middleware import SecurityMiddleware
from app.services.ml_service import ModelUnavailableError, model_service
from app.services.preprocessing_service import DatasetError

setup_logging()
logger = get_logger("ainids.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 72)
    logger.info("%s v%s starting (env=%s)", settings.APP_NAME, settings.APP_VERSION, settings.ENVIRONMENT)
    logger.info("database : %s", settings.DATABASE_URL.split("@")[-1])
    init_db()
    logger.info("database schema ready")

    model_service.load()
    if model_service.is_loaded:
        logger.info(
            "ML model ready: %s | %s trees | %s classes | test accuracy %s",
            model_service.metadata.get("algorithm"),
            model_service.metadata.get("n_estimators"),
            len(model_service.classes_),
            model_service.evaluation.get("accuracy"),
        )
    else:
        logger.error("ML model NOT loaded - prediction endpoints will return 503 (%s)", model_service.load_error)

    if settings.SEED_DEMO_DATA:
        from app.db.seed import seed_demo_data

        try:
            seed_demo_data()
        except Exception as exc:  # pragma: no cover - never block startup on seeding
            logger.warning("demo seeding skipped: %s", exc)

    logger.info("AI explanation layer: %s", "external LLM" if settings.ai_enabled else "local engine")
    logger.info("ready - docs at http://localhost:8000/docs")
    logger.info("=" * 72)
    yield
    logger.info("%s shutting down", settings.APP_NAME)


app = FastAPI(
    title=f"{settings.APP_NAME} API",
    version=settings.APP_VERSION,
    description=(
        "**AI-Powered Network Intrusion Detection System**\n\n"
        "Random Forest (100 trees) trained on CICIDS2017 network-flow features, with a documented "
        "risk engine, alerting, TreeSHAP explainability and an evidence-grounded AI assistant.\n\n"
        "Sign in with `POST /api/auth/login` and click **Authorize** to use the protected endpoints."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "auth", "description": "JWT authentication, permissions and user administration"},
        {"name": "admin", "description": "Admin-only: settings, network status, users, roles, audit log"},
        {"name": "analyst", "description": "Analyst workflow: analysis, alerts, predictions, investigations"},
        {"name": "datasets", "description": "Upload, profile and explore traffic datasets"},
        {"name": "predictions", "description": "Random Forest inference, jobs and record inspection"},
        {"name": "alerts", "description": "Security alerts and lifecycle management"},
        {"name": "dashboard", "description": "Aggregated statistics for the SOC dashboard"},
        {"name": "model", "description": "Model card, feature importance, evaluation, architecture"},
        {"name": "assistant", "description": "AI Security Assistant (evidence-grounded)"},
        {"name": "live", "description": "Live Traffic Simulation (SSE)"},
        {"name": "health", "description": "System health and status"},
    ],
)

# --------------------------------------------------------------------------- #
# Middleware (added inner -> outer)
# --------------------------------------------------------------------------- #
app.add_middleware(AuthContextMiddleware)          # verifies JWT for /api/*
app.add_middleware(RateLimitMiddleware)            # sliding-window limits
app.add_middleware(RequestLoggingMiddleware)       # access log + timings
app.add_middleware(SecurityMiddleware)             # headers + upload guards
app.add_middleware(                                # CORS (outermost)
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_origin_regex=settings.CORS_ALLOW_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Process-Time-Ms", "X-RateLimit-Remaining"],
)

# --------------------------------------------------------------------------- #
# Routers
# --------------------------------------------------------------------------- #
API = settings.API_PREFIX
app.include_router(health.router, prefix=API)
app.include_router(auth.router, prefix=API)
# Role-specific consoles.  Both routers declare their own permission guards, so an
# analyst token hitting /api/admin/* gets 403 from the admin router itself rather
# than depending on anything the frontend does.
app.include_router(admin.router, prefix=API)
app.include_router(analyst.router, prefix=API)
app.include_router(datasets.router, prefix=API)
app.include_router(predictions.router, prefix=API)
app.include_router(alerts.router, prefix=API)
app.include_router(dashboard.router, prefix=API)
app.include_router(model_api.router, prefix=API)
app.include_router(assistant.router, prefix=API)
app.include_router(live.router, prefix=API)


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #
@app.exception_handler(ModelUnavailableError)
async def model_unavailable_handler(request: Request, exc: ModelUnavailableError):
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": str(exc), "code": "model_unavailable"},
    )


@app.exception_handler(DatasetError)
async def dataset_error_handler(request: Request, exc: DatasetError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"message": exc.message, **exc.detail}, "code": "dataset_error"},
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # ``exc.errors()`` embeds the raw exception object in ``ctx.error`` for custom
    # validators, which is not JSON serialisable - flatten to plain fields so the
    # client receives a real 422 instead of an unrelated 500.
    errors = [
        {
            "loc": [str(part) for part in error.get("loc", [])],
            "msg": str(error.get("msg", "validation failed")),
            "type": str(error.get("type", "value_error")),
        }
        for error in exc.errors()[:5]
    ]
    first = errors[0] if errors else {"loc": [], "msg": "validation failed"}
    field = ".".join(first["loc"][1:]) or "request"
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": f"Invalid value for '{field}': {first['msg']}",
            "code": "validation_error",
            "errors": errors,
        },
    )


@app.exception_handler(OperationalError)
async def db_error_handler(request: Request, exc: OperationalError):
    logger.error("database error on %s: %s", request.url.path, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Database connection failed. Please try again shortly.", "code": "database_unavailable"},
    )


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_error_handler(request: Request, exc: SQLAlchemyError):
    logger.error("database error on %s: %s", request.url.path, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "A database error occurred while processing the request.", "code": "database_error"},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):  # pragma: no cover - safety net
    logger.exception("unhandled exception on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred while processing the request.", "code": "internal_error"},
    )


# --------------------------------------------------------------------------- #
# Root
# --------------------------------------------------------------------------- #
@app.get("/", tags=["health"], summary="Service banner")
def root():
    return {
        "name": settings.APP_NAME,
        "full_name": "AI-Powered Network Intrusion Detection System",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "api_prefix": settings.API_PREFIX,
        "model": {
            "algorithm": model_service.metadata.get("algorithm", "Random Forest"),
            "dataset": model_service.metadata.get("dataset", "CICIDS2017"),
            "loaded": model_service.is_loaded,
        },
        "endpoints": {
            "health": f"{settings.API_PREFIX}/health",
            "login": f"{settings.API_PREFIX}/auth/login",
            "dashboard": f"{settings.API_PREFIX}/dashboard/stats",
            "analyze": f"{settings.API_PREFIX}/predictions/analyze",
            "model_info": f"{settings.API_PREFIX}/model/info",
            "live_stream": f"{settings.API_PREFIX}/live/stream",
        },
        "uptime_seconds": round(time.time() - _START_TIME, 3),
    }


_START_TIME = time.time()
