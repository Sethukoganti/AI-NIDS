# ---------------------------------------------------------------------------
# AI-NIDS backend image
#
# Build context is the *repository root* (see docker-compose.yml) because the
# backend needs the trained model artifacts that live in ./ml/artifacts.
# The Random Forest model is loaded from disk at runtime - it is never
# retrained inside the container.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=UTC

WORKDIR /app

# libgomp1 is required by scikit-learn's OpenMP runtime; curl is used by HEALTHCHECK.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

# Dependency layer first so source edits do not re-resolve wheels.
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Application code + model artifacts
COPY backend/app ./app
COPY ml/artifacts ./ml/artifacts
COPY ml/cicids_config.py ./ml/cicids_config.py
COPY frontend/public/samples ./frontend/public/samples

# Uploads are bind-mounted in compose; this keeps the path valid for plain `docker run`.
RUN mkdir -p /app/data/uploads

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 ainids \
    && chown -R ainids:ainids /app
USER ainids

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health/live || exit 1

# Environment defaults - override with real secrets via compose/.env.
ENV AINIDS_PROJECT_ROOT=/app \
    ENVIRONMENT=production \
    MODEL_PATH=/app/ml/artifacts/random_forest_model.joblib \
    FEATURE_COLUMNS_PATH=/app/ml/artifacts/feature_columns.json \
    LABEL_CODES_PATH=/app/ml/artifacts/label_codes.json \
    LABEL_MAPPING_PATH=/app/ml/artifacts/label_mapping.json \
    PREPROCESSING_CONFIG_PATH=/app/ml/artifacts/preprocessing_config.json \
    MODEL_METADATA_PATH=/app/ml/artifacts/model_metadata.json \
    EVALUATION_PATH=/app/ml/artifacts/evaluation.json \
    FEATURE_IMPORTANCE_PATH=/app/ml/artifacts/feature_importance.json \
    DATASET_STATS_PATH=/app/ml/artifacts/dataset_stats.json \
    CORS_ORIGINS=http://localhost:5173,http://localhost:3000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
