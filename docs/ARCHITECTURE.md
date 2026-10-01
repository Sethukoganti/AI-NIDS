# Architecture notes

## Layers

```
transport     FastAPI routers (app/api/*)          - HTTP/SSE, auth dependency, response models
domain        services (app/services/*)            - all business rules, no HTTP knowledge
persistence   SQLAlchemy models (app/models/*)     - ORM only, no raw SQL
contracts     Pydantic schemas + ML JSON artifacts - the only place shapes are defined
```

Routers stay thin: they authenticate, validate with Pydantic, delegate to a service and translate
`DatasetError`-style exceptions into HTTP status codes. That is why the analysis pipeline is testable
without HTTP and why the rules live in exactly one module each (`risk_service`, `alert_service`).

## Request path for an analysis

1. `POST /api/predictions/analyze` → `prediction_service.create_job()` writes an `analysis_jobs` row
   (`queued`) and, for ≤ `SYNC_ANALYSIS_ROW_LIMIT` rows, executes inline; otherwise the job id is
   submitted to the thread pool (`JOB_WORKERS`, default 2) and the API returns immediately.
2. The worker moves the job through explicit stages
   (`reading → preprocessing → model inference → risk scoring → persisting → alerts → completed`),
   committing `progress` and `stage` so the UI can poll `/api/predictions/jobs/{id}`.
3. `preprocessing_service.prepare_features()` aligns the uploaded frame with `feature_columns.json`
   (by name, imputing missing-but-expected columns with training medians, dropping ±∞ rows) and hands
   a float32 DataFrame to `ml_service.predict()`.
4. `ml_service` calls `predict_proba` **once** for the batch, then maps indices → class names through
   `label_mapping.json`. No retraining, no per-row model calls.
5. `risk_service.assess()` converts (class, confidence, destination port) → level + score;
   `alert_service.create_alerts_for_job()` groups by `(attack, port)` and writes the bounded alert set.
6. Predictions (capped by `STORE_PREDICTIONS_LIMIT`), alerts and hourly `detection_statistics` are
   persisted in one transaction; the summary (distributions, averages, timing, ground-truth metrics)
   is written back onto the job row.

## Why things are shaped this way

- **Model loaded once at startup** (`main.lifespan`) — inference is a function call, not a load.
  The app fails fast with a clear message if an artifact is missing; it never substitutes a dummy model.
- **Feature order is data, not code** — `feature_columns.json` is the contract; both training and
  inference read the same file, and `ml_service.predict()` re-checks the incoming column order and
  raises instead of silently reshaping.
- **Ground truth is optional and separate** — the `Label` column is extracted for scoring but removed
  from the feature matrix, so a labelled file cannot leak its answer into the model.
- **Statistics are pre-aggregated** — the dashboard reads `detection_statistics` buckets; per-request
  `GROUP BY` over hundreds of thousands of `predictions` rows would not stay fast.
- **Alerts are bounded by construction** — one alert per `(attack, port)` pair, a 300-pair ceiling with
  per-attack overflow, and `occurrences=N` on every row mean a port sweep from a single flow file
  cannot create an unusable queue, while the linked `prediction_id` keeps each alert auditable.
- **The simulation reuses the inference path** — `live_service` streams rows through the same
  preprocessing/risk code as a batch job, so what you see in the demo is what an upload would produce.

## Failure modes handled explicitly

| Situation | Behaviour |
| --- | --- |
| Model artifact missing/corrupt | startup fails with a precise message (`MODEL_PATH`) |
| Upload not in CICIDS format | `400` at upload **and** at analysis time, listing matched/expected/missing features |
| < 80% feature coverage | `400` with `required_coverage` and a hint, before any row is stored |
| ±∞ / NaN values | replaced/skipped, counted in `summary.preprocessing`, never scored with a fabricated value |
| SHAP unavailable for a record | response carries `method: "global_feature_importance"` and the UI labels it as model-level |
| Empty database | assistant replies "no detection data available"; dashboard shows zeroed cards, not fake data |
| Provider key missing/invalid | `AI_PROVIDER=none` local engine is used; `/assistant/status` reports the mode honestly |

## Extension points

- `live_service.stream_frames()` already speaks the `start/flow/done` protocol — a real capture agent
  (Zeek/NFStream) could publish into the same shape without touching the frontend.
- `ai_explanation_service` takes structured facts, so adding another provider means adding one
  adapter function, not touching the rules.
- `ml/train_model.py` writes every artifact the API reads, so retraining a v2 model is a file swap
  (plus an evaluation refresh) rather than a code change.
