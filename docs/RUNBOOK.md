# Operations runbook

## Topology

| Service | Container | Port | Notes |
| --- | --- | --- | --- |
| SPA (nginx) | `ainids-frontend` | `FRONTEND_PORT` → 5173 → 80 | serves the Vite build, proxies `/api` and `/docs` to the backend, SSE buffering disabled |
| API (uvicorn) | `ainids-backend` | `BACKEND_PORT` → 8000 | non-root user, healthcheck on `/api/health/live` |
| PostgreSQL 16 | `ainids-postgres` | `POSTGRES_PORT` → 5432 | volume `pgdata`, `pg_isready` healthcheck |
| Redis 7 (optional) | `ainids-redis` | — | `--profile cache`; reserved for the future job queue |

## Bring-up / teardown

```bash
cp .env.example .env                 # set JWT_SECRET (required by compose)
docker compose up --build -d         # start everything
docker compose ps                    # health status per service
docker compose logs -f backend       # follow API logs
docker compose down                  # stop, keep volumes
docker compose down -v               # stop and delete the database + uploads
```

Local (no Docker): `uvicorn app.main:app --port 8000` in `backend/` and `npm run dev` in
`frontend/`; SQLite is used automatically.

## Health & readiness

| Probe | Meaning |
| --- | --- |
| `GET /api/health/live` | process is up (no DB access) — use for liveness |
| `GET /api/health` | DB reachable, model loaded (with class/feature counts), AI provider mode, upload dir, rate-limiter counters |
| `GET /api/health/system` | admin-only: Python/platform details, disk usage, job-worker config, environment flags |

Startup log lines to look for:

```
database schema ready
model loaded: Random Forest classes=9 features=70 in 0.79s
ML model ready: Random Forest | 100 trees | 9 classes | test accuracy 0.9959430496019596
AI explanation layer: local engine          (or the configured provider)
ready - docs at http://localhost:8000/docs
```

## Routine tasks

| Task | Command |
| --- | --- |
| Retrain / refresh artifacts | `python ml/train_model.py` (offline, then restart the API) |
| Rebuild the dataset | `python ml/build_dataset.py --download` then `python ml/build_dataset.py` |
| Reset the demo database | stop the API, delete `data/ainids.db`, start again (seed re-runs) |
| Inspect PostgreSQL | `docker compose exec postgres psql -U ainids -d ainids -c '\dt'` |
| Back up PostgreSQL | `docker compose exec postgres pg_dump -U ainids ainids > ainids_$(date +%F).sql` |
| Restore | `cat ainids_*.sql \| docker compose exec -T postgres psql -U ainids -d ainids` |
| Clear uploads | `docker compose down && docker volume rm ai-nids_uploads` |
| Rotate the JWT secret | change `JWT_SECRET` in `.env`, `docker compose up -d backend` (all sessions are invalidated) |

## Logs

Structured, single-line, with a request id per call:

```
rid=730868f974a5 GET /api/health/system -> 200 in 11.4ms user=<id> ip=<ip>
```

* `ainids.request` — method, path, status, duration, user id, client ip. Never bodies, passwords or
  tokens; `Authorization` values are redacted.
* `ainids.ml` — model load, SHAP explainer init, inference timing.
* `ainids.alerts` — `job <id>: 160 alert(s) from 593 suspicious flow(s) across 160 attack/port pair(s)`.
* `ainids.datasets`, `ainids.seed`, `ainids.ai` — uploads, demo bootstrap, provider calls.
* Set `LOG_LEVEL=DEBUG` for SQL/preprocessing detail while diagnosing; leave it at `INFO` otherwise.

## Capacity & tuning

| Symptom | Knob |
| --- | --- |
| Jobs queue up | raise `JOB_WORKERS` (CPU-bound: keep ≤ cores), or lower `STORE_PREDICTIONS_LIMIT` |
| Uploads of big files feel slow | raise `SYNC_ANALYSIS_ROW_LIMIT` to queue them in the background instead of blocking the request |
| Database growing | lower `STORE_PREDICTIONS_LIMIT`, or prune `predictions`/`alerts` for old jobs |
| Dashboard slow | ensure the `detection_statistics` rollup is populated (it is written per job) |
| 429s from a script | raise `RATE_LIMIT_*`, or set `RATE_LIMIT_ENABLED=false` for a local demo only |
| SHAP latency | lower `SHAP_MAX_RECORDS` so batch explanation falls back sooner |

## Incident checklist

1. `curl -s localhost:8000/api/health | jq` — which subsystem is red?
2. Model red → check `MODEL_PATH` and that `ml/artifacts` was copied into the image (`docker compose
   exec backend ls /app/ml/artifacts`). The API will not start with a missing artifact.
3. Database red → `docker compose ps postgres`; check `DATABASE_URL`/credentials/health.
4. 500s with no obvious cause → `docker compose logs --tail=200 backend` and match the
   `X-Request-ID` from the client response.
5. 401/403 storms after a deploy → the token secret changed (`JWT_SECRET`); users must sign in again.
6. Unexpected alert volume → confirm the grouping rules via `/api/alerts/rules` and the
   `job <id>: M alert(s) … across K attack/port pair(s)` log line before assuming a model problem.
   One alert per pair is expected: `M == K` unless the 300-pair ceiling kicked in.

## Demo IP access rules

Admins can demonstrate adding, changing and removing source-IP allow/deny rules from any flow's
**Detections → Flagged flows → Inspect → Overview → Demo firewall access controls**. The rules are
stored in the AI-NIDS database and shown in the UI, including for NORMAL-risk records or records
without a source IP (enter an address manually). These rules are explicitly simulated: they do not
call a firewall API, block traffic, or change any real network. No API key or network ID is needed.
Changes require explicit confirmation, the `network.configure` permission, and are recorded in the
audit log. **Response Center → Demo firewall IP rules** shows and clears the saved demo rules.

## Upgrade procedure

```bash
git pull
python ml/train_model.py                 # only if artifacts changed
docker compose build && docker compose up -d
curl -fsS localhost:8000/api/health | jq '.checks.model'
```
