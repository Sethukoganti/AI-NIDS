# Testing

## Backend + ML

```bash
cd backend
python -m pytest                 # 67 tests, ~7 s
python -m pytest -v
python -m pytest tests/test_ml_pipeline.py -v      # feature-order and bad-input contract
```

`tests/conftest.py` sets the test environment before the app is imported: its own SQLite file in the
temp directory (`ainids_pytest.db`), `SEED_DEMO_DATA=true`, `RATE_LIMIT_ENABLED=true`,
`AI_PROVIDER=none`. It never touches `data/ainids.db`, never calls an external provider and leaves no
state behind (the DB file is deleted at the start of each session). One `TestClient` runs the FastAPI
lifespan once; the shared 60-row sample is uploaded and analysed once and reused, which keeps the
suite at a few seconds.

Modules and intent:

| Module | Focus |
| --- | --- |
| `test_auth.py` | authentication, JWT, role separation, password policy, logout revocation |
| `test_datasets.py` | upload guard rails, schema enforcement, profiling, explorer pagination, admin-only delete |
| `test_predictions.py` | analysis pipeline end to end, ground-truth scoring, filters/sorting/pagination, record explanation |
| `test_alerts.py` | alert creation, flood control (one alert per attack/port pair, `occurrences=N`), triage, documented rules incl. the bounding policy |
| `test_model_api.py` | model card, importances, evaluation, architecture, class profiles, health |
| `test_ml_pipeline.py` | **strict feature contract**: order, deterministic reordering, misordered-matrix refusal, missing features, ±∞ handling, labels never used as features |
| `test_middleware.py` | rate limiter, security headers, instrumentation headers, no internal leakage |

### Adding a test

Use the fixtures instead of building state by hand: `client`, `auth`, `admin_auth`,
`sample_dataset`, `analysed_sample`, `feature_columns`, plus the CSV builders
`build_csv_bytes(rows=…, drop_leading=…, shuffle_columns=…)`. Assertions should pin *behaviour*, not
exact prose, so error-message wording can improve without breaking the suite.

## Frontend

```bash
cd frontend
npm run test          # vitest, jsdom + Testing Library (10 tests)
npx tsc --noEmit      # strict type-check (0 errors)
npm run build         # production build
```

The frontend tests cover the typed API client (token header, 401 handling, error normalisation), the
formatters/colour maps shared by the charts, and the login page rendering. Component tests for the
data-heavy pages would need MSW handlers against the recorded payload shapes; that is the next
increment if you want a wider frontend suite.

## Manual checks worth doing before a demo

1. `python ml/train_model.py` re-runs and the *AI Model* page then shows the new evaluation timestamp.
2. Upload a CSV with 10 of the 70 feature columns → accepted with imputation listed; upload a
   spreadsheet export → rejected with matched/expected/missing detail.
3. `POST /api/predictions/analyze` twice in a row → identical predictions and confidences
   (deterministic model, deterministic preprocessing).
4. Rename `backend/app/ml/feature_columns.json` → API refuses to start with a clear message (proves
   the model is never silently retrained or replaced).
5. `curl -N` the SSE endpoint → `start`, N × `flow`, `done`; the UI banner still says
   *"Live Traffic Simulation"*.
6. Delete `data/ainids.db`, restart → demo accounts + bootstrap analysis are recreated; the assistant
   then answers with real numbers instead of "no detection data available".

## CI sketch

```yaml
# .github/workflows/ci.yml (not committed - Docker/CI runners were unavailable in the build env)
jobs:
  backend:  # python 3.12, pip install -r backend/requirements.txt, pytest
  frontend: # node 20, npm ci, npx tsc --noEmit, npm run test, npm run build
  images:   # docker build backend/Dockerfile + frontend/Dockerfile (context: repo root)
```
