# AI-NIDS API reference

Base URL: `http://localhost:8000/api` · Interactive docs: `/docs` · Schema: `/openapi.json`

All endpoints require `Authorization: Bearer <jwt>` except `/api/health`, `/api/health/live`,
`/api/auth/login` and `/api/auth/config`. Roles: **A** = any authenticated user, **Ad** = admin only.

| # | Method | Path | Role | Purpose |
| --: | --- | --- | --- | --- |
| 1 | GET | `/` | public | service banner (version, docs link) |
| 2 | POST | `/auth/login` | public | email + password → JWT (rate limited 10/min/IP) |
| 3 | POST | `/auth/logout` | A | revoke the presented token |
| 4 | GET | `/auth/me` | A | current user |
| 5 | GET | `/auth/config` | public | login-screen config (demo accounts on/off, password policy) |
| 6 | GET | `/auth/users` | Ad | list users |
| 7 | POST | `/auth/users` | Ad | create user (password policy enforced) |
| 8 | POST | `/datasets/upload` | A | upload CSV/TSV/TXT/Parquet (extension, size, row, schema checks) |
| 9 | POST | `/datasets/sample` | A | register a bundled held-out sample (`sample_traffic`, `simulation_stream`) |
| 10 | GET | `/datasets` | A | list datasets |
| 11 | GET | `/datasets/reference` | A | full CICIDS2017 capture statistics (real build output) |
| 12 | GET | `/datasets/{id}` | A | dataset profile: columns, coverage, class distribution, sample rows |
| 13 | GET | `/datasets/{id}/rows` | A | server-side paginated rows (`page`, `page_size` ≤ 100) |
| 14 | GET | `/datasets/{id}/download` | A | download the stored file |
| 15 | DELETE | `/datasets/{id}` | Ad | delete dataset + stored file |
| 16 | POST | `/predictions/analyze` | A | run the model over a registered dataset |
| 17 | POST | `/predictions/analyze/upload` | A | upload + analyse in one call |
| 18 | POST | `/predictions/simulate` | A | score N sample flows sequentially (`persist=false` keeps the DB clean) |
| 19 | GET | `/predictions/jobs` | A | recent jobs (status, progress, stage) |
| 20 | GET | `/predictions/jobs/{id}` | A | job detail incl. `summary` and ground-truth metrics |
| 21 | GET | `/predictions` | A | stored predictions: `search`, `attack_type`, `risk_level`, `sort_by`, `sort_dir`, `page`, `page_size` |
| 22 | GET | `/predictions/{id}` | A | one flow: features, risk rationale, alerts, `?with_shap=true` |
| 23 | GET | `/predictions/{id}/explain` | A | grounded explanation (local engine or configured LLM) |
| 24 | GET | `/alerts` | A | alert list: `severity`, `status`, `attack_type`, `search`, pagination |
| 25 | GET | `/alerts/summary` | A | counters by severity/status |
| 26 | GET | `/alerts/rules` | A | the documented risk + grouping rules in machine-readable form |
| 27 | GET | `/alerts/{id}` | A | alert detail incl. linked prediction |
| 28 | PATCH | `/alerts/{id}` | A | triage: `new` → `reviewed` → `resolved` (+ note) |
| 29 | GET | `/dashboard/stats` | A | 6 metric cards + verdict/risk/attack distributions (`hours` window) |
| 30 | GET | `/dashboard/timeline` | A | hourly traffic series (cached rollup) |
| 31 | GET | `/dashboard/recent-alerts` | A | latest alerts for the dashboard table |
| 32 | GET | `/dashboard/alerts-summary` | A | severity/status counters |
| 33 | GET | `/model/info` | A | model card: algorithm, hyper-parameters, dataset, `accuracy_label`, limitations |
| 34 | GET | `/model/features` | A | `model.feature_importances_` (top-N, descending) |
| 35 | GET | `/model/evaluation` | A | per-class report + 9×9 confusion matrix (held-out split) |
| 36 | GET | `/model/architecture` | A | pipeline stages with real dimensions |
| 37 | GET | `/model/class-profiles` | A | per-class feature medians/p95 (explanation evidence) |
| 38 | POST | `/assistant/ask` | A | grounded Q&A → `{provider, answer, facts, sources, evidence}` (`include_evidence`) |
| 39 | GET | `/assistant/status` | A | provider, mode, model, `api_key_configured` |
| 40 | GET | `/live/samples` | A | replay samples available for the simulation |
| 41 | GET | `/live/stream` | A | SSE: `start` → `flow`×N → `done` (accepts `?token=`) |
| 42 | GET | `/health` | public | readiness: DB, model, AI, uploads, rate limiter |
| 43 | GET | `/health/live` | public | liveness only |
| 44 | GET | `/health/system` | Ad | detailed runtime/system information |

### Admin demo IP rules

The following admin-only endpoints manage persistent **simulation-only** source-IP rules for project
demos. They never call an external firewall API or change real network traffic. Mutations require
`confirm: true` and a reason; rules are IPv4-only.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/network/blocked-ips` | Simulation mode and saved IP rules |
| POST | `/admin/network/blocked-ips` | Add/replace a simulated source-IP deny rule |
| POST | `/admin/network/allowed-ips` | Add/replace a simulated broad source-IP allow rule |
| POST | `/admin/network/blocked-ips/remove` | Remove one simulated deny rule |
| POST | `/admin/network/allowed-ips/remove` | Remove one simulated allow rule |
| POST | `/admin/network/blocked-ips/clear` | Remove all simulated rules |

## Conventions

- **Auth**: `Authorization: Bearer <jwt>`; the SSE endpoint additionally accepts `?token=` because
  `EventSource` cannot set headers.
- **Errors** are JSON: `{"detail": "…"}` or, for validation problems,
  `{"detail": "...", "code": "validation_error", "errors": [{"loc", "msg", "type"}]}`.
  Status codes: 400 bad input/unsupported file, 401 unauthenticated, 403 role/ownership,
  404 unknown id, 409 conflict (e.g. dataset without a stored file), 413 too large, 422 validation,
  429 rate limited (with `Retry-After`).
- **Headers** on every response: `X-Request-ID`, `X-Process-Time-Ms`, `X-RateLimit-Limit`,
  `X-RateLimit-Remaining`.
- **Pagination** is always server-side: `{"items": [...], "total": n, "page": p, "page_size": s, "pages": k}`.

## Worked examples

```bash
# 1. sign in
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"analyst@ainids.dev","password":"Analyst@123"}' | jq -r .access_token)

# 2. register the bundled sample (1 500 held-out flows)
DS=$(curl -s -X POST localhost:8000/api/datasets/sample -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"sample":"sample_traffic"}' | jq -r .id)

# 3. analyse it
curl -s -X POST localhost:8000/api/predictions/analyze -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{\"dataset_id\":\"$DS\",\"force_sync\":true}" \
  | jq '.summary | {total_records, suspicious_records, risk_distribution, ground_truth}'

# 4. explain one detection
curl -s "localhost:8000/api/predictions/$(curl -s "localhost:8000/api/predictions?attack_type=DDoS&page_size=1" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.items[0].id')?with_shap=true" \
  -H "Authorization: Bearer $TOKEN" | jq '.explanation | {method, base_value}'

# 5. ask the assistant
curl -s -X POST localhost:8000/api/assistant/ask -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"question":"which attack is most common?"}' | jq '.answer'

# 6. stream the simulation (EventSource-compatible)
curl -N "localhost:8000/api/live/stream?rows=10&sample=simulation_stream&token=$TOKEN"
```
