# AI-NIDS — AI-Powered Network Intrusion Detection System

A complete, working network intrusion-detection platform: a **Random Forest** model trained on
**CICIDS2017**, served by a **FastAPI** backend with JWT auth and real middleware, and a
**React + TypeScript** SOC dashboard with explainability (SHAP / model importance) and an optional
grounded LLM explanation layer.

> **Honest accuracy statement.** On the held-out 30% test split of the cleaned CICIDS2017 table
> described in this repository the model scores **99.5943% accuracy (macro-F1 0.9818)** — measured,
> not typed in. That is a result on a *2017 research-lab capture*, not a warranty of real-world
> detection. It does **not** mean "99.99% everywhere", and it does **not** mean every possible
> attack is detected; only the 9 traffic classes below are recognised. See
> [Known limitations](#17-known-limitations).

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11--3.13-blue">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-0.115-009688">
  <img alt="React" src="https://img.shields.io/badge/React-18-61dafb">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5.7-3178c6">
  <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-16-336791">
  <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-1.6-f7931e">
  <img alt="Docker" src="https://img.shields.io/badge/docker-compose-2496ed">
</p>

---

## Quick start — one command

You need **Node 18+** and **Python 3.11–3.13** installed. Nothing else.

```bash
npm install          # once: installs the dashboard + backend dependencies
npm run dev          # starts the API and the dashboard together
```

Then open the URL that gets printed (`http://localhost:5173`) and sign in with
`analyst@ainids.dev` / `Analyst@123`.

`npm run dev` is self-healing: it creates `.env` with a generated JWT secret, sets up a project
virtual environment, installs the Python requirements, installs the frontend packages, verifies the
trained model files, starts both servers (prefixing their logs with `[api]` / `[web]`) and stops both
on `Ctrl+C`. Running it a second time in another terminal reuses the servers that are already up
instead of starting duplicates. If you open the **`frontend/`** folder in VS Code instead of the
root, `npm run dev` there does exactly the same thing.

| Command | What it does |
| --- | --- |
| `npm install` | one-time dependency setup (runs `npm run setup` for you) |
| `npm run dev` | **start everything** — API `:8000` + dashboard `:5173` |
| `npm run test` | backend `pytest` and frontend `vitest` in one go |
| `npm run train` | retrain/refresh the Random Forest artifacts (optional) |
| `npm run build` | production build of the dashboard |
| `npm run reset` | wipe the local database + uploads (demo data re-seeds on next start) |

Prefer doing it by hand or in containers? See [Installation](#13-installation) and
[Running the application](#17-running-the-application).

---

## Interface at a glance

The navigation is deliberately short — six destinations, plain-language labels, and one obvious
primary button:

| Where | What it is for |
| --- | --- |
| **Overview** | the live summary + a 3-step "start here" guide |
| **Analyze traffic** | upload/pick a CSV, watch it being scored flow by flow |
| **Detections** | *Flagged flows* and *Alert queue* tabs — filter, sort, open a record, press **Why?** |
| **AI model** | *Model & metrics* and *AI insights* tabs — accuracy, confusion matrix, feature importance |
| **Data** | *Datasets* and *Live simulation* tabs — uploads, the CICIDS2017 reference card, the replayed feed |
| **Settings** | your account, user management (admin), system information |

Older links still work: `/alerts` → `/detections?tab=alerts`, `/predictions` → `/detections`,
`/datasets` → `/data`, `/simulation` → `/data?tab=simulation`, `/insights` → `/model?tab=insights`.
Motion is kept subtle (fade/slide on navigation, staggered cards, animated counters) and it is fully
disabled for anyone with *prefers-reduced-motion* enabled.

---

## Table of contents

0. [Quick start (one command)](#quick-start--one-command)
0. [Interface at a glance](#interface-at-a-glance)
1. [What this project is](#1-what-this-project-is)
2. [Feature list](#2-feature-list)
3. [Architecture](#3-architecture)
4. [Project structure](#4-project-structure)
5. [Technology stack](#5-technology-stack)
6. [Dataset — CICIDS2017](#6-dataset--cicids2017)
7. [Machine-learning model](#7-machine-learning-model)
8. [Inference contract (strict feature handling)](#8-inference-contract-strict-feature-handling)
9. [Risk scoring & alert rules](#9-risk-scoring--alert-rules)
10. [Explainability (XAI)](#10-explainability-xai)
11. [AI Security Assistant](#11-ai-security-assistant)
12. [Live Traffic Simulation](#12-live-traffic-simulation)
13. [Installation](#13-installation)
14. [Environment variables](#14-environment-variables)
15. [Database setup](#15-database-setup)
16. [ML model setup](#16-ml-model-setup)
17. [Running the application](#17-running-the-application)
18. [API reference](#18-api-reference)
19. [Testing](#19-testing)
20. [Demo script](#20-demo-script)
21. [Security notes](#21-security-notes)
22. [Known limitations](#22-known-limitations)
23. [Future improvements](#23-future-improvements)
24. [Troubleshooting](#24-troubleshooting)
25. [Credits & references](#25-credits--references)

---

## 1. What this project is

AI-NIDS ingests network-flow records (CSV/TSV/Parquet in CICIDS2017 column format), scores every
flow with a pre-trained Random Forest, converts the model output into a documented risk level,
raises de-duplicated alerts, stores everything in PostgreSQL/SQLite, and explains the verdict —
first with TreeSHAP over the actual model, and optionally with an LLM that only ever sees the
structured model output (it cannot invent evidence because it is never given anything else).

The project is **defensive only**: it classifies traffic that is handed to it. There is no scanning,
exploitation, payload generation or any other offensive capability.

Everything the UI shows comes from a real HTTP call to the backend; there are no mock screens, no
hard-coded metrics and no "coming soon" placeholders for core features.

**Detected classes (9):** `Normal Traffic`, `DoS`, `DDoS`, `Port Scanning`, `Brute Force`,
`Web Attack`, `Bot`, `Infiltration`, `Heartbleed`.

---

## 2. Feature list

**Machine learning**
- Random Forest (100 trees, scikit-learn 1.6) trained offline on CICIDS2017; the serialized model is
  loaded with `joblib` at startup and **never retrained inside the API**.
- Strict inference contract: 70 features in the exact training order, missing-but-expected columns
  imputed with training medians (and reported), ±∞ → NaN rows dropped, ≥ 80% feature coverage
  required — otherwise a clear "incompatible file" error listing matched/expected/missing columns.
- Optional ground-truth scoring: if the uploaded file still carries its `Label` column, the job
  reports accuracy/precision/recall/F1 against it. The label is never used as a feature.

**Backend (FastAPI)**
- 44 REST endpoints under `/api`, OpenAPI docs at `/docs`.
- JWT authentication with **Admin** and **Analyst** roles, hashed passwords (bcrypt), login/logout.
- Real middleware: JWT auth guard, request logging that redacts secrets, per-endpoint rate limiting,
  CORS allow-list, security headers, upload size/type/row caps, Pydantic request validation.
- Background analysis jobs with progress reporting ("Processing 42%…"), server-side pagination,
  SQL aggregation and cached dashboard statistics.
- Dataset Explorer with server-side paging, per-column profiling and preview caching.

**Frontend (React + TS + Vite)**
- **Six-destination navigation** with plain-language labels and a 3-step "start here" guide; related
  screens are grouped into tabs instead of separate menu entries.
- **Subtle motion throughout**: page fades/slides on navigation, staggered card reveals, animated
  metric counters, animated collapsibles, drawer slide-in — all switched off automatically for
  `prefers-reduced-motion` users.
- **One command to run everything**: `npm run dev` bootstraps and starts API + dashboard together.
- Dark SOC dashboard (Tailwind + shadcn-style Radix primitives, Recharts, Lucide) with cyan accents.
- 6 metric cards, verdict pie, traffic timeline, attack-type bar chart, risk mix, recent-alerts table.
- Traffic Analyzer: drag-and-drop CSV upload, client-side type/size validation, sample datasets,
  live progress, incompatibility errors surfaced verbatim.
- Prediction Results: search, attack filter, risk filter, sorting, pagination, CSV export view.
- Record inspection with a **"Why?"** panel: TreeSHAP contributions per feature, model metadata and
  the AI explanation tab.
- Live Traffic Simulation over SSE (explicitly labelled as a replay, not packet capture).
- AI Security Assistant panel that answers from real database numbers and says
  *"no detection data available"* when the database is empty.

**Operations**
- Zero-config launcher (`npm run dev`) that installs what is missing, starts both servers and shuts
  them down together; `npm run test`, `npm run train`, `npm run reset` for the rest.
- Docker Compose stack (frontend + backend + PostgreSQL; optional Redis under a profile).
- pytest suite for the backend and ML contract tests, Vitest + Testing Library suite for the frontend.
- Structured logging, `/api/health`, `/api/health/live`, `/api/health/system` probes.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ Browser (React + TS + Vite, Tailwind, Recharts, Lucide)                          │
│  Dashboard · Traffic Analyzer · Prediction Results · Alerts · Datasets · Model   │
│  Insights · Live Simulation · Settings                     + AI Assistant panel  │
└───────────────┬──────────────────────────────────────────────────────────────────┘
                │  HTTPS/JSON + JWT (Bearer)          SSE (/api/live/stream)
┌───────────────▼──────────────────────────────────────────────────────────────────┐
│ FastAPI application                                                              │
│  middleware: CORS → Security headers → Request log → Rate limit → JWT auth       │
│  routers:  auth · datasets · predictions · alerts · dashboard · model ·          │
│            assistant · live · health                                            │
├──────────────────────────────────────────────────────────────────────────────────┤
│ Services                                                                         │
│  preprocessing  strict column matching, imputation, dtype/shape validation       │
│  ml             joblib Random Forest, predict_proba, TreeSHAP, feature importance│
│  risk           weighted severity × confidence + sensitive-port bonus → LOW..CRIT │
│  alert          (attack, port) grouping, volume cap, status workflow             │
│  prediction     background jobs, progress, persistence, ground-truth scoring     │
│  dataset        upload validation, profiling, preview cache, explorer paging     │
│  dashboard      SQL aggregation + cached hourly detection statistics             │
│  ai_explanation grounded explanations; local engine or OpenAI-compatible LLM     │
│  live_service   sample replay + SSE streaming for the simulation page            │
└───────────────┬──────────────────────────────────────────────────────────────────┘
                │ SQLAlchemy 2.0 (ORM only — no string-built SQL)
┌───────────────▼──────────────────────┐        ┌───────────────────────────────────┐
│ PostgreSQL 16 (docker) / SQLite (dev)│        │ ml/artifacts (mounted, read-only) │
│  users · datasets · analysis_jobs ·  │        │  random_forest_model.joblib       │
│  predictions · alerts ·              │        │  feature_columns.json             │
│  detection_statistics · audit_logs   │        │  label_mapping.json, metadata …   │
└──────────────────────────────────────┘        └───────────────────────────────────┘
```

**A single analysis request, end to end**

1. `POST /api/datasets/upload` → file type/size/row checks, then the CICIDS2017 schema is matched;
   an incompatible file is rejected with `400` *before* anything is stored.
2. `POST /api/predictions/analyze` → a job row is created and executed by a worker thread
   (small files respond inline). Stages: `reading → preprocessing → RF inference → risk scoring →
   persisting → alerts → completed`, each written to the job row and polled by the UI.
3. Features are canonicalised (BOM/whitespace), compared against `feature_columns.json`, imputed and
   re-ordered; `predict_proba` runs on a DataFrame so scikit-learn sees the training feature names.
4. Risk level/score are computed per row, alerts are grouped, predictions and hourly statistics are
   persisted, and the response returns distributions, timing, the model block and (if present) the
   ground-truth score.
5. Any single prediction can be explained: `GET /api/predictions/{id}?with_shap=true` returns the
   stored row, the TreeSHAP contributions for that record, the model's global importances, the risk
   rationale and the alerts it raised.

---

## 4. Project structure

```
ai-nids/
├── backend/
│   ├── app/
│   │   ├── api/                 # routers: auth, health, datasets, predictions, alerts,
│   │   │                        #          dashboard, model, assistant, live
│   │   ├── core/                # config.py (pydantic-settings), security.py, logging.py
│   │   ├── db/                  # session.py (engine/SessionLocal), seed.py (demo bootstrap)
│   │   ├── middleware/          # auth, rate_limit, logging, security
│   │   ├── ml/                  # ← runtime model artifacts (joblib + JSON, loaded, never trained)
│   │   ├── models/              # database_models.py (ORM), schemas.py (Pydantic contracts)
│   │   ├── services/            # preprocessing, ml, risk, alert, prediction, dataset,
│   │   │                        # dashboard, ai_explanation, live_service
│   │   └── main.py              # app factory, lifespan, middleware wiring, exception handlers
│   ├── tests/                   # pytest: auth, datasets, predictions, alerts, model API,
│   │                            # middleware, ML pipeline (feature order / bad input)
│   ├── Dockerfile
│   ├── pytest.ini
│   └── requirements.txt
├── package.json                 # root scripts: npm run dev / test / train / build / reset
├── scripts/                     # zero-dependency Node launcher (dev.mjs, setup.mjs, lib.mjs, …)
├── frontend/
│   ├── public/samples/          # sample_traffic.csv (1 500 flows), simulation_stream.csv (800)
│   ├── src/
│   │   ├── components/
│   │   │   ├── assistant/       # AssistantPanel.tsx (floating AI assistant)
│   │   │   ├── charts/          # Recharts wrappers (donut, timeline, bars, waterfall, matrix)
│   │   │   ├── layout/          # Sidebar.tsx (6 destinations), AppShell.tsx, HubTabs.tsx,
│   │   │   │                    # GuideSteps.tsx (3-step start guide)
│   │   │   ├── motion/Reveal.tsx# IntersectionObserver fade/slide wrapper
│   │   │   ├── ui/              # shadcn-style primitives incl. disclosure.tsx
│   │   │   ├── PredictionDetail.tsx, NetworkBackground.tsx, common.tsx
│   │   ├── context/AuthContext.tsx
│   │   ├── hooks/               # useHealth.ts, useCountUp.ts (animated metrics)
│   │   ├── lib/                 # api.ts (typed fetch client + SSE), types.ts, format.ts,
│   │   │                        # routes.ts (legacy deep-link redirects)
│   │   ├── pages/               # Landing, Login, Dashboard, TrafficAnalyzer, Detections,
│   │   │                        # ModelHub, DataHub, Settings (+ the panel pages they group)
│   │   ├── test/                # vitest setup + api/format/login/navigation tests
│   │   ├── App.tsx, main.tsx, index.css
│   ├── Dockerfile
│   └── package.json, vite.config.ts, tailwind.config.js, tsconfig*.json
├── ml/
│   ├── cicids_config.py         # shared constants: files, URLs, label map, 78 features, risk rules
│   ├── build_dataset.py         # streaming CICIDS2017 → cleaned parquet (+ full-dataset stats)
│   ├── train_model.py           # train / evaluate / export artifacts + demo samples
│   ├── build_profiles.py        # per-class feature profiles for the Model page
│   └── artifacts/               # training outputs (copied into backend/app/ml/)
├── data/
│   ├── processed/cicids2017_subset.parquet    # 217 731 × 72 training table
│   ├── uploads/                              # user uploads (git-ignored)
│   └── ainids.db                             # SQLite dev database (git-ignored)
├── docker/
│   └── nginx.conf               # SPA + /api + /docs proxy with SSE-friendly settings
├── docs/
│   ├── API.md                   # endpoint reference with example payloads
│   ├── ARCHITECTURE.md          # deeper design notes and data-flow walkthrough
│   ├── ML_PIPELINE.md           # dataset build, training, evaluation, model artifacts
│   ├── QUICKSTART.md            # two-minute "run it" guide for a fresh clone
│   ├── RUNBOOK.md               # operations: env, ports, backups, logs, troubleshooting
│   └── TESTING.md               # how to run and extend both test suites
├── docker-compose.yml
├── .env.example                 # every environment variable, no real secrets
└── README.md
```

---

## 5. Technology stack

| Layer | Choice | Why |
| --- | --- | --- |
| Model | scikit-learn **Random Forest** (100 trees) | required primary algorithm; strong on tabular flow data, ships `feature_importances_` and TreeSHAP support |
| Serialization | **joblib** | keeps dtype/array structure; loaded at runtime, never refit in the API |
| XAI | **SHAP** (TreeExplainer) + Gini importances | per-record attribution over the real model |
| API | **FastAPI** + Pydantic v2 | typed contracts, automatic OpenAPI docs |
| ORM/DB | **SQLAlchemy 2.0** + **PostgreSQL 16** (SQLite for dev) | parameterised queries, portable dev/prod |
| Auth | **PyJWT** + **bcrypt** | stateless JWT, hashed passwords |
| Frontend | **React 18 + TypeScript + Vite** | required stack, fast HMR |
| Styling | **Tailwind CSS** + Radix-based shadcn-style components | dark SOC theme with cyan accents |
| Charts | **Recharts**, icons **Lucide React** | required libraries |
| Tests | **pytest** (backend/ML), **Vitest** + Testing Library (frontend) | both suites run offline |
| Packaging | **Docker Compose** + nginx | one-command full stack |

---

## 6. Dataset — CICIDS2017

**Source.** The Canadian Institute for Cybersecurity *Intrusion Detection Evaluation Dataset*
(CICIDS2017) — 5 days of labelled traffic (CICFlowMeter flow features), published by UNB.
The pipeline downloads the eight per-day files from the public mirror
`https://huggingface.co/datasets/bvsam/cic-ids-2017` (the original UNB download host is frequently
unreachable; both are configured in `ml/cicids_config.py`). The raw capture is **not** redistributed
here — only derived, cleaned tables and small samples.

**Measured at build time** (from `ml/artifacts/dataset_stats.json`, regenerated on every build):

| Property | Value |
| --- | --- |
| Raw rows in the 8 files | **2 830 743** |
| Raw columns (incl. `Label`) | 79 |
| Rows dropped (NaN / ±∞) | 2 867 |
| Duplicate rows within batches | 142 733 |
| Rows kept after cleaning + sampling | **217 731** (`data/processed/cicids2017_subset.parquet`) |
| Model features | **70** |
| Target classes | 9 |

**Class distribution** — full capture vs. training table:

| Class | Full capture | Training table |
| --- | ---: | ---: |
| Normal Traffic | 2 271 320 | 118 240 |
| DoS | 251 712 | 29 292 |
| Port Scanning | 158 804 | 26 911 |
| DDoS | 128 025 | 30 000 |
| Brute Force | 13 832 | 9 150 |
| Web Attack | 2 180 | 2 143 |
| Bot | 1 956 | 1 948 |
| Infiltration | 36 | 36 |
| Heartbleed | 11 | 11 |

**Labelling.** CICIDS2017 ships 15 raw strings (`BENIGN`, `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`,
`DoS Slowhttptest`, `DDoS`, `PortScan`, `FTP-Patator`, `SSH-Patator`, `Web Attack – Brute Force`,
`Web Attack – XSS`, `Web Attack – Sql Injection`, `Bot`, `Infiltration`, `Heartbleed`). They are
folded into the 9 classes above by `cicids_config.LABEL_TO_ATTACK_TYPE`, e.g. `DoS Hulk` → `DoS`,
`SSH-Patator`/`FTP-Patator` → `Brute Force`, `Web Attack – SQL Injection` → `Web Attack`.

**Cleaning & sampling** (`ml/build_dataset.py`, streaming, RAM-safe):
- header whitespace/BOM canonicalised; a duplicated `Fwd Header Length_duplicated_0` column unifies;
- `±∞` replaced with `NaN`, rows containing `NaN` dropped;
- exactly constant columns removed (8 of them: `Bwd PSH Flags`, `Bwd URG Flags`, the four
  `* Avg …/Bulk` columns) → 78 features remain before variance filtering;
- **stratified reservoir sampling** caps the giant classes (Normal 120 000, DoS/PortScan/DDoS 30 000,
  every other attack family 20 000 — the small families are kept in full) so the table trains on a
  laptop. Class priors therefore differ from the raw capture; this is documented in
  `model_metadata.json` and is one reason the reported accuracy is a *lab-split* number.

Full-dataset statistics (rows, per-column min/max/mean/std/missing for all 79 columns) are computed
while streaming and stored in `dataset_stats.json`, which is what the **Dataset Explorer** shows as
the "CICIDS2017 (reference)" dataset.

---

## 7. Machine-learning model

**Algorithm (fixed by requirement): `RandomForestClassifier`, scikit-learn 1.6.1.**

| Hyper-parameter | Value |
| --- | --- |
| `n_estimators` | 100 |
| `min_samples_leaf` | 2 |
| `max_depth` | `None` |
| `random_state` | 42 (also splits the train/test data) |
| `n_jobs` | −1 (all cores) |

`min_samples_leaf=2` is a deliberate **footprint** choice: fully grown default trees made the joblib
artifact ≈ 1 GB, which is unnecessary for a project of this size. Re-run
`python ml/train_model.py --no-size-guard` if you want the unconstrained trees (and ~1 GB of disk).

**Training / evaluation** (`ml/train_model.py`):

| Item | Value |
| --- | --- |
| Training table | 217 731 rows × 70 features |
| Split | 70 / 30 stratified → 152 411 train / 65 320 test |
| Test accuracy | **0.9959430496** |
| Macro F1 | 0.981756 |
| Weighted F1 | 0.995943 |
| Model file | `random_forest_model.joblib` (4.34 MB) |
| Weakest classes | Infiltration recall 0.8182, Bot recall 0.9521 (28 of 585 Bot test flows → Normal) |

Per-class precision/recall/F1/support, the full 9×9 confusion matrix and the exact evaluation
timestamp live in `ml/artifacts/evaluation.json` and are rendered by the **AI Model** page — the
frontend reads them from the API, it never hard-codes them.

**Artifacts produced** (written to `ml/artifacts/`, mirrored into `backend/app/ml/`):

| File | Contents |
| --- | --- |
| `random_forest_model.joblib` | the fitted Random Forest |
| `feature_columns.json` | the **70 feature names in exact training order** |
| `label_mapping.json` | `class_index`, `index_to_class`, `normal_class`, `detailed_label_to_category` |
| `preprocessing_config.json` | imputation medians, inf-handling, coverage rule, canonicalisation |
| `model_metadata.json` | model card: algorithm, hyper-parameters, dataset provenance, splits, limitations |
| `evaluation.json` | accuracy, macro/weighted F1, per-class report, confusion matrix, disclaimer |
| `feature_importance.json` | Gini importances + method label |
| `label_codes.json` | target encoding used by the training table |
| `dataset_stats.json` | full-capture statistics + sampling config |
| `class_profiles.json` | per-class feature profiles (median / mean / p95 / normal-ratio) |
| `sample_traffic.csv`, `simulation_stream.csv` | 1 500 / 800 held-out flows shipped to the UI |

**How the model is used at runtime.** `backend/app/services/ml_service.py` loads the joblib artifact
and the JSON contracts **once** during FastAPI startup (≈0.8 s) via `joblib.load`; there is no
training, fitting or label-encoding code in the request path, and the API refuses to start with a
clear error if an artifact is missing.

---

## 8. Inference contract (strict feature handling)

Uploaded files are **never** fed to the model blindly. `preprocessing_service.py` enforces the exact
training-time contract:

1. **Read safely** — CSV/TSV/TXT/Parquet, size cap (`MAX_UPLOAD_SIZE`, default 25 MB) and row cap
   (`MAX_ROWS_PER_JOB`, default 200 000), separator auto-detected with explicit-separator fallback.
2. **Canonicalise names** — BOM, stray whitespace and the `Fwd Header Length_duplicated_0` artefact
   from CICIDS2017 are normalised so `Destination Port` and `"Destination Port"` are the same column.
3. **Match against `feature_columns.json`** — the file must cover ≥ **80%** (`MIN_FEATURE_COVERAGE`)
   of the 70 expected features. If not, the API returns `400` with the *matched*, *expected*,
   *missing*, *coverage*, *required coverage* and a human-readable hint — the same check runs at
   upload time, so an unusable file never reaches the database.
4. **Impute, don't invent** — expected columns that are absent are filled with the training medians
   from `preprocessing_config.json` **and reported back** in `imputed_features`. Columns that are
   not part of the training design are ignored (never silently added to the feature vector).
5. **Reorder exactly** — the matrix handed to `predict_proba` is built in `feature_columns.json`
   order, as a DataFrame carrying the training feature names, so scikit-learn cannot mis-align
   columns and cannot warn about unseen feature names.
6. **Drop, don't guess** — `±∞ → NaN`; rows containing NaN after imputation are dropped and counted
   in the job diagnostics (`invalid_rows`), never scored with a fabricated value.
7. **Label handling** — a `Label`/`Attack Type` column, when present, is captured as ground truth for
   optional scoring and is **excluded from the feature vector**. The model never sees it.

Any deviation from this path is a bug, not a configuration option.

---

## 9. Risk scoring & alert rules

Risk levels are **documented and deterministic** — the same rules power the UI, the alerts and the
`/api/alerts/rules` endpoint, so the documentation cannot drift from the implementation.

```
risk_score = attack_severity_weight[predicted_class] × confidence  (+ port bonus)

port bonus  = 0.05 per flow whose destination port is sensitive, capped at 0.10
              (sensitive = 21, 22, 23, 25, 110, 135, 139, 143, 445, 993, 995, 1433, 1521,
               2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017)

risk_score ≥ 0.96 → CRITICAL
risk_score ≥ 0.85 → HIGH
risk_score ≥ 0.65 → MEDIUM
otherwise         → LOW
```

| Predicted class | Severity weight |
| --- | ---: |
| Infiltration | 1.00 |
| Heartbleed | 0.98 |
| DDoS | 0.95 |
| Bot | 0.92 |
| Web Attack | 0.88 |
| Brute Force | 0.86 |
| DoS | 0.80 |
| Port Scanning | 0.72 |
| *any unknown class* | 0.75 |
| Normal Traffic | — (never scored as an attack) |

**Design consequences (deliberate):**
- **Normal traffic is always LOW.** Its score only records model uncertainty
  (`(1 − confidence) × 0.4`) so the value is still meaningful to sort by, but a normal flow can never
  produce an alert.
- **Not everything is CRITICAL.** Port Scanning — by far the most common alert in the sample data —
  tops out at `0.72 × confidence + 0.10 = 0.82`, i.e. HIGH at best. CRITICAL requires a
  high-severity family *and* near-certain confidence (e.g. Bot at 99% on a sensitive port → 0.969).
- **Alerts are raised for MEDIUM and above only**, and a burst cannot flood the queue. Qualifying
  flows are processed highest-risk first; the first flow of each `(attack type, destination port)`
  pair creates that pair's alert and every further flow of the pair is folded into it
  (`occurrences=N`, worst severity kept, `prediction_id` = the pair's highest-risk record). There is
  **exactly one alert per pair per job**, and at most 300 pairs own an alert (the remainder folds into
  one overflow alert per attack type), so a 1 000-flow port sweep becomes a handful of rows instead of
  1 000 notifications. Alert status workflow: `new → reviewed → resolved`.
  *Measured on the bundled 1 500-flow sample:* 593 suspicious flows → **160 alerts = 160 pairs**
  (155 MEDIUM, 4 HIGH, 1 CRITICAL), zero duplicates, largest groups `DDoS:80` with 183 flows and
  `DoS:80` with 166 flows.
- The rules are returned by `GET /api/alerts/rules` and rendered in the Alerts page, so the UI never
  paraphrases them.

---

## 10. Explainability (XAI)

Two genuinely computed layers — no template text is ever presented as an explanation:

- **Global importance** — `RandomForestClassifier.feature_importances_` (mean Gini decrease) over all
  100 trees, shipped in `feature_importance.json`, charted on the *AI Model* page ("Top Model
  Features") and always labelled as **model-level** importance.
- **Per-record attribution** — **TreeSHAP** (`shap.TreeExplainer`) computed on demand for a single
  record. The record inspector's **Why?** tab shows the base value, the predicted class probability
  and the signed contribution of each feature (a waterfall chart plus a table), which is what makes
  the verdict auditable rather than asserted.
- **Honest fallback** — if SHAP cannot attribute a record (library missing, class without support,
  batch size above `SHAP_MAX_RECORDS`), the API sets `method: "global_feature_importance"` and the UI
  says *"model-level importance — not a per-record explanation"*. It never dresses global importance
  up as a personal explanation.
- The LLM layer is explicitly forbidden from adding evidence: it receives only the structured SHAP
  output, risk factors and ground truth, and its prompt instructs it to explain *those* numbers.

---

## 11. AI Security Assistant

The assistant panel (bottom-right, available on every page) answers questions such as
*"why random forest?"*, *"how is risk calculated?"*, *"what are the alerts?"*, *"which attack is most
common?"*, *"give me a summary"* — always from **live database and model metadata**.

- **No key required.** With `AI_PROVIDER=none` (the default) a deterministic local engine composes the
  answer from real numbers: it queries `/api/dashboard` aggregations, the model card, the alert rules
  and the prediction rows it is allowed to see.
- **Optional LLM.** Set `AI_PROVIDER=openai` (or any OpenAI-compatible endpoint: Groq, Together,
  Ollama, …), `AI_API_KEY` and `AI_BASE_URL` and the same structured facts are passed to the model
  for a more conversational explanation. The call is made **server-side only** — the key never
  reaches the browser, and the response reports which provider produced it
  (`/api/assistant/status` → `provider`, `mode`, `api_key_configured`).
- **Grounded or silent.** Every answer carries the machine-readable facts it was built from
  (`facts` + `sources`, plus `evidence` on request — "which attack is most common?" returns the real
  counts, `DDoS 183 / Port Scanning 170 / DoS 170 / …`), and when the database holds no detections
  yet the assistant answers **"no detection data available"** instead of inventing a scenario.
  Out-of-scope questions are refused by intent routing.
- Evidence is returned alongside the prose (`flow`, `model_output`, `risk`, `feature_drivers`,
  `ground_truth`, `limitations`) so the user can check the claim.

---

## 12. Live Traffic Simulation

What it **is**: a browser-driven replay of held-out CICIDS2017 flows streamed from the backend over
**Server-Sent Events** (`GET /api/live/stream?rows=25&sample=simulation_stream`). Each flow is scored
by the real model and pushed to the UI as an event (`start` → `flow` × N → `done`), where it animates
the live feed, the per-second counters and the risk mix.

What it **is not**: it is *not* packet capture, it does not touch a network interface, and no
privileged sniffer is involved. The page header, the event stream and the API description all say
**"Live Traffic Simulation — replaying held-out CICIDS2017 flows"**, and the UI shows that label
verbatim so nobody can mistake it for live monitoring.

Real packet capture is deliberately out of scope for this build. If it is ever added it belongs in a
separate, explicitly enabled module (see [Future improvements](#23-future-improvements)) — the
streaming contract (`start`/`flow`/`done`) was designed so such a producer could be plugged in
without changing the UI.

---

## 13. Installation

### Prerequisites

| Requirement | Version used | Notes |
| --- | --- | --- |
| Python | 3.11 – 3.13 (built on 3.13.14) | 3.13 needs `shap ≥ 0.52` (pinned in requirements) |
| Node.js | 18+ (built on 20.20.2) | npm 10+ |
| PostgreSQL | 13+ (16 in compose) | **optional** — the default dev DB is SQLite, zero setup |
| Docker + Compose | optional | only for the containerised stack |
| Disk / RAM | ~1.5 GB / 2 GB | the training parquet is 25 MB, the model 4.34 MB |

### Option A — the one-command path (recommended)

```bash
git clone <your-fork-url> ai-nids
cd ai-nids
npm install      # installs frontend deps and prepares the Python environment
npm run dev      # starts API + dashboard and prints the URLs
```

That is the whole setup. The first run takes a couple of minutes (it builds `.venv` and downloads
the Python wheels); every run after that starts in a few seconds.

If you skipped `npm install`, `npm run dev` will notice the missing dependencies and install them
for you before starting — the only hard requirement is that Node and Python exist on your PATH.

### Option B — manual, if you prefer to see every step

```bash
git clone <your-fork-url> ai-nids
cd ai-nids
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into JWT_SECRET

python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

cd backend && python -m uvicorn app.main:app --reload --port 8000    # terminal 1
cd frontend && npm install && npm run dev                            # terminal 2
```

The first API start creates the database (SQLite by default), seeds the demo accounts, loads the
model and prints the measured accuracy it read from `evaluation.json`. `http://localhost:8000/docs`
opens the interactive API.

### Demo accounts (seeded on first start)

| Role | Email | Password | Can do |
| --- | --- | --- | --- |
| Analyst | `analyst@ainids.dev` | `Analyst@123` | upload, analyse, inspect, acknowledge alerts, ask the assistant |
| Admin | `admin@ainids.dev` | `Admin@1234` | everything above + user management, system info, delete datasets |

Change or disable them with `SEED_DEMO_DATA=false` (and the `DEMO_*` variables) before a real
deployment.

---

## 14. Environment variables

All variables live in `.env` (template: `.env.example`). **No secret is ever committed**; the
frontend receives none of them.

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_NAME` / `APP_VERSION` | `AI-NIDS` / `1.0.0` | shown in `/api/health` and the UI |
| `ENVIRONMENT` | `development` | `development` \| `production` (tightens logging/errors) |
| `LOG_LEVEL` | `INFO` | `DEBUG`…`ERROR` |
| `DATABASE_URL` | `sqlite:///./data/ainids.db` | SQLAlchemy URL; compose injects PostgreSQL |
| `DB_ECHO` | `false` | echo SQL (debugging only) |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `5` / `10` | connection pool (PostgreSQL) |
| `JWT_SECRET` | `change-me-…` | **must be replaced**; signs access tokens |
| `JWT_ALGORITHM` | `HS256` | token algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | token lifetime |
| `PASSWORD_MIN_LENGTH` | `8` | enforced on user creation/change |
| `MODEL_PATH` | `backend/app/ml/random_forest_model.joblib` | serialized Random Forest |
| `FEATURE_COLUMNS_PATH` | `backend/app/ml/feature_columns.json` | the 70 features, in order |
| `LABEL_MAPPING_PATH` | `backend/app/ml/label_mapping.json` | class index ↔ class name |
| `PREPROCESSING_CONFIG_PATH` | `backend/app/ml/preprocessing_config.json` | imputation medians, coverage rule |
| `MODEL_METADATA_PATH` / `EVALUATION_PATH` | `backend/app/ml/model_metadata.json` / `evaluation.json` | model card + measured metrics |
| `FEATURE_IMPORTANCE_PATH` | `backend/app/ml/feature_importance.json` | global importances |
| `DATASET_STATS_PATH` | `backend/app/ml/dataset_stats.json` | full-capture reference statistics |
| `MAX_UPLOAD_SIZE` | `26214400` (25 MB) | hard upload cap, enforced in middleware |
| `MAX_ROWS_PER_JOB` | `200000` | rows scored per analysis job |
| `SYNC_ANALYSIS_ROW_LIMIT` | `2000` | files up to this size respond inline instead of queueing a job |
| `STORE_PREDICTIONS_LIMIT` | `50000` | predictions persisted per job (keeps the DB lean) |
| `SHAP_MAX_RECORDS` | `2000` | cap for batch SHAP explanation |
| `JOB_WORKERS` | `2` | background analysis threads |
| `RATE_LIMIT_ENABLED` | `true` | master switch for rate limiting |
| `RATE_LIMIT_LOGIN` | `10/minute` | login attempts per IP |
| `RATE_LIMIT_PREDICT` | `30/minute` | analysis endpoints |
| `RATE_LIMIT_UPLOAD` | `20/minute` | upload endpoints |
| `RATE_LIMIT_DEFAULT` | `300/minute` | everything else |
| `CORS_ORIGINS` | `http://localhost:5173,…` | comma-separated allow-list |
| `CORS_ALLOW_ORIGIN_REGEX` | e2b/localhost pattern | extra origin regex for preview hosts |
| `AI_PROVIDER` | `none` | `none` \| `openai` \| `ollama` (any OpenAI-compatible endpoint) |
| `AI_API_KEY` | *(empty)* | server-side only; never sent to the browser |
| `AI_MODEL` | `gpt-4o-mini` | model name for the provider |
| `AI_BASE_URL` | `https://api.openai.com/v1` | provider base URL |
| `AI_TIMEOUT_SECONDS` / `AI_MAX_TOKENS` | `30` / `700` | provider call limits |
| `SEED_DEMO_DATA` | `true` | seed demo users + bootstrap analysis on first boot |
| `DEMO_USER_EMAIL` / `DEMO_USER_PASSWORD` | `analyst@ainids.dev` / `Analyst@123` | analyst account |
| `DEMO_ADMIN_EMAIL` / `DEMO_ADMIN_PASSWORD` | `admin@ainids.dev` / `Admin@1234` | admin account |

Optional compose-only variables: `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_PORT`,
`BACKEND_PORT`, `FRONTEND_PORT`.

---

## 15. Database setup

**Development (default).** `DATABASE_URL=sqlite:///./data/ainids.db` — tables are created at startup
and `data/ainids.db` is created on first run. Delete the file to start over (the demo seed runs again).

**PostgreSQL (compose / production).** `docker compose up` starts PostgreSQL 16 with
`POSTGRES_DB/USER/PASSWORD` (default `ainids/ainids/ainids`) and passes
`postgresql+psycopg2://…@postgres:5432/ainids` to the backend. To use your own server:

```bash
createdb ainids
export DATABASE_URL="postgresql+psycopg2://user:password@localhost:5432/ainids"
```

**Tables** (SQLAlchemy 2.0 models in `backend/app/models/database_models.py`; all access through the
ORM, so there is no hand-built SQL anywhere in the codebase):

| Table | Key columns | Feeds |
| --- | --- | --- |
| `users` | id, email (unique), password_hash (bcrypt), role, is_active, last_login_at | auth, admin panel |
| `datasets` | id, filename, stored_path, rows, columns, size_bytes, source, feature_coverage, missing_values, duplicate_rows, profile (JSON) | Dataset Explorer |
| `analysis_jobs` | id, dataset_id → datasets, status, progress, stage, total_rows, processed_rows, error, summary (JSON), model_version, timings | Traffic Analyzer progress + job history |
| `predictions` | id, job_id → analysis_jobs, record_index, prediction, is_attack, confidence, risk_level, risk_score, source/destination ip+port, flow_duration, packet stats, features (JSON), ground_truth | Prediction Results, record inspector, SHAP input |
| `alerts` | id, prediction_id → predictions, job_id, attack_type, severity, status, message, confidence, risk_score, source_ip, destination_port, notes (`occurrences=N`) | Alerts Center, dashboard |
| `detection_statistics` | bucket_start, total, normal, suspicious, low/medium/high/critical, alerts | cached dashboard timeline/aggregates |
| `audit_logs` | id, user_id, action, resource, detail (JSON), ip, created_at | admin traceability |

---

## 16. ML model setup

The repository already contains a trained model, so **nothing has to be trained to run the app**.
This section is for regenerating it or training your own.

```bash
# 0) optional - refresh the raw CICIDS2017 mirror (~257 MB) into /tmp/cicids2017
python ml/build_dataset.py --download          # streams the 8 parquet files from the HF mirror

# 1) build the cleaned, sampled training table + full-capture statistics
python ml/build_dataset.py                     # → data/processed/cicids2017_subset.parquet
                                               #   ml/artifacts/label_codes.json
                                               #   ml/artifacts/dataset_stats.json   (2.8 M-row stats)

# 2) train, evaluate and export every artifact + the demo samples
python ml/train_model.py                       # → ml/artifacts/*  + backend/app/ml/*
                                               #   + frontend/public/samples/*.csv
python ml/build_profiles.py                    # → class_profiles.json (per-class feature profiles)
```

Useful flags: `--no-size-guard` (default fully grown trees, ≈1 GB), `--n-estimators N`,
`--test-size 0.3`, `--seed 42`. Training the 217 731-row table takes ≈40 s on 2 cores; the full
2.8 M-row capture needs ≥ 8 GB RAM and is not required.

The **Dataset Explorer** reports statistics for the *entire* 2.83 M-row capture (computed while
streaming, not from the sampled table), which is why the reference dataset card shows far more rows
than the training table.

---

## 17. Running the application

### Everyday development

```bash
npm run dev            # from the repository root (or from frontend/ — same result)
```

You get both servers with prefixed logs:

```
▸ starting the API…
[api] model loaded: Random Forest classes=9 features=70 in 0.9s
✓ API ready on http://localhost:8000
▸ starting the dashboard…
[web] VITE v6.4.3  ready in 229 ms
╭──────────────────────────────────────────╮
│ AI-NIDS is running                       │
│ dashboard   http://localhost:5173        │
│ API docs    http://localhost:8000/docs   │
│ sign in     analyst@ainids.dev / Analyst@123 │
╰──────────────────────────────────────────╯
```

Useful environment overrides for the launcher: `AINIDS_API_PORT`, `AINIDS_WEB_PORT`,
`AINIDS_PYTHON` (pick a specific interpreter). Hot reload works on both sides — edit a React file
and the browser updates instantly; edit a Python file and restart with `Ctrl+C`, `npm run dev`.

### Manual / two-terminal mode

```bash
cd backend && python -m uvicorn app.main:app --reload --port 8000     # terminal 1
cd frontend && npm run dev:vite                                      # terminal 2 (UI only)
```

`frontend/npm run dev` starts the *whole* stack via the root launcher; `dev:vite` is the UI-only
script used by the launcher itself.

### Docker Compose (full stack)

### Production notes

- Run behind TLS; set `ENVIRONMENT=production`, a real `JWT_SECRET`, and restrict `CORS_ORIGINS`.
- `uvicorn --workers 1` is intentional: analysis jobs live in an in-process worker pool. To scale
  horizontally, point `JOB_WORKERS` at a shared queue (see Future improvements).
- `docker compose -f docker-compose.yml up -d` on a single VM is the intended deployment for this
  project; `/api/health/live` is the liveness probe, `/api/health` the readiness probe.

---

## 18. API reference

Base URL `http://localhost:8000/api` · interactive docs `/docs` · schema `/openapi.json`.
Every route below requires `Authorization: Bearer <token>` except `/api/health*`, `/api/auth/login`
and `/api/auth/config`. 44 routes in total (including the `/` banner).

### auth

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/auth/login` | public | email + password → JWT (rate limited 10/min per IP) |
| POST | `/auth/logout` | any | records the logout; the client drops the token |
| GET | `/auth/me` | any | current user |
| GET | `/auth/config` | public | login screen config (does it show demo accounts?) |
| GET | `/auth/users` | admin | list users |
| POST | `/auth/users` | admin | create user (role, password policy enforced) |

### datasets

| Method | Path | Description |
| --- | --- | --- |
| POST | `/datasets/upload` | upload CSV/TSV/TXT/Parquet (type, size, schema and row checks) |
| POST | `/datasets/sample` | register a bundled held-out sample (`sample_traffic`, `simulation_stream`) |
| GET | `/datasets` | list datasets with row/coverage summary |
| GET | `/datasets/reference` | full CICIDS2017 reference statistics (real build output) |
| GET | `/datasets/{id}` | dataset profile + preview |
| GET | `/datasets/{id}/rows` | server-side paginated rows for the Explorer (`page`, `page_size`) |
| GET | `/datasets/{id}/download` | download the stored file |
| DELETE | `/datasets/{id}` | delete dataset + file (admin) |

### predictions

| Method | Path | Description |
| --- | --- | --- |
| POST | `/predictions/analyze` | run the model over a registered dataset (queues a job above 2 000 rows) |
| POST | `/predictions/analyze/upload` | upload + analyse in one call |
| POST | `/predictions/simulate` | score N sample flows sequentially (use `persist=false` to keep the DB clean) |
| GET | `/predictions/jobs` | recent jobs with status/progress |
| GET | `/predictions/jobs/{id}` | job detail: stage, progress %, summary, ground-truth metrics |
| GET | `/predictions` | stored predictions: `search`, `attack_type`, `risk_level`, `sort`, `page`, `page_size` |
| GET | `/predictions/{id}` | one flow: stored features, risk rationale, alerts, `?with_shap=true` |
| GET | `/predictions/{id}/explain` | grounded explanation (local engine or configured LLM) |

### alerts

| Method | Path | Description |
| --- | --- | --- |
| GET | `/alerts` | filters: severity, status, attack type, search, pagination |
| GET | `/alerts/summary` | counters by severity/status for the Alerts Center |
| GET | `/alerts/rules` | the risk + alert-grouping rules actually used |
| GET | `/alerts/{id}` | alert detail incl. the linked prediction |
| PATCH | `/alerts/{id}` | `new → reviewed → resolved`, optional note |

### dashboard · model · assistant · live · health

| Method | Path | Description |
| --- | --- | --- |
| GET | `/dashboard/stats` | 6 metric cards + verdict/risk/attack distributions (window: `hours`) |
| GET | `/dashboard/timeline` | hourly traffic series (cached `detection_statistics` rollup) |
| GET | `/dashboard/recent-alerts` | latest alerts for the dashboard table |
| GET | `/dashboard/alerts-summary` | severity/status counters |
| GET | `/model/info` | model card: algorithm, hyper-parameters, dataset, splits, accuracy label |
| GET | `/model/features` | `model.feature_importances_` (top-N) — "Top Model Features" |
| GET | `/model/evaluation` | per-class report + 9×9 confusion matrix from the held-out split |
| GET | `/model/architecture` | pipeline stages with real dimensions |
| GET | `/model/class-profiles` | per-class feature medians/p95 used as explanation evidence |
| POST | `/assistant/ask` | grounded Q&A (`question`, `include_evidence`) |
| GET | `/assistant/status` | provider, mode, whether a key is configured |
| GET | `/live/samples` | replay samples available for the simulation |
| GET | `/live/stream` | SSE: `start` → `flow`×N → `done` (also accepts `?token=` for EventSource) |
| GET | `/health`, `/health/live`, `/health/system` | readiness, liveness, admin system info |

**Example — upload and analyse**

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@ainids.dev","password":"Analyst@123"}' | jq -r .access_token)

DS=$(curl -s -X POST localhost:8000/api/datasets/upload -H "Authorization: Bearer $TOKEN" \
  -F file=@frontend/public/samples/sample_traffic.csv | jq -r .id)

curl -s -X POST localhost:8000/api/predictions/analyze -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{\"dataset_id\":\"$DS\"}" | jq '.summary.metrics'
```

```jsonc
// POST /api/predictions/analyze  → 200 (excerpt of a real run: 1 500 held-out flows)
{
  "job": { "id": "…", "status": "completed", "progress": 100, "stage": "completed" },
  "summary": {
    "processed": 1500,
    "suspicious_records": 603,
    "risk_distribution": { "low": 907, "medium": 337, "high": 251, "critical": 5 },
    "attack_distribution": { "DDoS": 183, "DoS": 170, "Port Scanning": 170, "Brute Force": 50,
                             "Web Attack": 17, "Bot": 13 },
    "ground_truth": { "labelled_rows": 1500, "match_rate": 0.996,
      "binary": { "true_positive": 599, "true_negative": 896, "false_positive": 4,
                  "false_negative": 1, "precision": 0.993367, "recall": 0.998333,
                  "f1": 0.995844 } }
  }
}
```

---

## 19. Testing

### Backend + ML — `pytest` (67 tests, all green)

```bash
cd backend
python -m pytest                       # or: python -m pytest tests/test_predictions.py -v
```

| Module | Tests | What it covers |
| --- | ---: | --- |
| `test_auth.py` | 12 | login/JWT shape, wrong password, unknown email, garbage token, protected routes, analyst vs admin, weak-password rejection, user creation, logout revocation, public auth config |
| `test_datasets.py` | 14 | valid upload, wrong extension, empty file, unparseable file, incompatible columns (with structured error), reordered columns, imputation path, listing, profile + paginated rows, reference-dataset paging fallback, 404s, reference dataset, sample registration, admin-only delete |
| `test_predictions.py` | 9 | synchronous analysis summary, ground-truth scoring, job detail, server-side filters, sorting + pagination, record detail with explanation, 404, AI explanation on real evidence, `simulate` persistence flag |
| `test_alerts.py` | 7 | alert creation, flood control (one alert per attack/port pair), the no-duplicate-pair invariant checked over the whole database, summary ↔ list agreement, documented rules, triage PATCH, dashboard aggregates |
| `test_model_api.py` | 8 | model card, reported accuracy equals `evaluation.json`, importances sum to 1 and are ordered, per-class report + confusion matrix, architecture, class profiles, health, admin-only system info |
| `test_ml_pipeline.py` | 10 | **feature order enforced**, deterministic column reordering, refusal to predict on a misordered matrix, normalised probabilities, missing features rejected with detail, low coverage rejected, unknown extra columns ignored, ±∞ cleaned, non-flow files rejected, labels never used as features |
| `test_middleware.py` | 7 | rate-limit grammar and blocking, instrumentation headers, security headers, auth-before-404, login rate-limit headers, no internal leakage in errors |

The suite configures its own environment (`tests/conftest.py` points `DATABASE_URL` at a throw-away
SQLite file, disables the AI provider) so it never touches your development data.

### Frontend — `vitest` + Testing Library (10 tests)

```bash
cd frontend
npm run test          # or: npx vitest run
npx tsc --noEmit      # strict type-check
npm run build         # production build
```

Covers the API client (auth header injection, 401 → login redirect, error normalisation), the
formatters/colour maps and the login page rendering.

### What is *not* covered by tests

Live provider calls for `AI_PROVIDER=openai` (no key in CI), Docker image builds, and true
concurrent load. These are documented as manual checks in `docs/TESTING.md`.

---

## 20. Demo script

A 5-minute walkthrough that exercises every requirement (all numbers below are the real measured
values from the bundled held-out sample):

1. **Login** — open `http://localhost:5173`, sign in as `analyst@ainids.dev` / `Analyst@123`
   (the login screen fills the demo credentials from `/api/auth/config`).
2. **Dashboard** — the six metric cards, verdict pie, traffic timeline, attack-type bars, risk mix
   and recent-alerts table are all backed by `/api/dashboard/*`; the bootstrap analysis of the
   1 500-flow sample is already visible (603 suspicious flows, 160 alerts grouped from 593)
3. **Analyze traffic** — click *Use sample dataset* → *Analyze*: watch `reading → preprocessing →
   model inference → risk scoring → persisting → alerts` with a live percentage, then the summary
   (per-class distribution, average confidence, timing, model block, ground-truth score).
4. **Incompatibility path** — drag any non-network CSV (e.g. a spreadsheet export): the upload is
   rejected with *matched / expected / missing / coverage* detail instead of a vague failure; a CSV
   with 10 of the 70 feature columns is accepted and the imputed features are listed.
5. **Detections → Flagged flows** — search, filter by attack type/risk, sort by confidence, paginate
   server-side, open any attack row → **Why?** shows TreeSHAP contributions for that record
   (base value, predicted probability, signed per-feature impact) and the AI explanation tab.
6. **Detections → Alert queue** — severity/status counters, filters, the documented rules panel
   (`GET /api/alerts/rules`), open an alert → linked prediction, then triage it to *reviewed*.
   Point out that a port sweep produces **one aggregated alert with `occurrences=N`** instead of
   thousands of rows, and that Port Scanning cannot reach CRITICAL by construction.
7. **Data → Datasets** — the 2.83 M-row CICIDS2017 reference card next to your uploads, per-column
   statistics and server-side row paging (never the full dataset in the browser).
8. **AI model → Model & metrics** — model card (algorithm, hyper-parameters, dataset provenance, measured accuracy
   with its disclaimer), *Top Model Features* chart from `feature_importances_`, the per-class
   evaluation table and the 9×9 confusion matrix, the pipeline diagram and per-class profiles.
9. **Data → Live simulation** — start the SSE feed: the header says *"Live Traffic Simulation —
   replaying held-out CICIDS2017 flows"*, flows stream in one by one with risk/attack counters, and
   *Simulate & store* persists a run so it appears on the dashboard.
10. **AI Security Assistant** — ask *"why random forest?"*, *"how is risk calculated?"*,
    *"which attack is most common?"*: every answer cites the real numbers it used
    (`facts` / `sources`), and with an empty database it says *"no detection data available"*.
11. **Settings / admin** — as `admin@ainids.dev` / `Admin@1234`: user management, system info
    (`/api/health/system`), dataset deletion.
12. **API docs** — `http://localhost:8000/docs` for the full OpenAPI surface.

---

## 21. Security notes

| Control | Implementation |
| --- | --- |
| Password storage | bcrypt hashes (`app/core/security.py`); plaintext passwords are never stored, logged or returned |
| Authentication | signed JWT (`HS256`, `JWT_SECRET`), expiry via `ACCESS_TOKEN_EXPIRE_MINUTES`, revoked on logout |
| Authorisation | role checks on every privileged route (`get_current_admin`), verified by tests (analyst → 403) |
| Transport of the token | `Authorization: Bearer`, plus `?token=` **only** on the SSE endpoint (EventSource cannot set headers) — scoped to `/api/live/*` |
| Input validation | Pydantic v2 schemas on every request body/query; structured 422 responses |
| SQL injection | SQLAlchemy ORM queries only — no string-built SQL anywhere |
| Uploads | extension allow-list (.csv/.txt/.tsv/.parquet/.pq), `MAX_UPLOAD_SIZE` byte cap, row cap, filename sanitising, files stored under generated UUID names inside `data/uploads` |
| Rate limiting | per-IP, per-route sliding window (login 10/min, uploads 20/min, analysis 30/min) with `Retry-After` and `X-RateLimit-*` headers |
| CORS | explicit origin allow-list (`CORS_ORIGINS`) plus an optional regex for preview hosts; no `*` with credentials |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP, HSTS in production |
| Request logging | method, path, status, duration, request id, user id — **never** bodies, passwords or tokens; `Authorization` values are redacted |
| Error hygiene | handled errors return safe messages with a request id; stack traces stay in the server logs |
| Secrets | all secrets come from `.env`/environment (`.env` is git-ignored, `.env.example` holds placeholders); the AI key is used server-side only |
| Container hardening | backend runs as a non-root user, nginx serves static assets read-only, healthchecks on both images |
| Scope | defensive only — the project classifies traffic handed to it; there is no scanning, exploitation or payload generation code |

---

## 22. Known limitations

1. **Dataset age & origin.** CICIDS2017 is a 2017 lab capture. Traffic from 2018+ is out of
   distribution and the reported accuracy is a lab-split number, not a field guarantee.
2. **Not every attack can be detected.** Only the 9 trained classes exist; unknown attack families are
   either mapped to a known family or reported as normal traffic. Nothing here claims universal
   detection.
3. **Training subset.** Class priors differ from the raw capture (see §6); the model saw 217 731 of
   2 827 876 cleaned flows.
4. **CICIDS2017 label noise.** Labels come from the attack schedule, not manual review; published
   analyses put realistically usable accuracy well below 100%.
5. **Live Traffic Simulation is a replay.** It streams held-out CICIDS2017 flows; it is *not* packet
   capture and does not touch a network interface. Real capture would need a separate module (see §23).
6. **No PCAP support.** Flows must already be in CICFlowMeter/CICIDS2017 column format — the model
   cannot consume raw packets.
7. **Batch SHAP cap.** Per-record explanations are computed on demand; above `SHAP_MAX_RECORDS`
   (2 000) the API returns model-level importance and says so instead of pretending.
8. **Job execution is in-process.** Analysis jobs run in a thread pool, so the API is intended as a
   single-node deployment (compose `--workers 1`); horizontal scaling needs a shared queue.
9. **Small classes.** Infiltration (36 rows) and Heartbleed (11 rows) have very few examples, so their
   per-class metrics are noisy and their handling is best-effort.
10. **SQLite default.** Dev builds use SQLite; concurrent write-heavy analysis should use PostgreSQL
    (compose does).
11. **LLM explanations are optional and non-authoritative.** With `AI_PROVIDER=none` (default) they are
    deterministic and local; an external provider adds cost, latency and a data-sharing decision.
12. **No user-level data partitioning.** All authenticated users can see all datasets; only
    destructive and administrative actions are role-gated.

---

## 23. Future improvements

- **Optional live capture module** (explicitly separated): Zeek/Suricata/NFStream flow exporter →
  the existing `start`/`flow`/`done` SSE contract, gated behind `CAPTURE_ENABLED=false` by default and
  documented as requiring elevated privileges. The simulation stays the default demo path.
- **Queue-based job workers** (RQ/Celery + Redis, already an optional compose profile) so analysis
  scales beyond one process and survives API restarts.
- **Scheduled retraining + model registry**: version artifacts, keep per-version evaluation, promote
  with a drift check; the DB already records `model_version` per job.
- **Drift and performance monitoring**: PSI/KS per feature against `class_profiles.json`, alert when
  input distributions shift.
- **Optional model comparison module** (explicitly separate, never a silent swap): fit XGBoost/
  LightGBM/MLP on the same table and compare per-class metrics on the held-out split, keeping Random
  Forest as the primary detector.
- **Alert delivery**: webhooks/e-mail/Slack with severity routing and deduplication windows.
- **PCAP → flow extraction** in the ML pipeline so raw captures can be analysed.
- **Stronger auth**: refresh tokens, SSO/OIDC, per-user rate limits, audit-log UI.
- **Per-row SHAP for whole jobs** stored in the background (cost/benefit depends on volume).
- **Observability**: Prometheus metrics, OpenTelemetry traces, Grafana dashboards.
- **Packaging**: Kubernetes/Helm chart, GitHub Actions CI (pytest + vitest + image build + Trivy).

---

## 24. Troubleshooting

| Symptom | Cause & fix |
| --- | --- |
| `Model artifact not found: …random_forest_model.joblib` | artifacts missing. Run `python ml/train_model.py`, or point `MODEL_PATH` at your model. The API refuses to start without it — it never falls back to a random/untrained model. |
| `Address already in use` on 8000/5173 | another process holds the port: `lsof -i :8000` or change `--port` / `FRONTEND_PORT`. |
| Browser shows CORS errors | add your origin to `CORS_ORIGINS` (comma separated) and restart the API. |
| Upload rejected with *"Invalid file format"* | only `.csv/.txt/.tsv/.parquet/.pq` are accepted; re-export the file as CSV. |
| Upload rejected with *missing features* | the file is not CICIDS2017-compatible; the response lists exactly which columns are missing and the required coverage. |
| `429 Too Many Requests` while testing | rate limiting is doing its job; wait for `Retry-After` or raise `RATE_LIMIT_*` (disable with `RATE_LIMIT_ENABLED=false` for a local demo). |
| Dashboard empty after a fresh clone | the bootstrap analysis only runs on an empty database with `SEED_DEMO_DATA=true`; register a sample dataset and analyse it once, or delete `data/ainids.db` and restart. |
| Analysis stays at `queued` | the worker pool is busy (`JOB_WORKERS`, default 2) — check `/api/predictions/jobs` and the API logs. |
| SHAP explanation shows "model-level importance" | that record exceeded the SHAP budget or SHAP is unavailable — this is the documented, labelled fallback. |
| Chinese/mojibake labels in a raw CICIDS2017 CSV | the original files contain encoding artefacts; `ml/build_dataset.py` normalises them — re-run the build instead of hand-editing. |
| `sqlite3.OperationalError: database is locked` | delete the dev DB while the API is running, or use PostgreSQL for concurrent writes. |
| `npm run dev` says Python was not found | install Python 3.11–3.13 and make sure `python`/`python3` is on PATH (Windows: tick *Add python.exe to PATH*), or set `AINIDS_PYTHON` to the interpreter. |
| First `npm run dev` takes a while | that is the one-time dependency install (`.venv` + npm packages). Later runs start in seconds. |
| Ports 8000/5173 already busy | the launcher reuses whatever is already listening; to force a different pair use `AINIDS_API_PORT=8010 AINIDS_WEB_PORT=5180 npm run dev`. |
| Old bookmark opens the wrong page | legacy paths redirect automatically (`/alerts` → `/detections?tab=alerts` and friends); no action needed. |

---

## 25. Credits & references

- **CICIDS2017** — I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, *"Toward Generating a New Intrusion
  Detection Dataset and Intrusion Traffic Characterization"*, ICISSP 2018 (Canadian Institute for
  Cybersecurity, University of New Brunswick). Mirror used for automated downloads:
  `https://huggingface.co/datasets/bvsam/cic-ids-2017`.
- **scikit-learn** — Pedregosa et al., *"Scikit-learn: Machine Learning in Python"*, JMLR 12 (2011).
- **SHAP** — S. M. Lundberg, S.-I. Lee, *"A Unified Approach to Interpreting Model Predictions"*,
  NeurIPS 2017.
- **FastAPI**, **SQLAlchemy**, **Pydantic**, **React**, **Vite**, **Tailwind CSS**, **Recharts**,
  **Lucide** — see `backend/requirements.txt` and `frontend/package.json` for exact versions.

Built as an academic project: Machine Learning + Cybersecurity + Full-Stack + Explainable AI + a
grounded AI explanation layer, on real data, with no fabricated results. Defensive use only.
