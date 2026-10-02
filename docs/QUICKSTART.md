# Quick start

## 1. Run it

```bash
npm install     # once
npm run dev     # always
```

Open the printed URL (`http://localhost:5173`) and sign in:

| Role | Email | Password |
| --- | --- | --- |
| Analyst | `analyst@ainids.dev` | `Analyst@123` |
| Admin | `admin@ainids.dev` | `Admin@1234` |

`npm run dev` needs only **Node 18+** and **Python 3.11–3.13**. On the first run it creates `.env` with a
generated JWT secret, builds a `.venv`, installs the Python and npm dependencies, checks the trained
model files, then starts both servers with prefixed logs (`[api]`, `[web]`). `Ctrl+C` stops both.

Already have servers running? The launcher reuses them instead of starting duplicates, so a second
`npm run dev` is harmless. Want different ports?

```bash
AINIDS_API_PORT=8010 AINIDS_WEB_PORT=5180 npm run dev
```

## 2. Take the tour (2 minutes)

1. **Overview** — the three "start here" cards mirror the only three things you need: analyse, review,
   replay. Metric numbers animate in as they load.
2. **Analyze traffic → Use sample dataset → Analyze** — a progress bar walks through
   `reading → preprocessing → model inference → risk scoring → persisting → alerts`, then shows the
   summary (603 suspicious of 1 500 flows, 160 alerts, ground-truth agreement 99.6%).
3. **Detections → Flagged flows** — open any row, then the **Why?** tab: real TreeSHAP values for that
   flow, plus the risk rule that produced the level.
4. **Detections → Alert queue** — one alert per (attack, port) pair with `occurrences=N`; open the
   Rules panel to read the exact scoring formula that is running.
5. **AI model** — measured accuracy, 9×9 confusion matrix, top model features. **AI insights** holds
   the model-grounded commentary.
6. **Data → Live simulation** — stream a held-out attack feed flow-by-flow (labelled as a replay, not
   packet capture). **Data → Datasets** shows the 2.83 M-row CICIDS2017 reference card.
7. **Assistant** (bottom-right bubble) — ask "which attack is most common?" and it answers from the
   live database.

## 3. Other commands

| Command | Purpose |
| --- | --- |
| `npm run test` | backend `pytest` + frontend `vitest` |
| `npm run train` | regenerate the Random Forest artifacts (optional) |
| `npm run build` | production dashboard build |
| `npm run reset` | delete the local DB + uploads (demo data re-seeds on next start) |
| `npm run setup` | re-run the install checks without starting anything |

## 4. If something goes wrong

* **"Python was not found"** — install Python 3.11–3.13 and ensure it is on PATH, or point
  `AINIDS_PYTHON=/path/to/python` at it.
* **"model artifacts are missing"** — run `npm run train` (about a minute) and retry.
* **Login shows "Too many requests"** — the login limiter is 10/minute per IP; wait a minute or
  raise `RATE_LIMIT_LOGIN` in `.env`.
* **Empty dashboard** — `npm run reset` then `npm run dev` re-seeds the demo dataset and analysis.
