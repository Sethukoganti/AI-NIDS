# AI-NIDS — AI-Powered Network Intrusion Detection System

A real-time network monitor that captures live Wi-Fi/LAN traffic, scores every connection using a Random Forest model trained on CICIDS2017, and explains detected threats in plain language with concrete precautions.

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11--3.14-blue">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-0.115-009688">
  <img alt="React" src="https://img.shields.io/badge/React-18-61dafb">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5.7-3178c6">
  <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-1.6-f7931e">
  <img alt="Accuracy" src="https://img.shields.io/badge/accuracy-99.6%25-brightgreen">
</p>

---

## What it does

- **Live packet capture** — sniffs real packets from your Wi-Fi or Ethernet adapter using Npcap
- **Real-time classification** — every completed network flow is scored by a 100-tree Random Forest
- **Plain-language threat alerts** — each detection explains what the attack is and exactly what to do
- **Attack simulation** — replays real CICIDS2017 attack flows to demo detections on demand
- **Detects 8 attack types** — DoS, DDoS, Port Scanning, Brute Force, Web Attack (SQLi/XSS), Botnet, Infiltration, Heartbleed

---

## Requirements

Before running, install these:

| Requirement | Download |
|---|---|
| **Python 3.11 or higher** | https://www.python.org/downloads/ |
| **Node.js 18 or higher** | https://nodejs.org/ |
| **Npcap** (for live capture) | https://npcap.com/#download |

> **Npcap install options:** Keep all defaults. Make sure **"Install Npcap in WinPcap API-compatible Mode"** is checked.

---

## Quick start (3 steps)

### Step 1 — Install backend dependencies

Open a terminal and run:

```powershell
cd path\to\AI-NIDS\backend
pip install -r requirements.txt
```

> If you get SSL errors, add `--trusted-host pypi.org --trusted-host files.pythonhosted.org`

### Step 2 — Install frontend dependencies

Open a second terminal and run:

```powershell
cd path\to\AI-NIDS\frontend
npm install --strict-ssl=false
```

### Step 3 — Start the dashboard

**Terminal 1 (backend):**
```powershell
cd path\to\AI-NIDS\backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Terminal 2 (frontend):**
```powershell
cd path\to\AI-NIDS\frontend
npm run dev:vite
```

Then open **http://localhost:5173** in your browser.

---

## Using the dashboard

### Overview tab
Shows what the system is, the processing pipeline diagram, model details, and detected attack types.

### Live Capture tab
1. Select your network interface (Wi-Fi or Ethernet)
2. Click **"Start live capture"**
3. Real network flows appear scored as Safe (green) or a specific threat (red/orange)
4. Click **"Inject test threats (demo)"** to instantly show 4 real attack detections for presentation

### Attack Simulation tab
1. Select a sample file and number of flows
2. Click **"Run simulation"**
3. Real CICIDS2017 attack flows replay through the model — threat cards appear with explanations
4. Use this for demos when real attack traffic is not available

### AI Assistant
Click the **sparkle button** (bottom-right corner) to ask questions about the system.

---

## Demo — for presentations

Start the dashboard, go to **Live Capture**, click **Start**, then click **"Inject test threats (demo)"**. You'll see:

- 🔴 **DoS Hulk** — HTTP flood attack explanation + firewall steps
- 🟠 **Port Scanning** — reconnaissance detection + what to check
- 🔴 **DDoS** — distributed flood explanation + ISP contact steps
- 🟠 **SSH Brute Force** — login attack explanation + fail2ban recommendation

All scored by the real Random Forest using actual CICIDS2017 training data rows.

---

## Model details

| Property | Value |
|---|---|
| Algorithm | Random Forest Classifier |
| Trees | 100 estimators |
| Training dataset | CICIDS2017 (CIC, University of New Brunswick) |
| Features per flow | 70 statistical metrics |
| Test accuracy | **99.6%** on held-out test split |
| Attack classes | 8 (+ Normal Traffic) |

---

## Project structure

```
AI-NIDS/
├── backend/
│   ├── app/
│   │   ├── api/          — REST endpoints (capture, live, health, auth, etc.)
│   │   ├── ml/           — trained model artifacts (Random Forest + JSON configs)
│   │   ├── services/     — capture_service, ml_service, live_service, etc.
│   │   └── main.py       — FastAPI app entry point
│   └── capture_agent.py  — (legacy) standalone capture script
├── frontend/
│   └── src/
│       ├── pages/        — About, LiveCapture, Simulation
│       └── components/   — ThreatFeed, AI assistant, UI primitives
├── data/
│   └── processed/        — CICIDS2017 parquet subset
├── portscan_test.py       — test script to generate port scan traffic
└── README.md
```

---

## Troubleshooting

**"No module named scapy"**
```powershell
cd path\to\AI-NIDS\backend
pip install -r requirements.txt
```

**"Npcap is not installed"**
Download and install from https://npcap.com — check "WinPcap API-compatible Mode" during install, then restart the backend.

**"Permission denied" when starting live capture**
On Windows, run the backend terminal as Administrator. Live packet capture requires elevated privileges and Npcap.

**"Cannot reach the backend"**
Make sure the backend terminal shows `Uvicorn running on http://0.0.0.0:8000` before opening the browser.

**"npm: command not found"**
Install Node.js from https://nodejs.org and restart your terminal.

**SSL error during pip install**
```powershell
pip install <package> --trusted-host pypi.org --trusted-host files.pythonhosted.org
```

**Frontend shows blank page**
Hard refresh: press `Ctrl + Shift + R` in your browser.

---

## Tech stack

| Layer | Technology |
|---|---|
| ML model | scikit-learn Random Forest |
| Backend | FastAPI + Python |
| Database | SQLite (dev) |
| Frontend | React 18 + TypeScript + Vite |
| Styling | Tailwind CSS |
| Packet capture | Scapy + Npcap |
| Charts | Recharts + Lucide icons |

---

## Credits

- **Dataset**: CICIDS2017 — Canadian Institute for Cybersecurity, University of New Brunswick
- **Model**: scikit-learn RandomForestClassifier
- **Packet capture**: Scapy + Npcap (Nmap Project)
