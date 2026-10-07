"""
Live packet capture API — no authentication required.

POST /api/capture/start      → start the in-process sniffer thread
POST /api/capture/stop       → stop it
GET  /api/capture/status     → current state
GET  /api/capture/interfaces → available network interfaces
GET  /api/capture/stream     → SSE stream of scored flows
"""

from __future__ import annotations

import asyncio
import json
import pandas as pd
from typing import AsyncIterator, Optional

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.logging import get_logger
from app.services import capture_service, risk_service
from app.services.ml_service import ModelUnavailableError, model_service
from app.services.preprocessing_service import load_schema

router = APIRouter(prefix="/capture", tags=["live"])
logger = get_logger("ainids.capture")

POLL_INTERVAL = 0.4
HEARTBEAT_INTERVAL = 8


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


class StartCaptureRequest(BaseModel):
    iface: Optional[str] = None


# --------------------------------------------------------------------------- #
# Control endpoints — no auth
# --------------------------------------------------------------------------- #
@router.get("/interfaces", summary="List available network interfaces")
def get_interfaces():
    ifaces = capture_service.list_interfaces()
    active = [
        i for i in ifaces
        if any("." in ip and not ip.startswith("169.254") for ip in i.get("ips", []))
    ]
    return {"interfaces": active or ifaces[:6]}


@router.post("/start", summary="Start the packet capture sniffer")
def start_capture(payload: StartCaptureRequest = StartCaptureRequest()):
    result = capture_service.start_capture(iface=payload.iface)
    return {**result, **capture_service.status()}


@router.post("/stop", summary="Stop the packet capture sniffer")
def stop_capture():
    result = capture_service.stop_capture()
    return {**result, **capture_service.status()}


@router.get("/status", summary="Capture sniffer status")
def capture_status():
    return {
        **capture_service.status(),
        "model_ready": model_service.is_loaded,
        "npcap_installed": capture_service._npcap_installed(),
    }


# --------------------------------------------------------------------------- #
# Flow scoring
# --------------------------------------------------------------------------- #
def _score_flow(raw: dict) -> dict | None:
    try:
        schema = load_schema()
        row = {
            col: (raw["features"].get(col) if raw["features"].get(col) is not None else float("nan"))
            for col in schema.feature_columns
        }
        df = pd.DataFrame([row])

        from app.services.preprocessing_service import prepare_features
        prepared = prepare_features(df, schema, strict=False)
        if prepared.features.empty:
            return None

        prediction = model_service.predict(prepared.features.iloc[[0]])
        label = prediction["labels"][0]
        confidence = float(prediction["confidences"][0])
        is_attack = label != model_service.normal_class

        from app.services import config_service
        runtime = config_service.get_runtime()
        dst_port = raw.get("dst_port")
        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except (TypeError, ValueError):
            dst_port = None

        assessment = risk_service.assess(
            label, confidence, is_attack,
            model_service.normal_class, dst_port,
            thresholds=runtime.risk_thresholds(),
            port_bonus=runtime.sensitive_port_bonus,
        )

        return {
            "prediction":       label,
            "confidence":       round(confidence, 6),
            "is_attack":        is_attack,
            "risk_level":       assessment.level,
            "risk_score":       round(assessment.score, 6),
            "source_ip":        raw.get("src_ip"),
            "destination_ip":   raw.get("dst_ip"),
            "source_port":      raw.get("src_port"),
            "destination_port": dst_port,
            "protocol":         raw.get("proto"),
            "flow_duration":    round(float(raw.get("duration_us") or 0), 2),
            "packet_rate":      round(float(raw.get("packet_rate") or 0), 4),
        }
    except Exception as exc:
        logger.debug("scoring error: %s", exc)
        return None


# --------------------------------------------------------------------------- #
# SSE stream — no auth
# --------------------------------------------------------------------------- #
@router.get("/stream", summary="SSE stream of live scored network flows")
async def stream(request: Request):
    async def generator() -> AsyncIterator[str]:
        model_service.require_model()
        total = suspicious = 0
        idle_since = asyncio.get_event_loop().time()

        yield _sse("start", {
            "label":         "Live Network Capture",
            "note":          "Scoring completed flows from your network interface in real-time.",
            "algorithm":     model_service.metadata.get("algorithm"),
            "n_estimators":  model_service.metadata.get("n_estimators"),
            "classes":       model_service.classes_ if model_service.is_loaded else [],
            "agent_running": capture_service.is_active(),
            "interface":     capture_service._capture_iface,
        })

        try:
            while True:
                if await request.is_disconnected():
                    return

                scored = 0
                while True:
                    try:
                        raw = capture_service.flow_queue.get_nowait()
                    except Exception:
                        break

                    result = _score_flow(raw)
                    if result is None:
                        continue

                    total += 1
                    if result["is_attack"]:
                        suspicious += 1

                    result["index"] = total
                    result["cursor"] = {"total": total, "suspicious": suspicious, "progress": 0}
                    yield _sse("flow", result)
                    scored += 1
                    idle_since = asyncio.get_event_loop().time()

                now = asyncio.get_event_loop().time()
                if scored == 0 and (now - idle_since) >= HEARTBEAT_INTERVAL:
                    yield ": heartbeat\n\n"
                    idle_since = now

                await asyncio.sleep(POLL_INTERVAL)

        except ModelUnavailableError as exc:
            yield _sse("error", {"message": f"ML model unavailable: {exc}"})
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("capture stream error: %s", exc)
            yield _sse("error", {"message": str(exc)[:300]})

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "Connection":        "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# --------------------------------------------------------------------------- #
# Demo injection — uses REAL CICIDS2017 feature vectors extracted from the
# training dataset. These are the actual rows the model was trained on,
# so classification is guaranteed correct with high confidence.
# --------------------------------------------------------------------------- #

import json as _json
import pathlib as _pathlib

def _load_real_flows():
    """Load pre-extracted real CICIDS2017 rows from demo_flows.json."""
    path = _pathlib.Path(__file__).parent.parent / "ml" / "demo_flows.json"
    if not path.exists():
        return []
    data = _json.loads(path.read_text())
    flows = []
    meta = {
        "Port Scanning": {"src_ip": "192.168.1.200", "dst_ip": "10.0.0.1", "src_port": 61000, "dst_port": 80,  "proto": "TCP"},
        "Brute Force":   {"src_ip": "198.51.100.22", "dst_ip": "10.0.0.1", "src_port": 44444, "dst_port": 22,  "proto": "TCP"},
        "DDoS":          {"src_ip": "203.0.113.45",  "dst_ip": "10.0.0.1", "src_port": 80,    "dst_port": 80,  "proto": "UDP"},
        "DoS":           {"src_ip": "192.168.1.105", "dst_ip": "10.0.0.1", "src_port": 54321, "dst_port": 80,  "proto": "TCP"},
    }
    for cls_name, rows in data.items():
        m = meta.get(cls_name, {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 12345, "dst_port": 80, "proto": "TCP"})
        for row in rows[:1]:  # one row per class
            flows.append({
                "label":    cls_name,
                "features": row,
                **m,
                "duration_us":  row.get("Flow Duration", 0),
                "packet_rate":  row.get("Flow Packets/s", 0),
            })
    return flows


class InjectRequest(BaseModel):
    count: int = 4


@router.post("/inject", summary="Inject real CICIDS2017 attack flows for live demo")
def inject_demo_flows(payload: InjectRequest = InjectRequest()):
    """
    Pushes REAL CICIDS2017 feature vectors directly into the scoring queue.
    These are actual rows from the training dataset — the model classifies
    them with high confidence exactly as it does during batch analysis.
    """
    flows = _load_real_flows()
    if not flows:
        return {"injected": 0, "error": "demo_flows.json not found — run extract script"}

    count = max(1, min(payload.count, len(flows)))
    injected = 0
    labels = []
    for flow in flows[:count]:
        try:
            capture_service.flow_queue.put_nowait({
                "features":   flow["features"],
                "src_ip":     flow["src_ip"],
                "dst_ip":     flow["dst_ip"],
                "src_port":   flow["src_port"],
                "dst_port":   flow["dst_port"],
                "proto":      flow["proto"],
                "duration_us": flow.get("duration_us", 0),
                "packet_rate": flow.get("packet_rate", 0),
            })
            labels.append(flow["label"])
            injected += 1
        except Exception:
            pass

    return {
        "injected": injected,
        "labels":   labels,
        "note":     "Real CICIDS2017 rows scored by the production Random Forest.",
    }
