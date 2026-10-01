"""
Live simulation API (Server-Sent Events).

``GET /api/live/stream`` pushes one event per flow through the production
pipeline so the dashboard updates without polling.  EventSource-style clients
that cannot set headers may authenticate with ``?token=<jwt>`` (the auth
middleware accepts this for ``/api/live/*`` only).
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.core.logging import get_logger
from app.core.security import get_current_user
from app.services import live_service
from app.services.ml_service import ModelUnavailableError

router = APIRouter(prefix="/live", tags=["live"])
logger = get_logger("ainids.api.live")


@router.get("/samples", summary="Available replay samples for the simulation")
def samples(user=Depends(get_current_user)):
    return {
        "samples": live_service.available_samples(),
        "disclaimer": (
            "Live Traffic Simulation replays real, held-out CICIDS2017 flow records one at a "
            "time. It does not capture packets from a network interface."
        ),
    }


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@router.get("/stream", summary="SSE stream of simulated flow detections")
async def stream(
    request: Request,
    rows: int = Query(120, ge=1, le=2000),
    sample: str = Query("simulation_stream.csv"),
):
    async def generator() -> AsyncIterator[str]:
        try:
            for item in live_service.stream_frames(rows=rows, sample=sample):
                if await request.is_disconnected():
                    logger.info("live stream client disconnected")
                    return
                yield _sse(item["event"], item["data"])
                await asyncio.sleep(0.02)  # pace the stream so the UI can animate it
        except ModelUnavailableError as exc:
            yield _sse("error", {"message": f"ML model is currently unavailable. {exc}"})
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("live stream failed: %s", type(exc).__name__)
            yield _sse("error", {"message": str(exc)[:300]})

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
