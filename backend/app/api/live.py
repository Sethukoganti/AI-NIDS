"""
Authenticated live simulation API (Server-Sent Events).

GET /api/live/stream  pushes one event per flow through the production pipeline.
GET /api/live/samples lists available sample files.
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.rbac import P_TRAFFIC_ANALYZE, require_permission
from app.db.session import get_db
from app.models.database_models import User
from app.services import live_service
from app.services.ml_service import ModelUnavailableError
from app.services.preprocessing_service import DatasetError

router = APIRouter(prefix="/live", tags=["live"])
logger = get_logger("ainids.api.live")


@router.get("/samples", summary="Available replay samples for the simulation")
def samples(_user: User = Depends(require_permission(P_TRAFFIC_ANALYZE))):
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
    dataset_id: str | None = None,
    user: User = Depends(require_permission(P_TRAFFIC_ANALYZE)),
    db: Session = Depends(get_db),
):
    dataset_path = None
    dataset_name = None
    if dataset_id is not None:
        try:
            dataset, dataset_path = live_service.user_dataset_path(db, dataset_id, user.id)
        except DatasetError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
        dataset_name = dataset.filename

    async def generator() -> AsyncIterator[str]:
        try:
            for item in live_service.stream_frames(
                rows=rows,
                sample=sample,
                source_path=dataset_path,
                source_name=dataset_name,
            ):
                if await request.is_disconnected():
                    logger.info("live stream client disconnected")
                    return
                yield _sse(item["event"], item["data"])
                await asyncio.sleep(0.02)
        except ModelUnavailableError as exc:
            yield _sse("error", {"message": f"ML model is currently unavailable. {exc}"})
        except Exception as exc:
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
