"""
Prediction API - the ML endpoints.

* ``POST /analyze``            analyse an already-registered dataset
* ``POST /analyze/upload``     upload + register + analyse in one call
* ``GET  /jobs`` / ``/jobs/{id}``  background job progress ("Processing 42%...")
* ``GET  /``                   filter / search / sort / paginate stored results
* ``GET  /{id}``               full record inspection + TreeSHAP explanation
* ``GET  /{id}/explain``       AI/grounded explanation of a single detection
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import get_current_user
from app.db.session import session_scope, get_db
from app.models.database_models import Dataset, User
from app.models.schemas import AnalyzeRequest, JobOut, PredictionPage, SimulateRequest
from app.services import ai_explanation_service, dataset_service, prediction_service
from app.services.ml_service import ModelUnavailableError
from app.services.preprocessing_service import DatasetError

router = APIRouter(prefix="/predictions", tags=["predictions"])
logger = get_logger("ainids.api.predictions")


def _analyze(db: Session, dataset: Dataset, user: User | None, force_sync: bool = False) -> dict:
    if not dataset.stored_path:
        raise HTTPException(status_code=409, detail="This dataset has no stored file to analyse.")

    row_estimate = dataset.rows or 0
    synchronous = force_sync or row_estimate <= settings.SYNC_ANALYSIS_ROW_LIMIT

    if synchronous and row_estimate <= 20_000:
        job = prediction_service.create_job(db, dataset, user.id if user else None)
        job.status = "running"
        job.stage = "running"
        db.commit()
        try:
            summary = prediction_service.run_analysis(db, job, dataset, user_id=user.id if user else None)
        except DatasetError as exc:
            job.status, job.stage, job.error = "failed", "failed", exc.message
            db.commit()
            raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, **exc.detail}) from exc
        except ModelUnavailableError as exc:
            job.status, job.stage, job.error = "failed", "failed", str(exc)
            db.commit()
            raise HTTPException(status_code=503, detail={"message": str(exc)}) from exc
        db.refresh(job)
        return {"mode": "sync", "job": job.to_dict(), "summary": summary}

    job = prediction_service.create_job(db, dataset, user.id if user else None)
    prediction_service.submit_job(job.id)
    return {
        "mode": "async",
        "job": job.to_dict(),
        "message": "Analysis queued. Poll /api/predictions/jobs/{job_id} for progress.",
    }


@router.post("/analyze", summary="Run the Random Forest over a registered dataset")
def analyze(
    payload: AnalyzeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    dataset = db.get(Dataset, payload.dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return _analyze(db, dataset, user, force_sync=payload.force_sync)


@router.post("/analyze/upload", summary="Upload a CSV and analyse it in one step")
async def analyze_upload(
    file: UploadFile = File(...),
    force_sync: bool = Query(True),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    try:
        path, size = dataset_service.save_upload(raw, file.filename or "upload.csv")
        dataset = dataset_service.register_dataset(
            db,
            filename=file.filename or path.name,
            stored_path=path,
            size_bytes=size,
            user_id=user.id,
        )
        result = _analyze(db, dataset, user, force_sync=force_sync)
    except DatasetError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, **exc.detail}) from exc
    result["dataset"] = dataset.to_dict()
    return result


@router.get("/jobs", summary="Recent analysis jobs")
def jobs(
    limit: int = Query(25, ge=1, le=100),
    mine: bool = False,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return {"items": prediction_service.list_jobs(db, limit=limit, user_id=user.id if mine else None)}


@router.get("/jobs/{job_id}", response_model=JobOut, summary="Job progress / result summary")
def job_detail(job_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    data = prediction_service.job_overview(db, job_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    return data


@router.get("", response_model=PredictionPage, summary="Stored predictions (filter/sort/paginate)")
def list_predictions(
    job_id: str | None = None,
    dataset_id: str | None = None,
    verdict: str = Query("all", pattern="^(all|attack|normal|high_risk|critical)$"),
    attack_type: str | None = None,
    risk_level: str | None = None,
    min_confidence: float | None = Query(None, ge=0.0, le=1.0),
    search: str | None = None,
    sort_by: str = Query("record_index", pattern="^(record_index|confidence|risk_score|risk_level|prediction|created_at)$"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return prediction_service.list_predictions(
        db,
        job_id=job_id,
        dataset_id=dataset_id,
        verdict=verdict,
        attack_type=attack_type,
        risk_level=risk_level,
        min_confidence=min_confidence,
        search=search,
        sort_by=sort_by,
        sort_dir=sort_dir,
        page=page,
        page_size=page_size,
    )


@router.get("/{prediction_id}", summary="Inspect one flow (features, risk, SHAP explanation)")
def prediction_detail(
    prediction_id: str,
    shap: bool = Query(True, description="Compute per-record TreeSHAP values"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    payload = prediction_service.prediction_detail(db, prediction_id, with_shap=shap)
    if payload is None:
        raise HTTPException(status_code=404, detail="Prediction not found.")
    return payload


@router.get("/{prediction_id}/explain", summary="AI/grounded explanation of a detection")
def explain(
    prediction_id: str,
    force_local: bool = Query(False, description="Skip the external LLM even if configured"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    payload = prediction_service.prediction_detail(db, prediction_id, with_shap=True)
    if payload is None:
        raise HTTPException(status_code=404, detail="Prediction not found.")
    evidence = ai_explanation_service.build_prediction_evidence(
        payload,
        payload.get("explanation"),
        ground_truth=payload.get("ground_truth"),
    )
    if payload.get("explanation") is None:
        evidence["note_on_drivers"] = (
            "SHAP was unavailable for this record, so feature drivers come from global "
            "feature importance and training-median deviations."
        )
    result = ai_explanation_service.explain(evidence, force_local=force_local)
    result["prediction_id"] = prediction_id
    result["explanation_method"] = payload.get("explanation_method")
    result["explanation_label"] = payload.get("explanation_label")
    return result


@router.post("/simulate", summary="Process sample flows sequentially (live-simulation helper)")
def simulate(
    payload: SimulateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Non-streaming variant of the live simulation: returns the N records."""
    from app.services.live_service import simulate_rows

    return simulate_rows(
        db, rows=payload.rows, sample=payload.sample, persist=payload.persist, user_id=user.id
    )
