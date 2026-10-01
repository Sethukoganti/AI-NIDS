"""Dataset API - upload, profile, explore (server-side pagination) and delete."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import get_current_user, require_admin
from app.db.session import get_db
from app.models.database_models import Dataset, User
from app.models.schemas import (
    DatasetDetailOut,
    DatasetPage,
    SampleDatasetRequest,
)
from app.services import dataset_service
from app.services.preprocessing_service import DatasetError

router = APIRouter(prefix="/datasets", tags=["datasets"])
logger = get_logger("ainids.api.datasets")


@router.post("/upload", summary="Upload a network-flow CSV/parquet dataset")
async def upload_dataset(
    file: UploadFile = File(..., description="CICIDS2017-compatible network-flow CSV"),
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
    except DatasetError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"message": exc.message, **exc.detail},
        ) from exc

    payload = dataset.to_dict(include_meta=False)
    payload["analysis_ready"] = (dataset.feature_coverage or 0) >= 0.5
    payload["message"] = (
        f"Uploaded {dataset.rows:,} rows x {dataset.columns} columns. "
        f"{round((dataset.feature_coverage or 0) * 100, 1)}% of the model's expected "
        "network-flow features were found."
    )
    return payload


@router.post("/sample", summary="Register a bundled held-out CICIDS2017 sample as a dataset")
def use_sample(
    payload: SampleDatasetRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        dataset = dataset_service.register_builtin_sample(db, payload.sample, user.id)
    except DatasetError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message}) from exc
    data = dataset.to_dict(include_meta=False)
    data["message"] = (
        f"Sample dataset ready: {dataset.rows:,} held-out CICIDS2017 flows "
        f"({dataset.class_distribution or {}})."
    )
    return data


@router.get("", response_model=DatasetPage, summary="List datasets")
def list_datasets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return dataset_service.list_datasets(db, page=page, page_size=page_size, search=search)


@router.get("/reference", summary="Full CICIDS2017 reference statistics (real, from the build step)")
def reference(user: User = Depends(get_current_user)):
    return dataset_service.reference_dataset()


@router.get("/{dataset_id}", response_model=DatasetDetailOut, summary="Dataset profile + sample rows")
def dataset_detail(
    dataset_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    dataset = dataset_service.dataset_detail(db, dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return dataset.to_dict(include_meta=True)


@router.get("/{dataset_id}/rows", summary="Server-side paginated rows for the Dataset Explorer")
def dataset_rows(
    dataset_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: str | None = None,
    sort_by: str | None = None,
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    dataset = dataset_service.dataset_detail(db, dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    try:
        return dataset_service.dataset_rows(
            dataset,
            page=page,
            page_size=page_size,
            search=search,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )
    except DatasetError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message}) from exc


@router.delete("/{dataset_id}", summary="Delete a dataset (and its stored file)")
def delete_dataset(
    dataset_id: str,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not dataset_service.delete_dataset(db, dataset_id):
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return {"deleted": True, "dataset_id": dataset_id}


@router.get("/{dataset_id}/download", summary="Download the original stored file")
def download_dataset(
    dataset_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from pathlib import Path

    from fastapi.responses import FileResponse

    dataset = dataset_service.dataset_detail(db, dataset_id)
    if dataset is None or not dataset.stored_path:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    path = Path(dataset.stored_path)
    if not path.exists() or not str(path.resolve()).startswith(str(settings.upload_dir.resolve())):
        raise HTTPException(status_code=404, detail="Stored file is no longer available.")
    return FileResponse(path, filename=dataset.filename, media_type="text/csv")
