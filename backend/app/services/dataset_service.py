"""
Dataset service - safe storage, profiling and preview of uploaded traffic files.

Uploads are validated (extension, size, parseability) and profiled once on
upload so the Dataset Explorer and the analyzer can work without re-reading the
whole file. Only a bounded preview is ever loaded for the browser.
"""

from __future__ import annotations

import re
import shutil
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.middleware.security_middleware import validate_upload_filename
from app.models.database_models import Dataset
from app.services import preprocessing_service
from app.services.preprocessing_service import (
    DatasetError,
    load_schema,
    match_features,
    profile_dataframe,
    read_traffic_file,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.database_models import DatasetVersion
    from app.services.config_service import RuntimeConfig

logger = get_logger("ainids.datasets")

PREVIEW_ROWS = 5000
SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "public" / "samples"
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

# tiny LRU so the explorer does not re-parse the file on every page request
_preview_cache: "OrderedDict[str, pd.DataFrame]" = OrderedDict()
_CACHE_MAX = 3


def _safe_filename(name: str) -> str:
    cleaned = SAFE_NAME.sub("_", Path(name).name)
    return cleaned[:120] or "upload.csv"


def _assert_schema_compatible(columns: list[str], schema) -> None:
    """Raise DatasetError when a file cannot be scored by the current model."""
    matched, missing = match_features(columns, schema)
    coverage = len(matched) / max(len(schema.feature_columns), 1)

    if not matched:
        raise DatasetError(
            "This dataset is incompatible with the current model because required "
            "network-flow features are missing.",
            400,
            {
                "matched_features": 0,
                "expected_features": len(schema.feature_columns),
                "missing_features": missing[:25],
                "coverage": 0.0,
                "required_coverage": schema.min_feature_coverage,
                "hint": "Upload a CICIDS2017-compatible network-flow CSV (MachineLearningCVE "
                        "feature set) or export flows with the same feature names.",
            },
        )
    if coverage < schema.min_feature_coverage:
        raise DatasetError(
            "This dataset is incompatible with the current model because required "
            f"network-flow features are missing (matched {len(matched)} of "
            f"{len(schema.feature_columns)} expected features, "
            f"{coverage * 100:.1f}% coverage).",
            400,
            {
                "matched_features": len(matched),
                "expected_features": len(schema.feature_columns),
                "missing_features": missing[:25],
                "coverage": round(coverage, 4),
                "required_coverage": schema.min_feature_coverage,
                "hint": "Ensure the export uses the CICIDS2017 MachineLearningCVE column names "
                        "(see docs/DATA.md). Column order does not matter.",
            },
        )


def register_dataset(
    db: Session,
    *,
    filename: str,
    stored_path: Path,
    size_bytes: int,
    user_id: str | None,
    source: str = "upload",
    status_ok: str = "ready",
) -> Dataset:
    """Profile a stored traffic file and persist its Dataset row."""
    schema = load_schema()
    df = read_traffic_file(stored_path, max_rows=PREVIEW_ROWS)
    profile = profile_dataframe(df, schema)

    # Fail fast: a file that does not match the trained feature schema is rejected
    # here with the same structured message the analysis step would produce, so the
    # user learns about the incompatibility before queueing a job.
    _assert_schema_compatible(df.columns.tolist(), schema)

    dataset = Dataset(
        filename=filename,
        stored_path=str(stored_path),
        uploaded_by=user_id,
        rows=profile["rows"],
        columns=profile["columns"],
        size_bytes=size_bytes,
        status=status_ok,
        source=source,
        target_column=profile["target_column"],
        attack_categories=sorted(profile["class_distribution"].keys()),
        missing_values=profile["missing_values"],
        duplicate_rows=profile["duplicate_rows"],
        numerical_columns=profile["numerical_columns"],
        categorical_columns=profile["categorical_columns"],
        feature_coverage=profile["feature_coverage"],
        schema_matched=profile["feature_coverage"] >= 0.5,
        columns_meta=profile["columns_meta"],
        class_distribution=profile["class_distribution"],
        sample_rows=_sample_rows(df),
    )
    db.add(dataset)
    db.commit()
    db.refresh(dataset)
    _cache_preview(dataset.id, df)
    logger.info(
        "dataset registered: %s (%d rows x %d cols, coverage %.2f)",
        dataset.filename,
        dataset.rows,
        dataset.columns,
        dataset.feature_coverage or 0.0,
    )
    return dataset


def save_upload(file_bytes: bytes, filename: str, runtime=None) -> tuple[Path, int]:
    """Validate and persist raw upload bytes to disk."""
    size = len(file_bytes)
    error = validate_upload_filename(filename, size, runtime=runtime)
    if error:
        raise DatasetError(error, 400)

    safe = _safe_filename(filename)
    target = settings.upload_dir / f"{uuid.uuid4().hex[:8]}_{safe}"
    target.write_bytes(file_bytes)

    # cheap structural sanity check: the file must parse as delimited text
    try:
        preview = target.read_bytes()[:4096].decode("utf-8", errors="ignore")
        if not preview.strip():
            target.unlink(missing_ok=True)
            raise DatasetError("The uploaded dataset contains no records.")
        if "," not in preview and ";" not in preview and "\t" not in preview and target.suffix.lower() not in {".parquet", ".pq"}:
            target.unlink(missing_ok=True)
            raise DatasetError(
                "Invalid file format. Please upload a CSV file with a header row and "
                "comma-separated network-flow records."
            )
    except DatasetError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        target.unlink(missing_ok=True)
        raise DatasetError("Invalid file format. Please upload a CSV file.") from exc
    return target, size


def register_builtin_sample(db: Session, sample: str, user_id: str | None) -> Dataset:
    """Register one of the bundled held-out demo CSVs as a dataset."""
    available = {
        "sample_traffic": SAMPLE_DIR / "sample_traffic.csv",
        "simulation_stream": SAMPLE_DIR / "simulation_stream.csv",
    }
    path = available.get(sample)
    if path is None or not path.exists():
        raise DatasetError(
            "The built-in sample dataset is not available on this server. "
            "Run `python ml/train_model.py` to generate frontend/public/samples.",
            404,
        )
    target = settings.upload_dir / f"sample_{sample}.csv"
    shutil.copy2(path, target)
    dataset = register_dataset(
        db,
        filename=f"{sample}.csv (CICIDS2017 held-out sample)",
        stored_path=target,
        size_bytes=target.stat().st_size,
        user_id=user_id,
        source="sample",
    )

    # Version 1 of the sample so an admin can promote it to a training candidate
    # and every future change is attributable.
    _record_sample_version(db, dataset, version=1, note="Initial registration of the held-out sample.")
    db.commit()
    return dataset


def _record_sample_version(
    db: Session, dataset: Dataset, *, version: int = 1, note: str | None = None
) -> "DatasetVersion":
    from app.models.database_models import DatasetVersion

    row = DatasetVersion(
        dataset_id=dataset.id,
        version=version,
        rows=dataset.rows,
        columns=dataset.columns,
        size_bytes=dataset.size_bytes,
        columns_meta=dataset.columns_meta,
        target_classes=dataset.attack_categories,
        class_distribution=dataset.class_distribution,
        note=note,
        created_by=dataset.uploaded_by,
    )
    db.add(row)
    db.flush()
    return row


def sample_file(path_name: str) -> Path | None:
    path = SAMPLE_DIR / path_name
    return path if path.exists() else None


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #
def list_datasets(db: Session, page: int = 1, page_size: int = 20, search: str | None = None) -> dict:
    stmt = select(Dataset)
    if search:
        stmt = stmt.where(func.lower(Dataset.filename).like(f"%{search.lower()}%"))
    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    rows = db.scalars(
        stmt.order_by(Dataset.created_at.desc()).offset(max(page - 1, 0) * page_size).limit(page_size)
    ).all()
    return {
        "items": [d.to_dict() for d in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


def dataset_detail(db: Session, dataset_id: str) -> Dataset | None:
    return db.get(Dataset, dataset_id)


def record_version(
    db: Session,
    dataset: Dataset,
    *,
    note: str | None = None,
    created_by: str | None = None,
) -> "DatasetVersion":
    """
    Snapshot the current file of ``dataset`` as a new immutable version row.

    Used when a file is replaced or promoted, so an admin can see what the
    training run of a given week actually consumed.
    """
    from app.models.database_models import DatasetVersion

    latest = db.scalar(
        select(DatasetVersion)
        .where(DatasetVersion.dataset_id == dataset.id)
        .order_by(DatasetVersion.version.desc())
        .limit(1)
    )
    version = (latest.version + 1) if latest else 1
    row = DatasetVersion(
        dataset_id=dataset.id,
        version=version,
        rows=dataset.rows,
        columns=dataset.columns,
        size_bytes=dataset.size_bytes,
        columns_meta=dataset.columns_meta,
        target_classes=dataset.attack_categories,
        class_distribution=dataset.class_distribution,
        note=note,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    return row


def list_versions(db: Session, dataset_id: str) -> list[dict]:
    from app.models.database_models import DatasetVersion

    rows = db.scalars(
        select(DatasetVersion)
        .where(DatasetVersion.dataset_id == dataset_id)
        .order_by(DatasetVersion.version.desc())
    ).all()
    return [row.to_dict() for row in rows]


def _cache_preview(dataset_id: str, df: pd.DataFrame) -> None:
    _preview_cache[dataset_id] = df
    _preview_cache.move_to_end(dataset_id)
    while len(_preview_cache) > _CACHE_MAX:
        _preview_cache.popitem(last=False)


def dataset_rows(
    dataset: Dataset,
    page: int = 1,
    page_size: int = 50,
    verdict: str | None = None,
    search: str | None = None,
    sort_by: str | None = None,
    sort_dir: str = "asc",
) -> dict:
    """
    Server-side paginated preview of a dataset (bounded to PREVIEW_ROWS rows -
    the browser never receives a whole 197k-row file).
    """
    source = "stored_file"
    note: str | None = None

    if dataset.stored_path:
        path = Path(dataset.stored_path)
    elif dataset.source == "reference":
        # The full CICIDS2017 capture is never stored in this deployment, so the
        # explorer pages through the bundled held-out sample instead of pretending
        # the whole 2.83 M-row file is available - and says so in `note`.
        path = SAMPLE_DIR / "sample_traffic.csv"
        source = "reference_sample"
        note = (
            f"Statistics on this page describe the full {dataset.rows:,}-row CICIDS2017 capture, "
            "which is not stored locally. The rows below come from the bundled 1 500-flow held-out "
            "sample that ships with the project."
        )
        if not path.exists():
            raise DatasetError(
                "The reference sample file is missing. Run `python ml/train_model.py` to regenerate "
                "frontend/public/samples.",
                404,
            )
    else:
        raise DatasetError("This dataset has no stored file to page through.", 409)

    df = _preview_cache.get(dataset.id)
    if df is None:
        df = read_traffic_file(path, max_rows=PREVIEW_ROWS)
        _cache_preview(dataset.id, df)

    total_rows_available = int(df.shape[0])
    work = df

    if search:
        needle = search.lower()
        mask = work.astype(str).apply(lambda col: col.str.lower().str.contains(needle, na=False))
        work = work[mask.any(axis=1)]
    if sort_by and sort_by in work.columns:
        work = work.sort_values(sort_by, ascending=(sort_dir == "asc"), kind="stable")

    total = int(work.shape[0])
    start = max(page - 1, 0) * page_size
    page_frame = work.iloc[start : start + page_size]
    return {
        "columns": [str(c) for c in df.columns],
        "items": _records(page_frame),
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "preview_limit": PREVIEW_ROWS,
        "preview_truncated": dataset.rows > total_rows_available,
        "dataset_rows": dataset.rows,
        "source": source,
        "note": note,
    }


def _sample_rows(df: pd.DataFrame, n: int = 5) -> list[dict]:
    return _records(df.head(n))


def _records(frame: pd.DataFrame) -> list[dict]:
    """JSON-safe row records."""
    safe = frame.copy()
    for col in safe.columns:
        if pd.api.types.is_float_dtype(safe[col]):
            safe[col] = safe[col].astype(object).where(safe[col].notna(), None)
    return safe.replace({float("inf"): None, float("-inf"): None}).to_dict(orient="records")


def delete_dataset(db: Session, dataset_id: str) -> bool:
    dataset = db.get(Dataset, dataset_id)
    if dataset is None:
        return False
    path = Path(dataset.stored_path) if dataset.stored_path else None
    db.delete(dataset)
    db.commit()
    _preview_cache.pop(dataset_id, None)
    if path and path.exists() and path.name.startswith(tuple("0123456789abcdef")) and "_" in path.name:
        # only delete files we created inside the uploads directory
        try:
            if path.parent == settings.upload_dir:
                path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            logger.warning("could not remove upload file %s", path)
    return True


def reference_dataset() -> dict:
    """Real statistics of the full CICIDS2017 capture, from the build step."""
    stats = preprocessing_service.load_reference_stats()
    metadata = {}
    try:
        from app.services.ml_service import model_service

        metadata = model_service.metadata
    except Exception:  # pragma: no cover
        pass
    return {
        "name": "CICIDS2017 (MachineLearningCVE)",
        "available": bool(stats),
        "full_dataset": {
            "rows": stats.get("full_dataset_rows"),
            "columns": stats.get("full_dataset_columns"),
            "source_files": stats.get("source_files", {}),
            "class_counts": stats.get("class_counts_full_dataset", {}),
            "attack_categories": sorted((stats.get("class_counts_full_dataset") or {}).keys()),
        },
        "training_table": {
            "rows": stats.get("training_rows"),
            "columns": stats.get("training_columns"),
            "class_counts": stats.get("class_counts_training_table", {}),
            "dropped_constant_columns": stats.get("dropped_constant_columns", []),
            "sampling": stats.get("sampling", {}),
        },
        "column_statistics": stats.get("columns", []),
        "target_column": stats.get("target_column", "Attack Type"),
        "generated_at": stats.get("generated_at"),
        "model": {
            "algorithm": metadata.get("algorithm"),
            "n_estimators": metadata.get("n_estimators"),
            "n_features": metadata.get("n_features"),
            "classes": metadata.get("classes", []),
        },
    }
