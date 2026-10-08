"""
Live Traffic Simulation service.

IMPORTANT (honesty): this does **not** capture packets from a network interface.
It replays held-out CICIDS2017 records or a user's uploaded network-flow dataset
one at a time through the production pipeline (preprocess -> Random Forest ->
risk engine). ``docs/ARCHITECTURE.md`` describes the optional packet-capture
front-end that would replace the replay source.
"""

from __future__ import annotations

import math
import time
from pathlib import Path

import pandas as pd
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.database_models import Dataset
from app.services import dataset_service, risk_service
from app.services.ml_service import model_service
from app.services.preprocessing_service import DatasetError, load_schema, prepare_features, read_traffic_file

logger = get_logger("ainids.live")

DEFAULT_SAMPLE = "simulation_stream.csv"


def available_samples() -> list[dict]:
    samples = []
    for name in ("sample_traffic.csv", "simulation_stream.csv"):
        path = dataset_service.sample_file(name)
        if path is None:
            continue
        rows = sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore")) - 1
        samples.append(
            {
                "name": name,
                "label": "Held-out CICIDS2017 flows" if "sample" in name else "Simulation stream",
                "rows": max(rows, 0),
                "size_bytes": path.stat().st_size,
                "source": "held-out 30% CICIDS2017 test split (never used for training)",
            }
        )
    return samples


def user_dataset_path(db: Session, dataset_id: str, user_id: str) -> tuple[Dataset, Path]:
    dataset = db.get(Dataset, dataset_id)
    if dataset is None or dataset.uploaded_by != user_id or not dataset.stored_path:
        raise DatasetError("Dataset not found.", 404)

    path = Path(dataset.stored_path).resolve()
    try:
        path.relative_to(settings.upload_dir.resolve())
    except ValueError as exc:
        raise DatasetError("Stored dataset is unavailable.", 404) from exc
    if not path.is_file():
        raise DatasetError("Stored dataset is unavailable.", 404)
    return dataset, path


def _load(sample: str, rows: int, source_path: Path | None = None) -> pd.DataFrame:
    if source_path is None:
        # accept both "simulation_stream" and "simulation_stream.csv"
        if not sample.endswith(".csv"):
            sample = f"{sample}.csv"
        source_path = dataset_service.sample_file(sample)
        if source_path is None:
            raise DatasetError(
                "The simulation sample file is missing. Run `python ml/train_model.py` to generate "
                "frontend/public/samples.",
                404,
            )
    df = read_traffic_file(source_path, max_rows=rows)
    if df.empty:
        raise DatasetError("The selected simulation dataset contains no records.")
    return df


def simulate_rows(
    db: Session,
    rows: int = 50,
    sample: str = DEFAULT_SAMPLE,
    persist: bool = False,
    user_id: str | None = None,
    dataset_id: str | None = None,
    runtime=None,
) -> dict:
    """Run N flows through the full pipeline and return the per-flow results."""
    from app.services import alert_service, config_service

    runtime = runtime or config_service.runtime_snapshot(db)
    uploaded_dataset = None
    uploaded_path = None
    if dataset_id is not None:
        if user_id is None:
            raise DatasetError("Dataset not found.", 404)
        uploaded_dataset, uploaded_path = user_dataset_path(db, dataset_id, user_id)

    if persist:
        dataset = uploaded_dataset or dataset_service.register_builtin_sample(
            db, "simulation_stream" if "simulation" in sample else "sample_traffic", user_id
        )
        from app.models.database_models import AnalysisJob
        from app.services import prediction_service

        job = prediction_service.create_job(db, dataset, user_id)
        summary = prediction_service.run_analysis(
            db, job, dataset, user_id=user_id, source="simulation", runtime=runtime
        )
        db.commit()
        records = prediction_service.list_predictions(db, job_id=job.id, page=1, page_size=min(rows, 200))
        alerts = alert_service.list_alerts(db, job_id=job.id, page=1, page_size=200)
        return {
            "persisted": True,
            "processed": summary["total_records"],
            "job": job.to_dict(),
            "summary": summary,
            "records": records["items"],
            "alerts": alerts["items"],
            "effective_configuration": runtime.to_dict(),
        }

    frame = _load(sample, rows, source_path=uploaded_path)
    schema = load_schema()
    prepared = prepare_features(frame, schema, strict=True)
    thresholds = runtime.risk_thresholds()
    results = []
    started = time.perf_counter()

    for i in range(len(prepared.features)):
        row = prepared.features.iloc[[i]]
        prediction = model_service.predict(row)
        label = prediction["labels"][0]
        confidence = float(prediction["confidences"][0])
        is_attack = label != model_service.normal_class
        dest_port = _value(prepared.row_meta.get("destination_port"), i)
        assessment = risk_service.assess(
            label,
            confidence,
            is_attack,
            model_service.normal_class,
            dest_port,
            thresholds=thresholds,
            port_bonus=runtime.sensitive_port_bonus,
        )
        results.append(
            {
                "index": i,
                "prediction": label,
                "confidence": round(confidence, 6),
                "is_attack": is_attack,
                "risk_level": assessment.level,
                "risk_score": round(assessment.score, 6),
                "destination_port": int(dest_port) if dest_port is not None and not math.isnan(dest_port) else None,
                "flow_duration": _value(prepared.features["Flow Duration"], i),
                "packet_rate": _value(prepared.features["Flow Packets/s"], i),
                "packet_length_mean": _value(prepared.features["Packet Length Mean"], i),
                "ground_truth": prepared.ground_truth[i],
            }
        )

    suspicious = [r for r in results if r["is_attack"]]
    return {
        "persisted": False,
        "sample": uploaded_dataset.filename if uploaded_dataset else sample,
        "processed": len(results),
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "summary": {
            "total_records": len(results),
            "normal_records": len(results) - len(suspicious),
            "suspicious_records": len(suspicious),
            "risk_distribution": _count(results, "risk_level"),
            "attack_distribution": _count(suspicious, "prediction"),
        },
        "records": results,
        "alerts": [],
        "effective_configuration": runtime.to_dict(),
    }


def stream_frames(
    rows: int = 200,
    sample: str = DEFAULT_SAMPLE,
    runtime=None,
    source_path: Path | None = None,
    source_name: str | None = None,
):
    """
    Generator used by the SSE endpoint: yields one event dict per flow so the
    dashboard can update live without reloading anything.
    """
    from app.services import config_service

    runtime = runtime or config_service.get_runtime()
    frame = _load(sample, rows, source_path=source_path)
    schema = load_schema()
    prepared = prepare_features(frame, schema, strict=True)
    total = len(prepared.features)
    thresholds = runtime.risk_thresholds()

    yield {
        "event": "start",
        "data": {
            "total": total,
            "sample": source_name or sample,
            "algorithm": model_service.metadata.get("algorithm"),
            "n_estimators": model_service.metadata.get("n_estimators"),
            "classes": model_service.classes_ if model_service.is_loaded else [],
            "label": (
                f"Live Traffic Simulation ({source_name})"
                if source_name
                else "Live Traffic Simulation (replaying held-out CICIDS2017 flows)"
            ),
            "note": (
                "Uploaded network-flow records are being analyzed; this is not a packet-capture feed."
                if source_name
                else "Records are replayed from the held-out dataset sample - this is not a "
                     "packet-capture feed."
            ),
            "detection_sensitivity": runtime.detection_sensitivity,
            "status": runtime.status,
        },
    }

    cumulative = {"total": 0, "suspicious": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    attacks: dict[str, int] = {}

    for i in range(total):
        row = prepared.features.iloc[[i]]
        prediction = model_service.predict(row)
        label = prediction["labels"][0]
        confidence = float(prediction["confidences"][0])
        is_attack = label != model_service.normal_class
        dest_port = _value(prepared.row_meta.get("destination_port"), i)
        assessment = risk_service.assess(
            label,
            confidence,
            is_attack,
            model_service.normal_class,
            dest_port,
            thresholds=thresholds,
            port_bonus=runtime.sensitive_port_bonus,
        )

        cumulative["total"] += 1
        cumulative["suspicious" if is_attack else "low"] += 0 if is_attack else 0
        if is_attack:
            cumulative["suspicious"] += 1
            cumulative[assessment.level] = cumulative.get(assessment.level, 0) + 1
            attacks[label] = attacks.get(label, 0) + 1
        else:
            cumulative["low"] += 1

        yield {
            "event": "flow",
            "data": {
                "index": i,
                "prediction": label,
                "confidence": round(confidence, 6),
                "is_attack": is_attack,
                "risk_level": assessment.level,
                "risk_score": round(assessment.score, 6),
                "destination_port": None if dest_port is None or math.isnan(dest_port) else int(dest_port),
                "packet_rate": _value(prepared.features["Flow Packets/s"], i),
                "flow_duration": _value(prepared.features["Flow Duration"], i),
                "ground_truth": prepared.ground_truth[i],
                "cursor": {
                    "total": cumulative["total"],
                    "suspicious": cumulative["suspicious"],
                    "progress": round(100 * (i + 1) / total, 2),
                },
            },
        }

    yield {
        "event": "done",
        "data": {
            "total": cumulative["total"],
            "suspicious": cumulative["suspicious"],
            "normal": cumulative["total"] - cumulative["suspicious"],
            "risk_distribution": {k: cumulative.get(k, 0) for k in ("low", "medium", "high", "critical")},
            "attack_distribution": attacks,
        },
    }


# --------------------------------------------------------------------------- #
def _value(series, i):
    if series is None:
        return None
    try:
        value = float(series.iloc[i])
    except (TypeError, ValueError, IndexError):
        return None
    return None if value != value else round(value, 6)


def _count(rows: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[str(row[key])] = out.get(str(row[key]), 0) + 1
    return out
