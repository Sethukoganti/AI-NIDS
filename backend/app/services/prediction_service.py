"""
Prediction service - the analysis pipeline orchestrator.

    file -> preprocessing -> feature alignment -> Random Forest -> probabilities
         -> risk engine -> alerts -> persistence -> dashboard rollup -> summary

Large files run as a background job (progress persisted so the UI can poll);
small files are analysed inline so the API stays snappy either way.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import session_scope
from app.models.database_models import (
    Alert,
    AnalysisJob,
    Dataset,
    DetectionStatistic,
    Prediction,
)
from app.services import (
    alert_service,
    config_service,
    investigation_service,
    notification_service,
    preprocessing_service,
    risk_service,
)
from app.services.config_service import RuntimeConfig
from app.services.ml_service import ModelUnavailableError, model_service

logger = get_logger("ainids.predictions")

_executor_lock = threading.Lock()
_executor: ThreadPoolExecutor | None = None
_executor_workers = 0
_progress_lock = threading.Lock()


def _pool(workers: int) -> ThreadPoolExecutor:
    """
    Background job pool, resized when an admin changes ``detection.job_workers``.

    Rebuilding the executor only affects jobs queued *after* the change: work
    already running on the old pool finishes untouched.
    """
    global _executor, _executor_workers
    workers = max(1, int(workers or settings.JOB_WORKERS))
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="ainids-job"
            )
            _executor_workers = workers
            logger.info("analysis worker pool started with %d worker(s)", workers)
        elif workers != _executor_workers:
            previous, _executor_workers = _executor, workers
            _executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ainids-job")
            logger.info("analysis worker pool resized %d -> %d", previous._max_workers, workers)
        return _executor


def pool_workers() -> int:
    return _executor_workers or settings.JOB_WORKERS


# features persisted with every prediction so records stay inspectable later
DISPLAY_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Packet Length Mean",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Average Packet Size",
    "SYN Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Job plumbing
# --------------------------------------------------------------------------- #
def create_job(db: Session, dataset: Dataset, user_id: str | None) -> AnalysisJob:
    job = AnalysisJob(
        dataset_id=dataset.id,
        created_by=user_id,
        status="queued",
        stage="queued",
        progress=0.0,
        total_rows=dataset.rows,
        model_version=str(model_service.metadata.get("version", "unknown")),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def submit_job(job_id: str, workers: int | None = None, runtime: RuntimeConfig | None = None) -> None:
    """Queue a background analysis job on the configured worker pool."""
    if workers is None:
        runtime = runtime or config_service.get_runtime()
        workers = runtime.job_workers
    _pool(workers or settings.JOB_WORKERS).submit(_run_job_thread, job_id)


def _run_job_thread(job_id: str) -> None:
    with session_scope() as db:
        job = db.get(AnalysisJob, job_id)
        if job is None:
            logger.error("job %s vanished before execution", job_id)
            return
        dataset = db.get(Dataset, job.dataset_id)
        if dataset is None:
            job.status, job.error, job.finished_at = "failed", "dataset no longer exists", _now()
            return
        try:
            # Re-read the effective configuration at execution time: an admin may
            # have changed detection sensitivity or limits between queueing and
            # running, and the job must be analysed under the configuration that
            # actually applied.
            run_analysis(db, job, dataset, user_id=job.created_by)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("analysis job %s failed", job_id)
            job.status = "failed"
            job.stage = "failed"
            job.error = f"{type(exc).__name__}: {exc}"[:600]
            job.finished_at = _now()


def _set_progress(db: Session, job: AnalysisJob, progress: float, stage: str, processed: int | None = None) -> None:
    with _progress_lock:
        job.progress = float(max(0.0, min(progress, 100.0)))
        job.stage = stage
        if processed is not None:
            job.processed_rows = int(processed)
        db.commit()


# --------------------------------------------------------------------------- #
# Core pipeline
# --------------------------------------------------------------------------- #
def run_analysis(
    db: Session,
    job: AnalysisJob,
    dataset: Dataset,
    user_id: str | None = None,
    source: str = "upload",
    persist: bool = True,
    runtime: RuntimeConfig | None = None,
) -> dict:
    from app.services.preprocessing_service import DatasetError, load_schema, prepare_features, read_traffic_file

    runtime = runtime or config_service.runtime_snapshot(db)
    if not runtime.model_enabled:
        raise DatasetError(
            "The detection model is currently disabled by an administrator configuration change.",
            503,
            {"scope": "model", "setting": "enabled"},
        )

    job.status = "running"
    job.stage = "reading file"
    job.started_at = _now()
    _set_progress(db, job, 2.0, "reading file")
    started = time.perf_counter()

    schema = load_schema()
    path = Path(dataset.stored_path) if dataset.stored_path else None
    if path is None or not path.exists():
        raise DatasetError("The uploaded file could not be found on the server.", 404)

    row_limit = runtime.max_rows_per_job
    df = read_traffic_file(path, max_rows=row_limit)
    truncated = len(df) >= row_limit

    _set_progress(db, job, 12.0, "preprocessing", len(df))
    prepared = prepare_features(df, schema, strict=True)
    warnings: list[str] = []
    if truncated:
        warnings.append(
            f"File contained more than the {row_limit:,}-row per-job limit configured by the "
            f"administrator; only the first {row_limit:,} flows were analysed."
        )
    if prepared.diagnostics["imputed_features"]:
        warnings.append(
            "These trained features were absent from the file and were filled with the "
            "training-split median (values shown in 'imputed_features'): "
            + ", ".join(prepared.diagnostics["imputed_features"][:12])
            + ("…" if len(prepared.diagnostics["imputed_features"]) > 12 else "")
        )
    if prepared.diagnostics.get("rows_dropped_missing_values"):
        warnings.append(
            f"{prepared.diagnostics['rows_dropped_missing_values']:,} rows were dropped "
            "because required feature values were missing or infinite."
        )
    if prepared.diagnostics.get("onehot_features_created"):
        warnings.append(
            "One-hot encoded categorical columns detected and aligned to trained features: "
            + ", ".join(prepared.diagnostics["onehot_features_created"][:10])
        )

    _set_progress(db, job, 30.0, "running Random Forest", prepared.diagnostics["rows_usable"])
    result = model_service.predict(prepared.features)
    labels: list[str] = result["labels"]
    confidences = result["confidences"]
    probabilities = result["probabilities"]
    classes = result["classes"]
    normal_class = model_service.normal_class

    _set_progress(db, job, 60.0, "risk analysis", prepared.diagnostics["rows_usable"])

    # ---- risk + row records ------------------------------------------- #
    feature_names = model_service.feature_names()
    index_of = {name: i for i, name in enumerate(feature_names)}
    matrix = prepared.features.to_numpy(dtype="float64")
    dest_ports = prepared.row_meta.get("destination_port")
    src_ports = prepared.row_meta.get("source_port")
    src_ips = prepared.row_meta.get("source_ip")
    dst_ips = prepared.row_meta.get("destination_ip")
    protocols = prepared.row_meta.get("protocol")

    store_features = [f for f in DISPLAY_FEATURES if f in index_of]
    top_factors = model_service.deviations(prepared.features.iloc[: min(len(prepared.features), 5000)], top=5)

    thresholds = runtime.risk_thresholds()
    records: list[dict] = []
    risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    attack_counts: dict[str, int] = {}
    normal_count = 0

    for i, label in enumerate(labels):
        is_attack = label != normal_class
        dest_port = _num(dest_ports, i)
        assessment = risk_service.assess(
            prediction=label,
            confidence=float(confidences[i]),
            is_attack=is_attack,
            normal_class=normal_class,
            destination_port=dest_port,
            thresholds=thresholds,
            port_bonus=runtime.sensitive_port_bonus,
        )
        risk_counts[assessment.level] = risk_counts.get(assessment.level, 0) + 1
        if is_attack:
            attack_counts[label] = attack_counts.get(label, 0) + 1
        else:
            normal_count += 1

        rowwise_proba = probabilities[i] if probabilities.shape[0] > i else np.zeros(len(classes))
        order = np.argsort(rowwise_proba)[::-1][:3]

        records.append(
            {
                "record_index": i,
                "prediction": label,
                "is_attack": is_attack,
                "confidence": float(confidences[i]),
                "risk_level": assessment.level,
                "risk_score": assessment.score,
                "risk_factors": assessment.factors,
                "top_probabilities": [
                    {"class": classes[j], "probability": float(rowwise_proba[j])} for j in order
                ],
                "source_port": _int_or_none(src_ports, i),
                "destination_port": _int_or_none(dest_ports, i),
                "source_ip": _str_or_none(src_ips, i),
                "destination_ip": _str_or_none(dst_ips, i),
                "protocol": _str_or_none(protocols, i),
                "flow_duration": _feature(matrix, index_of, "Flow Duration", i),
                "packet_rate": _feature(matrix, index_of, "Flow Packets/s", i),
                "packet_length_mean": _feature(matrix, index_of, "Packet Length Mean", i),
                "total_fwd_packets": _feature(matrix, index_of, "Total Fwd Packets", i),
                "total_bwd_packets": _feature(matrix, index_of, "Total Backward Packets", i),
                "flow_bytes_per_s": _feature(matrix, index_of, "Flow Bytes/s", i),
                "ground_truth": prepared.ground_truth[i],
                "event_time": prepared.event_times[i],
                "features": {f: _feature(matrix, index_of, f, i) for f in store_features},
                "top_factors": top_factors[i] if i < len(top_factors) else [],
            }
        )

    _set_progress(db, job, 75.0, "persisting results", prepared.diagnostics["rows_usable"])

    # ---- persistence --------------------------------------------------- #
    stored = 0
    alert_count = 0
    incidents_created = 0
    if persist:
        limit = min(len(records), runtime.store_predictions_limit)
        stored_objects: list[Prediction] = []
        for record in records[:limit]:
            if (record["confidence"] or 0.0) < runtime.min_confidence_to_store:
                continue
            prediction = Prediction(
                dataset_id=dataset.id,
                job_id=job.id,
                record_index=record["record_index"],
                prediction=record["prediction"],
                is_attack=record["is_attack"],
                confidence=record["confidence"],
                risk_level=record["risk_level"],
                risk_score=record["risk_score"],
                source_port=record["source_port"],
                destination_port=record["destination_port"],
                source_ip=record["source_ip"],
                destination_ip=record["destination_ip"],
                protocol=record["protocol"],
                flow_duration=record["flow_duration"],
                packet_rate=record["packet_rate"],
                packet_length_mean=record["packet_length_mean"],
                total_fwd_packets=record["total_fwd_packets"],
                total_bwd_packets=record["total_bwd_packets"],
                flow_bytes_per_s=record["flow_bytes_per_s"],
                event_time=_parse_ts(record["event_time"]),
                ground_truth=record["ground_truth"],
                source=source,
                features=record["features"],
                top_factors=record["top_factors"],
            )
            db.add(prediction)
            stored_objects.append(prediction)
        db.flush()
        stored = len(stored_objects)
        if len(records) > limit:
            warnings.append(
                f"Only the first {limit:,} of {len(records):,} flow results were stored; the "
                "summary statistics below cover every analysed row."
            )
        if stored < len(records) and runtime.min_confidence_to_store > 0:
            warnings.append(
                f"{len(records) - stored:,} flow(s) below the configured minimum confidence of "
                f"{runtime.min_confidence_to_store:.2f} were summarised but not stored."
            )

        _set_progress(db, job, 88.0, "generating alerts", prepared.diagnostics["rows_usable"])
        alerts = alert_service.create_alerts_for_job(db, job.id, dataset.id, stored_objects, runtime=runtime)
        alert_count = len(alerts)
        if alerts:
            notification_service.create_for_alerts(db, alerts, runtime=runtime)
            incidents_created = investigation_service.create_incidents_for_alerts(
                db, alerts, runtime=runtime
            )
    else:
        stored = len(records)

    # ---- summary -------------------------------------------------------- #
    summary = _build_summary(
        records=records,
        labels=labels,
        confidences=confidences,
        attack_counts=attack_counts,
        risk_counts=risk_counts,
        normal_count=normal_count,
        diagnostics=prepared.diagnostics,
        ground_truth=prepared.ground_truth,
        stored=stored,
        alerts=alert_count,
        classes=classes,
        runtime=runtime,
        incidents=incidents_created,
    )

    if persist:
        _rollup_statistics(db, summary)
        job.status = "completed"
        job.stage = "completed"
        job.progress = 100.0
        job.processed_rows = len(records)
        job.total_rows = len(records)
        job.summary = summary
        job.warnings = warnings
        job.finished_at = _now()
        job.duration_ms = int((time.perf_counter() - started) * 1000)
        dataset.rows = len(records)
        db.commit()
    else:
        job.status = "completed"
        job.progress = 100.0
        job.summary = summary
        job.warnings = warnings
        job.finished_at = _now()
        job.duration_ms = int((time.perf_counter() - started) * 1000)
        db.commit()

    summary["warnings"] = warnings
    summary["job_id"] = job.id
    summary["duration_ms"] = job.duration_ms
    return summary


def _build_summary(
    records: list[dict],
    labels: list[str],
    confidences: np.ndarray,
    attack_counts: dict[str, int],
    risk_counts: dict[str, int],
    normal_count: int,
    diagnostics: dict,
    ground_truth: list[str | None],
    stored: int,
    alerts: int,
    classes: list[str],
    runtime: RuntimeConfig | None = None,
    incidents: int = 0,
) -> dict:
    total = len(records)
    suspicious = total - normal_count
    avg_confidence = float(np.mean(confidences)) if total else 0.0

    # ground-truth comparison when the upload shipped a Label column
    ground_truth_report: dict | None = None
    labelled = [
        (rec["prediction"], gt)
        for rec, gt in zip(records, ground_truth)
        if gt
    ]
    if labelled:
        correct = sum(1 for pred, gt in labelled if pred == gt)
        normal_class = model_service.normal_class
        tp = sum(1 for pred, gt in labelled if pred != normal_class and gt != normal_class)
        tn = sum(1 for pred, gt in labelled if pred == normal_class and gt == normal_class)
        fp = sum(1 for pred, gt in labelled if pred != normal_class and gt == normal_class)
        fn = sum(1 for pred, gt in labelled if pred == normal_class and gt != normal_class)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        ground_truth_report = {
            "labelled_rows": len(labelled),
            "match_rate": round(correct / len(labelled), 6),
            "binary": {
                "true_positive": tp,
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
                "precision": round(precision, 6),
                "recall": round(recall, 6),
                "f1": round(2 * precision * recall / (precision + recall), 6) if (precision + recall) else 0.0,
            },
            "note": (
                "Computed by comparing the model's predictions with the Label column shipped in "
                "the uploaded file. The model never used that column as an input."
            ),
        }

    by_class_avg_conf = {}
    for cls in classes:
        values = [c for label, c in zip(labels, confidences) if label == cls]
        if values:
            by_class_avg_conf[cls] = round(float(np.mean(values)), 6)

    return {
        "total_records": total,
        "normal_records": normal_count,
        "suspicious_records": suspicious,
        "detection_rate": round(suspicious / total, 6) if total else 0.0,
        "average_confidence": round(avg_confidence, 6),
        "attack_distribution": dict(sorted(attack_counts.items(), key=lambda kv: -kv[1])),
        "risk_distribution": risk_counts,
        "high_risk_records": risk_counts.get("high", 0) + risk_counts.get("critical", 0),
        "critical_records": risk_counts.get("critical", 0),
        "alerts_generated": alerts,
        "incidents_created": incidents,
        "stored_predictions": stored,
        "average_confidence_by_class": by_class_avg_conf,
        "ground_truth": ground_truth_report,
        "preprocessing": diagnostics,
        "effective_configuration": runtime.to_dict() if runtime else None,
        "model": {
            "algorithm": model_service.metadata.get("algorithm"),
            "n_estimators": model_service.metadata.get("n_estimators"),
            "version": model_service.metadata.get("version"),
            "test_accuracy": model_service.evaluation.get("accuracy"),
        },
    }


def _rollup_statistics(db: Session, summary: dict) -> None:
    """Maintain the hourly dashboard rollup from this job's results."""
    bucket = _now().replace(minute=0, second=0, microsecond=0)
    row = db.scalar(select(DetectionStatistic).where(DetectionStatistic.bucket_start == bucket))
    if row is None:
        row = DetectionStatistic(bucket_start=bucket, attack_counts={})
        db.add(row)
        db.flush()
    row.total += summary["total_records"]
    row.normal += summary["normal_records"]
    row.suspicious += summary["suspicious_records"]
    row.low += summary["risk_distribution"].get("low", 0)
    row.medium += summary["risk_distribution"].get("medium", 0)
    row.high += summary["risk_distribution"].get("high", 0)
    row.critical += summary["risk_distribution"].get("critical", 0)
    row.alerts += summary["alerts_generated"]
    merged = dict(row.attack_counts or {})
    for attack, count in summary["attack_distribution"].items():
        merged[attack] = merged.get(attack, 0) + count
    row.attack_counts = merged


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #
SORTABLE = {
    "record_index": Prediction.record_index,
    "confidence": Prediction.confidence,
    "risk_score": Prediction.risk_score,
    "risk_level": Prediction.risk_level,
    "prediction": Prediction.prediction,
    "created_at": Prediction.created_at,
}


def list_predictions(
    db: Session,
    job_id: str | None = None,
    dataset_id: str | None = None,
    verdict: str | None = None,       # all | attack | normal | high_risk | critical
    attack_type: str | None = None,
    risk_level: str | None = None,
    min_confidence: float | None = None,
    search: str | None = None,
    sort_by: str = "record_index",
    sort_dir: str = "asc",
    page: int = 1,
    page_size: int = 25,
) -> dict:
    stmt = select(Prediction)
    if job_id:
        stmt = stmt.where(Prediction.job_id == job_id)
    if dataset_id:
        stmt = stmt.where(Prediction.dataset_id == dataset_id)

    if verdict and verdict != "all":
        if verdict == "attack":
            stmt = stmt.where(Prediction.is_attack.is_(True))
        elif verdict == "normal":
            stmt = stmt.where(Prediction.is_attack.is_(False))
        elif verdict == "high_risk":
            stmt = stmt.where(Prediction.risk_level.in_(["high", "critical"]))
        elif verdict == "critical":
            stmt = stmt.where(Prediction.risk_level == "critical")
    if attack_type and attack_type != "all":
        stmt = stmt.where(Prediction.prediction == attack_type)
    if risk_level and risk_level != "all":
        stmt = stmt.where(Prediction.risk_level == risk_level)
    if min_confidence is not None:
        stmt = stmt.where(Prediction.confidence >= min_confidence)
    if search:
        like = f"%{search.lower()}%"
        clauses = [
            func.lower(Prediction.prediction).like(like),
            func.cast(Prediction.record_index, __import__("sqlalchemy").String).like(like),
        ]
        if search.strip().isdigit():
            clauses.append(Prediction.destination_port == int(search.strip()))
            clauses.append(Prediction.source_port == int(search.strip()))
        stmt = stmt.where(clauses[0] | clauses[1] | clauses[2] | clauses[3])

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    column = SORTABLE.get(sort_by, Prediction.record_index)
    stmt = stmt.order_by(column.desc() if sort_dir == "desc" else column.asc())
    stmt = stmt.offset(max(page - 1, 0) * page_size).limit(page_size)
    rows = db.scalars(stmt).all()

    return {
        "items": [p.to_dict(include_features=False) for p in rows],
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "pages": max(1, (int(total) + page_size - 1) // page_size),
        "sort_by": sort_by,
        "sort_dir": sort_dir,
    }


def job_overview(db: Session, job_id: str) -> dict | None:
    job = db.get(AnalysisJob, job_id)
    if job is None:
        return None
    data = job.to_dict()
    data["alert_count"] = int(
        db.scalar(select(func.count(Alert.id)).where(Alert.job_id == job_id)) or 0
    )
    return data


def list_jobs(db: Session, limit: int = 25, user_id: str | None = None) -> list[dict]:
    stmt = select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(limit)
    if user_id:
        stmt = stmt.where(AnalysisJob.created_by == user_id)
    return [job.to_dict() for job in db.scalars(stmt).all()]


def prediction_detail(db: Session, prediction_id: str, with_shap: bool = True) -> dict | None:
    """
    Full inspection payload for one flow:
    stored row + live TreeSHAP explanation (falls back to global importance with
    an explicit label) + the class profile comparison used by the UI.
    """
    prediction = db.get(Prediction, prediction_id)
    if prediction is None:
        return None

    payload = prediction.to_dict(include_features=True)

    shap_payload = None
    explanation_method = "global_feature_importance"
    explanation_label = (
        "Global model feature importance (SHAP unavailable for this record). These values "
        "describe how the model behaves overall, not this specific prediction."
    )
    if with_shap:
        try:
            from app.services.preprocessing_service import load_schema, prepare_features

            features = pd.DataFrame([payload["features"]])
            schema = load_schema()
            # rebuild a full feature row: stored values + training medians for the rest
            row = {}
            for feature in schema.feature_columns:
                row[feature] = float(payload["features"].get(feature, schema.feature_medians.get(feature, 0.0)))
            aligned = pd.DataFrame([row])[schema.feature_columns].astype("float32")
            shap_payload = model_service.explain_shap(aligned, payload["prediction"], max_rows=1)
            explanation_method = "tree_shap"
            explanation_label = "TreeSHAP (per-record SHAP values)"
        except ModelUnavailableError as exc:
            logger.warning("SHAP unavailable for prediction %s: %s", prediction_id, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("SHAP failed for prediction %s: %s", prediction_id, type(exc).__name__)

    payload["explanation"] = shap_payload
    payload["explanation_method"] = explanation_method
    payload["explanation_label"] = explanation_label
    if shap_payload is None:
        payload["fallback_explanation"] = model_service.importance(top=8)

    alerts = db.scalars(
        select(Alert).where(Alert.prediction_id == prediction_id).order_by(Alert.created_at.desc())
    ).all()
    payload["alerts"] = [a.to_dict() for a in alerts]
    return payload


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _num(series: pd.Series | None, i: int) -> float | None:
    if series is None:
        return None
    try:
        value = float(series.iloc[i])
    except (TypeError, ValueError, IndexError):
        return None
    return None if value != value else value


def _int_or_none(series: pd.Series | None, i: int) -> int | None:
    value = _num(series, i)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _str_or_none(series: pd.Series | None, i: int) -> str | None:
    if series is None:
        return None
    try:
        value = str(series.iloc[i]).strip()
    except (IndexError, AttributeError):
        return None
    if not value or value.lower() in {"nan", "none", ""}:
        return None
    return value[:64]


def _feature(matrix: np.ndarray, index_of: dict[str, int], name: str, i: int) -> float | None:
    idx = index_of.get(name)
    if idx is None or i >= matrix.shape[0]:
        return None
    value = float(matrix[i, idx])
    return None if value != value else value


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
