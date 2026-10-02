"""
Investigation service - the analyst workspace.

An investigation is a durable record that ties together an alert, the flow the
model flagged, the evidence that explains the verdict and the analyst's notes.
Analysts can read and write investigations; they cannot change the model or any
global detection configuration, which is enforced by the route layer.

Evidence policy
---------------
Everything stored in ``evidence`` is measured from the prediction row that the
Random Forest actually produced.  The service never adds an interpretation of its
own - that is the AI assistant's job, and its output is labelled as such.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.database_models import Alert, Investigation, Prediction, User
from app.services import risk_service

logger = get_logger("ainids.investigations")

STATUSES = ("open", "in_progress", "pending", "escalated", "closed")
PRIORITIES = ("low", "medium", "high", "critical")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def next_reference(db: Session) -> str:
    """Human-friendly sequential reference (``INV-0007``)."""
    count = int(db.scalar(select(func.count(Investigation.id))) or 0)
    return f"INV-{count + 1:04d}"


# --------------------------------------------------------------------------- #
# Evidence assembly
# --------------------------------------------------------------------------- #
def build_evidence(
    db: Session,
    *,
    prediction: Prediction | None = None,
    alert: Alert | None = None,
    runtime: Any | None = None,
) -> dict:
    """
    Collect the observed facts behind a verdict.

    The returned payload is explicitly labelled ``observed`` so the UI can render
    it separately from any AI-generated interpretation.
    """
    evidence: dict[str, Any] = {
        "observed": True,
        "label": "Observed data (model output and stored flow features)",
        "generated_at": _now().isoformat(),
    }

    if alert is not None:
        evidence["alert"] = {
            "id": alert.id,
            "alert_type": alert.alert_type,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "status": alert.status,
            "message": alert.message,
            "confidence": round(alert.confidence, 6),
            "risk_score": round(alert.risk_score, 6),
            "source_ip": alert.source_ip,
            "destination_port": alert.destination_port,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            "escalated": alert.escalated,
            "notes": alert.notes,
        }

    if prediction is not None:
        from app.services.ml_service import model_service

        factors = prediction.top_factors or []
        importance = model_service.importance(top=10) if model_service.is_loaded else {"importances": []}
        evidence["prediction"] = {
            "id": prediction.id,
            "record_index": prediction.record_index,
            "predicted_class": prediction.prediction,
            "is_attack": prediction.is_attack,
            "confidence": round(prediction.confidence, 6),
            "risk_level": prediction.risk_level,
            "risk_score": round(prediction.risk_score, 6),
            "ground_truth": prediction.ground_truth,
            "source": prediction.source,
            "timestamp": prediction.event_time.isoformat() if prediction.event_time else None,
        }
        evidence["flow"] = {
            "source_ip": prediction.source_ip,
            "destination_ip": prediction.destination_ip,
            "source_port": prediction.source_port,
            "destination_port": prediction.destination_port,
            "protocol": prediction.protocol,
            "flow_duration": prediction.flow_duration,
            "packet_rate": prediction.packet_rate,
            "packet_length_mean": prediction.packet_length_mean,
            "total_fwd_packets": prediction.total_fwd_packets,
            "total_bwd_packets": prediction.total_bwd_packets,
            "flow_bytes_per_s": prediction.flow_bytes_per_s,
        }
        evidence["features"] = prediction.features or {}
        evidence["feature_deviation"] = factors
        evidence["global_feature_importance"] = importance.get("importances", [])
        evidence["risk_rules"] = {
            "level": prediction.risk_level,
            "score": round(prediction.risk_score, 6),
            "thresholds": (runtime.risk_thresholds() if runtime else risk_service.THRESHOLDS),
            "formula": risk_service.rules_documentation()["formula"],
        }
        if prediction.ground_truth:
            evidence["ground_truth_note"] = (
                "Ground truth comes from the Label column of the analysed file. The model never "
                "used it as an input."
            )

    if runtime is not None and getattr(runtime, "enhanced_investigation", False):
        evidence["enhanced_investigation"] = True
        evidence["effective_configuration"] = runtime.to_dict()

    return evidence


def summarise_evidence(evidence: dict) -> str:
    """One-paragraph, purely factual summary used as the investigation summary."""
    lines: list[str] = []
    alert = evidence.get("alert") or {}
    prediction = evidence.get("prediction") or {}
    flow = evidence.get("flow") or {}

    if alert:
        lines.append(
            f"Alert {alert.get('id', '?')} reports '{alert.get('attack_type')}' at "
            f"{alert.get('severity', '?').upper()} severity (confidence "
            f"{float(alert.get('confidence') or 0) * 100:.1f}%, risk score "
            f"{float(alert.get('risk_score') or 0):.3f})."
        )
    if prediction:
        lines.append(
            f"The Random Forest classified the flow as '{prediction.get('predicted_class')}' "
            f"with {float(prediction.get('confidence') or 0) * 100:.1f}% confidence; recorded risk "
            f"level {prediction.get('risk_level')} at score {prediction.get('risk_score')}."
        )
    if flow.get("destination_port") is not None:
        endpoint = f"{flow.get('source_ip') or 'unknown'}:{flow.get('source_port') or '?'}"
        target = f"{flow.get('destination_ip') or 'unknown'}:{flow.get('destination_port')}"
        protocol = flow.get("protocol") or "unknown protocol"
        lines.append(f"Flow {endpoint} -> {target} over {protocol}.")
    deviations = evidence.get("feature_deviation") or []
    if deviations:
        top = ", ".join(
            f"{item.get('feature')} ({item.get('deviation_from_median', 0):+.2f} vs median)"
            for item in deviations[:3]
            if item.get("feature")
        )
        lines.append(f"Largest deviations from the training medians: {top}.")

    gt = prediction.get("ground_truth")
    if gt:
        lines.append(f"The analysed file labels this record as '{gt}'.")

    return " ".join(lines) or "No stored evidence is available for this record yet."


# --------------------------------------------------------------------------- #
# Auto incident creation
# --------------------------------------------------------------------------- #
def create_incidents_for_alerts(db: Session, alerts: list[Alert], runtime: Any | None = None) -> int:
    """
    Open an investigation for every alert at/above the configured severity.

    Controlled by ``network.auto_incident_creation`` and
    ``alerts.auto_incident_severity``; returns how many were created.
    """
    if not alerts:
        return 0
    if runtime is None:
        from app.services import config_service

        runtime = config_service.get_runtime(db=db)
    if not getattr(runtime, "auto_incident_creation", False):
        return 0

    created = 0
    for alert in alerts:
        created += ensure_for_alert(db, alert, runtime=runtime)
    if created:
        logger.info("opened %d automatic investigation(s)", created)
    return created


def ensure_for_alert(db: Session, alert: Alert, runtime: Any | None = None) -> int:
    """
    Open an investigation for one alert when it clears the auto-incident severity.

    Idempotent: an alert that already has an investigation is left alone, so it is
    safe to call after both alert creation and escalation.
    """
    if runtime is None or not getattr(runtime, "auto_incident_creation", False):
        return 0
    floor = getattr(runtime, "auto_incident_severity", "critical")
    if not risk_service.severity_is_at_least(alert.severity, floor):
        return 0
    if db.scalar(select(Investigation).where(Investigation.alert_id == alert.id)):
        return 0

    prediction = db.get(Prediction, alert.prediction_id) if alert.prediction_id else None
    evidence = build_evidence(db, prediction=prediction, alert=alert, runtime=runtime)
    investigation = Investigation(
        reference=next_reference(db),
        title=f"{alert.attack_type} investigation ({alert.severity.upper()})",
        status="escalated" if alert.escalated else "open",
        priority=alert.severity,
        assigned_to=None,
        created_by=None,
        alert_id=alert.id,
        prediction_id=alert.prediction_id,
        job_id=alert.job_id,
        dataset_id=alert.dataset_id,
        summary=summarise_evidence(evidence),
        findings=[],
        notes=[],
        evidence=evidence,
        risk_level=alert.severity,
        attack_type=alert.attack_type,
    )
    db.add(investigation)
    db.flush()
    alert.investigation_id = investigation.id
    return 1


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #
def list_investigations(
    db: Session,
    *,
    status: str | None = None,
    priority: str | None = None,
    assigned_to: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> dict:
    stmt = select(Investigation)
    if status and status != "all":
        stmt = stmt.where(Investigation.status == status)
    if priority and priority != "all":
        stmt = stmt.where(Investigation.priority == priority)
    if assigned_to:
        stmt = stmt.where(Investigation.assigned_to == assigned_to)
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Investigation.title).like(like),
                func.lower(Investigation.reference).like(like),
                func.lower(func.coalesce(Investigation.attack_type, "")).like(like),
                func.lower(func.coalesce(Investigation.summary, "")).like(like),
            )
        )

    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    rows = db.scalars(
        stmt.order_by(Investigation.updated_at.desc())
        .offset(max(page - 1, 0) * page_size)
        .limit(min(page_size, 200))
    ).all()
    return {
        "items": [row.to_dict() for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "statuses": list(STATUSES),
        "priorities": list(PRIORITIES),
    }


def get_investigation(db: Session, investigation_id: str) -> Investigation | None:
    return db.get(Investigation, investigation_id)


def create_investigation(
    db: Session,
    *,
    user: User,
    title: str,
    alert_id: str | None = None,
    prediction_id: str | None = None,
    summary: str | None = None,
    priority: str = "medium",
    runtime: Any | None = None,
) -> Investigation:
    alert = db.get(Alert, alert_id) if alert_id else None
    prediction = db.get(Prediction, prediction_id) if prediction_id else None
    if prediction is None and alert is not None and alert.prediction_id:
        prediction = db.get(Prediction, alert.prediction_id)

    evidence = build_evidence(db, prediction=prediction, alert=alert, runtime=runtime)
    investigation = Investigation(
        reference=next_reference(db),
        title=title[:200],
        status="open",
        priority=priority,
        assigned_to=user.id,
        created_by=user.id,
        alert_id=alert.id if alert else None,
        prediction_id=prediction.id if prediction else None,
        job_id=(alert.job_id if alert else None) or (prediction.job_id if prediction else None),
        dataset_id=(alert.dataset_id if alert else None) or (prediction.dataset_id if prediction else None),
        summary=summary or summarise_evidence(evidence),
        findings=[],
        notes=[],
        evidence=evidence,
        risk_level=(alert.severity if alert else None) or (prediction.risk_level if prediction else None),
        attack_type=(alert.attack_type if alert else None) or (prediction.prediction if prediction else None),
    )
    db.add(investigation)
    db.flush()
    if alert is not None:
        alert.investigation_id = investigation.id
    return investigation


def update_investigation(
    db: Session,
    investigation: Investigation,
    *,
    user: User,
    title: str | None = None,
    summary: str | None = None,
    status: str | None = None,
    priority: str | None = None,
    assigned_to: str | None = None,
    note: str | None = None,
    finding: str | None = None,
) -> Investigation:
    if title:
        investigation.title = title[:200]
    if summary is not None:
        investigation.summary = summary
    if status:
        if status not in STATUSES:
            raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
        investigation.status = status
        if status == "closed":
            investigation.closed_at = _now()
            investigation.closed_by = user.id
        else:
            investigation.closed_at = None
            investigation.closed_by = None
    if priority:
        if priority not in PRIORITIES:
            raise ValueError(f"priority must be one of: {', '.join(PRIORITIES)}")
        investigation.priority = priority
    if assigned_to is not None:
        investigation.assigned_to = assigned_to or None

    entry: dict[str, Any] | None = None
    if note:
        entry = {"at": _now().isoformat(), "author": user.name, "author_id": user.id, "text": note}
        investigation.notes = [*(investigation.notes or []), entry]
    if finding:
        entry = {"at": _now().isoformat(), "author": user.name, "author_id": user.id, "text": finding}
        investigation.findings = [*(investigation.findings or []), entry]
    db.flush()
    return investigation


def investigation_stats(db: Session) -> dict:
    by_status = {
        str(k): int(v) for k, v in db.execute(
            select(Investigation.status, func.count()).group_by(Investigation.status)
        ).all()
    }
    by_priority = {
        str(k): int(v) for k, v in db.execute(
            select(Investigation.priority, func.count()).group_by(Investigation.priority)
        ).all()
    }
    open_cases = sum(count for status, count in by_status.items() if status != "closed")
    return {
        "total": int(db.scalar(select(func.count(Investigation.id))) or 0),
        "open": open_cases,
        "closed": by_status.get("closed", 0),
        "by_status": by_status,
        "by_priority": by_priority,
    }
