"""
Analyst API (``/api/analyst``).

The analyst console: run the model over traffic, work the alert queue and own
investigations.  Every route is guarded by an *analyst* permission, never an
administration one - an analyst token reaching an ``/api/admin`` route gets
``403`` from the admin router itself.

Shared read-only endpoints (model card, datasets, live stream) stay on their
existing paths; this router adds the analyst-specific workflow surface.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.rbac import (
    P_ALERTS_ACKNOWLEDGE,
    P_ALERTS_VIEW,
    P_ASSISTANT_USE,
    P_DATASETS_UPLOAD,
    P_INVESTIGATIONS_NOTES,
    P_PREDICTIONS_VIEW,
    P_TRAFFIC_ANALYZE,
    require_permission,
)
from app.db.session import get_db
from app.models.database_models import Alert, User
from app.models.schemas import (
    AlertPage,
    AlertUpdateRequest,
    AssistantRequest,
    InvestigationCreateRequest,
    InvestigationOut,
    InvestigationPage,
    InvestigationUpdateRequest,
)
from app.services import (
    ai_explanation_service,
    alert_service,
    audit_service,
    config_service,
    dataset_service,
    investigation_service,
    notification_service,
    prediction_service,
)
from app.services.preprocessing_service import DatasetError

router = APIRouter(prefix="/analyst", tags=["analyst"])
logger = get_logger("ainids.api.analyst")


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
@router.post("/traffic/analyze", summary="Upload traffic and run the Random Forest")
async def analyze_traffic(
    request: Request,
    file: UploadFile = File(...),
    force_sync: bool = Query(True),
    user: User = Depends(require_permission(P_TRAFFIC_ANALYZE)),
    db: Session = Depends(get_db),
):
    from app.api.predictions import _analyze

    runtime = config_service.runtime_snapshot(db)
    raw = await file.read()
    try:
        path, size = dataset_service.save_upload(raw, file.filename or "upload.csv", runtime=runtime)
        dataset = dataset_service.register_dataset(
            db,
            filename=file.filename or path.name,
            stored_path=path,
            size_bytes=size,
            user_id=user.id,
        )
        dataset_service.record_version(db, dataset, note="Analyst upload", created_by=user.id)
        db.commit()
        result = _analyze(db, dataset, user, force_sync=force_sync, request=request)
    except DatasetError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, **exc.detail}) from exc
    result["dataset"] = dataset.to_dict()
    return result


@router.post("/traffic/analyze/{dataset_id}", summary="Run the Random Forest over a stored dataset")
def analyze_dataset(
    dataset_id: str,
    request: Request,
    force_sync: bool = Query(True),
    user: User = Depends(require_permission(P_TRAFFIC_ANALYZE)),
    db: Session = Depends(get_db),
):
    from app.api.predictions import _analyze

    from app.models.database_models import Dataset

    dataset = db.get(Dataset, dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return _analyze(db, dataset, user, force_sync=force_sync, request=request)


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
@router.get("/alerts", response_model=AlertPage, summary="Alert queue")
def list_alerts(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    job_id: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    return alert_service.list_alerts(
        db,
        status=status,
        severity=severity,
        attack_type=attack_type,
        job_id=job_id,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.post("/alerts/{alert_id}/acknowledge", summary="Acknowledge an alert")
def acknowledge(
    alert_id: str,
    request: Request,
    user: User = Depends(require_permission(P_ALERTS_ACKNOWLEDGE)),
    db: Session = Depends(get_db),
):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    previous = {"status": alert.status, "acknowledged": bool(alert.acknowledged_at)}
    alert_service.acknowledge_alert(db, alert, user)
    audit_service.record_change(
        db,
        scope="alerts",
        changes={"status": {"previous": previous["status"], "new": alert.status}},
        user=user,
        request=request,
        resource=f"alert:{alert.id}",
        category=audit_service.CAT_ALERT,
        detail={"acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None},
    )
    db.commit()
    return alert.to_dict()


@router.patch("/alerts/{alert_id}", response_model=dict, summary="Update alert status / notes")
def update_alert(
    alert_id: str,
    payload: AlertUpdateRequest,
    request: Request,
    user: User = Depends(require_permission(P_ALERTS_ACKNOWLEDGE)),
    db: Session = Depends(get_db),
):
    alert = alert_service.update_alert(
        db, alert_id, status=payload.status, notes=payload.notes, user=user
    )
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    audit_service.record_change(
        db,
        scope="alerts",
        changes={"status": {"previous": None, "new": payload.status}} if payload.status else {},
        user=user,
        request=request,
        resource=f"alert:{alert.id}",
        category=audit_service.CAT_ALERT,
    )
    db.commit()
    return alert.to_dict()


@router.get("/alerts/summary", summary="Alert counts by severity / status / attack type")
def alerts_summary(
    request: Request,
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    return alert_service.alert_summary(db)


# --------------------------------------------------------------------------- #
# Predictions
# --------------------------------------------------------------------------- #
@router.get("/predictions", summary="Stored predictions")
def predictions(
    request: Request,
    job_id: str | None = None,
    dataset_id: str | None = None,
    verdict: str = Query("all", pattern="^(all|attack|normal|high_risk|critical)$"),
    attack_type: str | None = None,
    risk_level: str | None = None,
    min_confidence: float | None = Query(None, ge=0.0, le=1.0),
    search: str | None = None,
    sort_by: str = Query("record_index"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: User = Depends(require_permission(P_PREDICTIONS_VIEW)),
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


@router.get("/predictions/{prediction_id}", summary="Inspect one flow")
def prediction_detail(
    prediction_id: str,
    request: Request,
    user: User = Depends(require_permission(P_PREDICTIONS_VIEW)),
    db: Session = Depends(get_db),
):
    payload = prediction_service.prediction_detail(db, prediction_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Prediction not found.")
    return payload


# --------------------------------------------------------------------------- #
# Investigations
# --------------------------------------------------------------------------- #
@router.get("/investigations", response_model=InvestigationPage, summary="Investigation workspace")
def list_investigations(
    request: Request,
    status: str | None = None,
    priority: str | None = None,
    assigned_to: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    return investigation_service.list_investigations(
        db,
        status=status,
        priority=priority,
        assigned_to=assigned_to,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.post("/investigations", response_model=InvestigationOut, summary="Open an investigation")
def create_investigation(
    payload: InvestigationCreateRequest,
    request: Request,
    user: User = Depends(require_permission(P_INVESTIGATIONS_NOTES)),
    db: Session = Depends(get_db),
):
    runtime = config_service.runtime_snapshot(db)
    investigation = investigation_service.create_investigation(
        db,
        user=user,
        title=payload.title,
        alert_id=payload.alert_id,
        prediction_id=payload.prediction_id,
        summary=payload.summary,
        priority=payload.priority,
        runtime=runtime,
    )
    audit_service.record(
        db,
        action="investigation.created",
        user=user,
        request=request,
        category=audit_service.CAT_INVESTIGATION,
        resource=f"investigation:{investigation.id}",
        new_value={"reference": investigation.reference, "priority": investigation.priority},
    )
    db.commit()
    return investigation.to_dict()


@router.get("/investigations/stats", summary="Investigation counts")
def investigation_stats(
    request: Request,
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    return investigation_service.investigation_stats(db)


@router.get("/investigations/{investigation_id}", response_model=InvestigationOut, summary="One investigation")
def get_investigation(
    investigation_id: str,
    request: Request,
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    investigation = investigation_service.get_investigation(db, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation.to_dict()


@router.patch("/investigations/{investigation_id}", response_model=InvestigationOut, summary="Update an investigation")
def update_investigation(
    investigation_id: str,
    payload: InvestigationUpdateRequest,
    request: Request,
    user: User = Depends(require_permission(P_INVESTIGATIONS_NOTES)),
    db: Session = Depends(get_db),
):
    investigation = investigation_service.get_investigation(db, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    before = {"status": investigation.status, "priority": investigation.priority}
    try:
        investigation_service.update_investigation(
            db,
            investigation,
            user=user,
            title=payload.title,
            summary=payload.summary,
            status=payload.status,
            priority=payload.priority,
            assigned_to=payload.assigned_to,
            note=payload.note,
            finding=payload.finding,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    audit_service.record_change(
        db,
        scope="investigations",
        changes={
            "status": {"previous": before["status"], "new": investigation.status},
            "priority": {"previous": before["priority"], "new": investigation.priority},
        },
        user=user,
        request=request,
        resource=f"investigation:{investigation.id}",
        category=audit_service.CAT_INVESTIGATION,
        note="note added" if payload.note else ("finding added" if payload.finding else None),
    )
    db.commit()
    return investigation.to_dict()


# --------------------------------------------------------------------------- #
# Assistant
# --------------------------------------------------------------------------- #
@router.post("/assistant", summary="Ask the AI assistant about stored data")
def assistant(
    payload: AssistantRequest,
    request: Request,
    user: User = Depends(require_permission(P_ASSISTANT_USE)),
    db: Session = Depends(get_db),
):
    result = ai_explanation_service.answer(
        db, question=payload.question, prediction_id=payload.prediction_id
    )
    if payload.include_evidence and result.get("evidence") is None:
        # The service only attaches evidence for prediction-scoped questions; an
        # operator asking about a dataset or the platform gets the evidence
        # packet built here instead, still grounded in stored rows.
        result["evidence"] = _analyst_evidence(db, user)
    audit_service.record(
        db,
        action="assistant.asked",
        user=user,
        request=request,
        category=audit_service.CAT_GENERAL,
        resource=f"prediction:{payload.prediction_id}" if payload.prediction_id else "assistant",
        detail={"question": payload.question[:200], "provider": result.get("provider")},
    )
    db.commit()
    return result


def _analyst_evidence(db: Session, user: User) -> dict:
    """The facts an analyst-level answer is allowed to be based on."""
    from app.models.database_models import Prediction

    total = int(db.scalar(select(func.count(Prediction.id))) or 0)
    attacks = int(
        db.scalar(select(func.count(Prediction.id)).where(Prediction.is_attack.is_(True))) or 0
    )
    return {
        "label": "Observed data (stored analysis results)",
        "observed": True,
        "total_predictions": total,
        "attack_predictions": attacks,
        "normal_predictions": total - attacks,
        "attack_percent": round(100.0 * attacks / total, 2) if total else 0.0,
        "alerts": alert_service.alert_summary(db),
        "investigations": investigation_service.investigation_stats(db),
        "network_status": config_service.runtime_snapshot(db).status,
    }


# --------------------------------------------------------------------------- #
# Notifications
# --------------------------------------------------------------------------- #
@router.get("/notifications", summary="Notification feed visible to the analyst")
def notifications(
    request: Request,
    is_read: bool | None = None,
    category: str | None = None,
    severity: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    return notification_service.list_notifications(
        db,
        user=user,
        is_read=is_read,
        category=category,
        severity=severity,
        page=page,
        page_size=page_size,
    )


@router.post("/notifications/{notification_id}/read", summary="Mark a notification read")
def read_notification(
    notification_id: str,
    request: Request,
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    notification = notification_service.mark_read(db, notification_id, user)
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found or not visible to you.")
    db.commit()
    return notification.to_dict()


@router.post("/notifications/read-all", summary="Mark every visible notification read")
def read_all_notifications(
    request: Request,
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    count = notification_service.mark_all_read(db, user)
    db.commit()
    return {"marked": count}