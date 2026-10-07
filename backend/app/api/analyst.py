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

import csv
import io

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.rbac import (
    P_ALERTS_ACKNOWLEDGE,
    P_ALERTS_VIEW,
    P_ASSISTANT_USE,
    P_DASHBOARD_VIEW,
    P_DATASETS_UPLOAD,
    P_INVESTIGATIONS_NOTES,
    P_PREDICTIONS_VIEW,
    P_TRAFFIC_ANALYZE,
    require_permission,
)
from app.core.security import get_current_user, hash_password, verify_password
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
    network_status_service,
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


# --------------------------------------------------------------------------- #
# Network status (read-only)
# --------------------------------------------------------------------------- #
@router.get("/network/status", summary="Current network operational status (read-only)")
def network_status(
    request: Request,
    user: User = Depends(require_permission(P_DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
):
    """
    Returns the current network status so the analyst can see the platform threat
    level without needing any administration permission.  Read-only: the analyst
    sees the status, the reason it was set, and the last few transitions, but
    cannot change it.
    """
    current = network_status_service.current_dict(db)
    recent_history = network_status_service.history(db, limit=5)
    return {
        "status": current.get("status"),
        "status_key": current.get("status_key"),
        "label": current.get("label"),
        "description": current.get("description"),
        "tone": current.get("tone"),
        "source": current.get("source"),
        "reason": current.get("reason"),
        "started_at": current.get("started_at"),
        "changed_by": current.get("changed_by"),
        "recent_history": recent_history[:5],
    }


# --------------------------------------------------------------------------- #
# Self-service profile
# --------------------------------------------------------------------------- #
class _SelfUpdateRequest(Exception):
    pass


from pydantic import BaseModel, Field as PydanticField
from typing import Optional


class AnalystSelfUpdateRequest(BaseModel):
    name: Optional[str] = PydanticField(default=None, min_length=1, max_length=120)
    current_password: Optional[str] = PydanticField(default=None, min_length=1, max_length=256)
    new_password: Optional[str] = PydanticField(default=None, min_length=1, max_length=256)


@router.patch("/me", summary="Update own display name or password")
def update_self(
    payload: AnalystSelfUpdateRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Self-service profile update available to every authenticated user.
    - Name change: just send ``name``.
    - Password change: send ``current_password`` + ``new_password``.
      ``current_password`` must match before the new one is accepted.
    """
    from app.core.config import settings

    changed: list[str] = []

    if payload.name is not None and payload.name.strip() != user.name:
        user.name = payload.name.strip()
        changed.append("name")

    if payload.new_password is not None:
        if not payload.current_password:
            raise HTTPException(
                status_code=422,
                detail="current_password is required to set a new password.",
            )
        if not verify_password(payload.current_password, user.password_hash):
            raise HTTPException(
                status_code=401,
                detail="Current password is incorrect.",
            )
        min_len = settings.PASSWORD_MIN_LENGTH
        if len(payload.new_password) < min_len:
            raise HTTPException(
                status_code=422,
                detail=f"New password must be at least {min_len} characters.",
            )
        if payload.new_password.isalpha() or payload.new_password.isdigit():
            raise HTTPException(
                status_code=422,
                detail="New password must contain both letters and numbers.",
            )
        user.password_hash = hash_password(payload.new_password)
        # Stamp access_reset_at so any other open sessions are invalidated.
        from datetime import datetime, timezone
        user.access_reset_at = datetime.now(timezone.utc)
        changed.append("password")

    if not changed:
        return {"changed": [], "user": user.to_public_dict()}

    db.flush()
    audit_service.record(
        db,
        action="user.self_updated",
        user=user,
        request=request,
        category=audit_service.CAT_USER,
        resource=f"user:{user.id}",
        new_value={"changed": changed},
    )
    db.commit()
    db.refresh(user)
    return {"changed": changed, "user": user.to_public_dict()}


# --------------------------------------------------------------------------- #
# Alert export (CSV)
# --------------------------------------------------------------------------- #
@router.get("/alerts/export", summary="Export filtered alerts as CSV")
def export_alerts(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    job_id: str | None = None,
    search: str | None = None,
    limit: int = Query(default=5000, ge=1, le=10000),
    user: User = Depends(require_permission(P_ALERTS_VIEW)),
    db: Session = Depends(get_db),
):
    """
    Download the current alert queue as a CSV file.  Accepts the same filter
    params as the paginated list endpoint so the analyst exports exactly what
    they are looking at.
    """
    result = alert_service.list_alerts(
        db,
        status=status,
        severity=severity,
        attack_type=attack_type,
        job_id=job_id,
        search=search,
        page=1,
        page_size=limit,
    )
    alerts = result.get("items", [])

    columns = [
        "id",
        "created_at",
        "attack_type",
        "alert_type",
        "severity",
        "status",
        "confidence",
        "risk_score",
        "source_ip",
        "destination_port",
        "record_index",
        "message",
        "notes",
        "resolved_at",
        "acknowledged_at",
        "escalated",
        "job_id",
        "dataset_id",
        "prediction_id",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for alert in alerts:
        writer.writerow({col: alert.get(col, "") for col in columns})

    output.seek(0)
    filename = "ai_nids_alerts.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
