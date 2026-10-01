"""Alert API - the Alerts Center backend."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.database_models import User
from app.models.schemas import AlertPage, AlertUpdateRequest
from app.services import alert_service, risk_service

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertPage, summary="List alerts with filters")
def list_alerts(
    status: str | None = Query(None, pattern="^(all|new|reviewed|resolved|open)$"),
    severity: str | None = Query(None, pattern="^(all|low|medium|high|critical)$"),
    attack_type: str | None = None,
    job_id: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    user: User = Depends(get_current_user),
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


@router.get("/summary", summary="Alert counters for the dashboard/Alerts Center")
def summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return alert_service.alert_summary(db)


@router.get("/rules", summary="The documented risk/alert rules actually used by the engine")
def rules(user: User = Depends(get_current_user)):
    return risk_service.rules_documentation()


@router.get("/{alert_id}", summary="Alert detail")
def alert_detail(alert_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from app.models.database_models import Alert

    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    data = alert.to_dict()
    if alert.prediction_id:
        data["prediction_url"] = f"/api/predictions/{alert.prediction_id}"
    return data


@router.patch("/{alert_id}", summary="Mark an alert reviewed/resolved, or add a note")
def update_alert(
    alert_id: str,
    payload: AlertUpdateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.status == "open":
        payload.status = "new"
    alert = alert_service.update_alert(
        db, alert_id, status=payload.status, notes=payload.notes, user=user
    )
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    db.commit()
    db.refresh(alert)
    return alert.to_dict()
