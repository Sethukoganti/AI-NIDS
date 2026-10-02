"""Dashboard API - aggregated, real statistics for the SOC dashboard."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.rbac import P_DASHBOARD_VIEW, P_ALERTS_VIEW, require_permission
from app.db.session import get_db
from app.models.database_models import User
from app.services import alert_service, dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", summary="Metric cards + charts data (window configurable)")
def stats(
    hours: int = Query(24, ge=0, le=8760, description="0 = all time"),
    alert_limit: int = Query(8, ge=1, le=50),
    user: User = Depends(require_permission(P_DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
):
    return dashboard_service.overview(db, hours=hours, alert_limit=alert_limit)


@router.get("/timeline", summary="Traffic over time (hourly buckets)")
def timeline(
    hours: int = Query(24, ge=1, le=720),
    user: User = Depends(require_permission(P_DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
):
    return {"points": dashboard_service.traffic_timeline(db, hours=hours), "hours": hours}


@router.get("/recent-alerts", summary="Latest alerts for the dashboard table")
def recent_alerts(
    limit: int = Query(10, ge=1, le=50),
    user: User = Depends(require_permission(P_DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
):
    return {"items": dashboard_service.recent_alerts(db, limit=limit)}


@router.get("/alerts-summary", summary="Alert counters (severity/status breakdown)")
def alerts_summary(user: User = Depends(require_permission(P_ALERTS_VIEW)), db: Session = Depends(get_db)):
    return alert_service.alert_summary(db)
