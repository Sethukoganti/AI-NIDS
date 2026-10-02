"""AI Security Assistant API."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import P_ASSISTANT_USE, require_permission
from app.db.session import get_db
from app.models.database_models import User
from app.models.schemas import AssistantRequest, AssistantResponse
from app.services import ai_explanation_service

router = APIRouter(prefix="/assistant", tags=["assistant"])


@router.get("/status", summary="Which explanation provider is active")
def status(user: User = Depends(require_permission(P_ASSISTANT_USE))):
    return {
        "provider": settings.AI_PROVIDER,
        "enabled": settings.ai_enabled,
        "mode": "external LLM" if settings.ai_enabled else "local explanation engine",
        "model": settings.AI_MODEL if settings.ai_enabled else None,
        "api_key_configured": bool(settings.AI_API_KEY),
        "note": (
            "With AI_PROVIDER=none the assistant answers from a deterministic local engine that "
            "reads the same model output, SHAP values and database aggregates. Configure "
            "AI_PROVIDER + AI_API_KEY to have an LLM phrase the answers (still restricted to the "
            "supplied evidence)."
        ),
    }


@router.post("/ask", response_model=AssistantResponse, summary="Ask the assistant about the current data")
def ask(
    payload: AssistantRequest,
    user: User = Depends(require_permission(P_ASSISTANT_USE)),
    db: Session = Depends(get_db),
):
    result = ai_explanation_service.answer(
        db, payload.question, prediction_id=payload.prediction_id, user=user
    )
    if not payload.include_evidence:
        result.pop("evidence", None)
    return result
