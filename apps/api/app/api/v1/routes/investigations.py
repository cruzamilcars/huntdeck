import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.core.config import Settings, get_settings
from app.core.security import CurrentUser, get_current_user
from app.domain.ioc.parser import parse_ioc
from app.domain.ioc.types import IocType
from app.domain.quota.service import get_quota_service, get_quota_store
from app.schemas.investigation import InvestigationRequest, InvestigationResponse
from app.services.orchestrator import InvestigationOrchestrator, get_orchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("/history", response_model=list[dict])
async def investigation_history(
    user: CurrentUser = Depends(get_current_user),
    store=Depends(get_quota_store),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict]:
    return store.list_investigations(user, limit)


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_200_OK)
async def investigate_ioc(
    payload: InvestigationRequest,
    user: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
    orchestrator: InvestigationOrchestrator = Depends(get_orchestrator),
    quota_service=Depends(get_quota_service),
    store=Depends(get_quota_store),
    x_byok_providers: str | None = Header(default=None),
) -> InvestigationResponse:
    parsed_ioc = parse_ioc(payload.ioc)
    if parsed_ioc.type == IocType.UNKNOWN:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Unsupported or malformed IOC.",
        )

    byok_providers = {
        provider.strip() for provider in (x_byok_providers or "").split(",") if provider.strip()
    }
    quota_decision = quota_service.reserve(user, settings.daily_free_quota, byok_providers)
    if not quota_decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Daily free quota exhausted. Configure BYOK to continue.",
        )

    result = await orchestrator.investigate(
        payload.ioc,
        used_byok=quota_decision.used_byok,
        quota={
            "free_queries_used": quota_decision.free_queries_used,
            "byok_queries_used": quota_decision.byok_queries_used,
            "reason": quota_decision.reason,
            "daily_free_quota": settings.daily_free_quota,
        },
    )
    try:
        store.save_investigation(user, result)
    except Exception:  # noqa: BLE001 - persistence must never break the response
        logger.exception("Failed to persist investigation")
    return result
