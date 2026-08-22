import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import CurrentUser, get_current_user
from app.domain.ioc.parser import parse_ioc
from app.domain.ioc.types import IocType
from app.domain.quota.service import get_quota_store
from app.schemas.investigation import InvestigationResponse
from app.services.orchestrator import InvestigationOrchestrator, get_orchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


@router.get("", response_model=list[dict])
async def list_watchlist(
    user: CurrentUser = Depends(get_current_user),
    store=Depends(get_quota_store),
    orchestrator: InvestigationOrchestrator = Depends(get_orchestrator),
    recheck_ttl_hours: int = Query(default=24, ge=0, le=720),
    recheck_max: int = Query(default=3, ge=0, le=10),
) -> list[dict]:
    """List watch items, lazily refreshing the stalest ones first.

    Items never checked or older than ``recheck_ttl_hours`` are re-investigated
    automatically, at most ``recheck_max`` per call so a single request can
    never exhaust quota. Set ``recheck_max=0`` for a read-only listing.
    """
    items = store.list_watch_items(user)
    if recheck_max == 0:
        return items

    cutoff = datetime.now(UTC) - timedelta(hours=recheck_ttl_hours)
    stale = [item for item in items if _checked_before(item.get("last_checked_at"), cutoff)]
    stale.sort(key=lambda item: item.get("last_checked_at") or "")

    refreshed = 0
    for item in stale:
        if refreshed >= recheck_max:
            break
        try:
            result = await orchestrator.investigate(
                item["raw_ioc"],
                used_byok=False,
                quota={"reason": "watchlist_auto_recheck"},
            )
            store.touch_watch_item(
                user, item["normalized_ioc"], result.risk.score, result.risk.severity
            )
            refreshed += 1
        except Exception:  # noqa: BLE001 - listing must survive provider failures
            logger.exception("Auto-recheck failed for %s", item["normalized_ioc"])

    if refreshed:
        return store.list_watch_items(user)
    return items


def _checked_before(last_checked_at: str | None, cutoff: datetime) -> bool:
    if not last_checked_at:
        return True
    try:
        checked_at = datetime.fromisoformat(str(last_checked_at))
    except ValueError:
        return True
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=UTC)
    return checked_at < cutoff


@router.post("", response_model=dict, status_code=status.HTTP_201_CREATED)
async def add_to_watchlist(
    payload: dict,
    user: CurrentUser = Depends(get_current_user),
    store=Depends(get_quota_store),
) -> dict:
    raw_ioc = str(payload.get("ioc") or "").strip()
    parsed_ioc = parse_ioc(raw_ioc)
    if parsed_ioc.type == IocType.UNKNOWN:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Unsupported or malformed IOC.",
        )
    return store.add_watch_item(user, parsed_ioc, note=str(payload.get("note") or "") or None)


@router.delete("/{normalized_ioc}")
async def remove_from_watchlist(
    normalized_ioc: str,
    user: CurrentUser = Depends(get_current_user),
    store=Depends(get_quota_store),
) -> dict[str, bool]:
    removed = store.remove_watch_item(user, normalized_ioc)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Watch item not found.",
        )
    return {"removed": True}


@router.post("/{normalized_ioc}/recheck", response_model=InvestigationResponse)
async def recheck_watch_item(
    normalized_ioc: str,
    user: CurrentUser = Depends(get_current_user),
    store=Depends(get_quota_store),
    orchestrator: InvestigationOrchestrator = Depends(get_orchestrator),
) -> InvestigationResponse:
    items = store.list_watch_items(user)
    target = next((item for item in items if item["normalized_ioc"] == normalized_ioc), None)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Watch item not found.",
        )

    result = await orchestrator.investigate(
        target["raw_ioc"],
        used_byok=False,
        quota={"reason": "watchlist_recheck"},
    )
    try:
        store.touch_watch_item(user, normalized_ioc, result.risk.score, result.risk.severity)
    except Exception:  # noqa: BLE001 - recheck must not fail because of persistence
        logger.exception("Failed to update watch item %s", normalized_ioc)
    return result
