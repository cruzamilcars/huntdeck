from dataclasses import dataclass
from datetime import UTC, date, datetime
from threading import Lock

from app.core.security import CurrentUser


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    used_byok: bool
    free_queries_used: int
    byok_queries_used: int
    reason: str


class InMemoryQuotaService:
    def __init__(self) -> None:
        self._lock = Lock()
        self._usage: dict[tuple[str, str, date], dict[str, int]] = {}

    def reserve(
        self,
        user: CurrentUser,
        daily_free_quota: int,
        byok_providers: set[str],
    ) -> QuotaDecision:
        today = datetime.now(UTC).date()
        key = (user.org_id, user.user_id, today)

        with self._lock:
            usage = self._usage.setdefault(key, {"free": 0, "byok": 0})
            if usage["free"] < daily_free_quota:
                usage["free"] += 1
                return QuotaDecision(
                    allowed=True,
                    used_byok=False,
                    free_queries_used=usage["free"],
                    byok_queries_used=usage["byok"],
                    reason="platform_quota",
                )

            if byok_providers:
                usage["byok"] += 1
                return QuotaDecision(
                    allowed=True,
                    used_byok=True,
                    free_queries_used=usage["free"],
                    byok_queries_used=usage["byok"],
                    reason="byok",
                )

            return QuotaDecision(
                allowed=False,
                used_byok=False,
                free_queries_used=usage["free"],
                byok_queries_used=usage["byok"],
                reason="quota_exhausted",
            )


class SqliteQuotaService:
    """Quota backed by the durable SQLite store.

    Same decision flow as InMemoryQuotaService, but usage survives process
    restarts via the shared store.
    """

    def __init__(self, quota_store) -> None:
        self._store = quota_store

    def reserve(
        self,
        user: CurrentUser,
        daily_free_quota: int,
        byok_providers: set[str],
    ) -> QuotaDecision:
        allowed, used_byok, free, byok, reason = self._store.reserve_usage(
            user,
            datetime.now(UTC).date(),
            daily_free_quota,
            byok_providers,
        )
        return QuotaDecision(
            allowed=allowed,
            used_byok=used_byok,
            free_queries_used=free,
            byok_queries_used=byok,
            reason=reason,
        )


def _build_quota_service():
    import logging

    from app.core.config import get_settings
    from app.infrastructure.store import SqliteStore
    from app.infrastructure.supabase_store import SupabaseStore

    log = logging.getLogger(__name__)
    settings = get_settings()

    if settings.supabase_url and settings.supabase_service_role_key:
        store = SupabaseStore(
            url=settings.supabase_url,
            service_role_key=settings.supabase_service_role_key,
        )
        log.info("Quota store: Supabase (PostgREST, service role)")
    else:
        store = SqliteStore(settings.database_path)
        log.info(
            "Quota store: local SQLite (%s). Set SUPABASE_URL and "
            "SUPABASE_SERVICE_ROLE_KEY to switch to Supabase persistence.",
            settings.database_path,
        )
    return SqliteQuotaService(store), store


_quota_service = None
_quota_store = None


def get_quota_service() -> SqliteQuotaService:
    global _quota_service, _quota_store
    if _quota_service is None:
        _quota_service, _quota_store = _build_quota_service()
    return _quota_service


def get_quota_store():
    get_quota_service()
    return _quota_store
