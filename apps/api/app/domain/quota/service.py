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


quota_service = InMemoryQuotaService()
