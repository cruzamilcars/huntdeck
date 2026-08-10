from app.core.security import CurrentUser
from app.domain.quota.service import InMemoryQuotaService


def test_quota_uses_free_allowance_before_byok() -> None:
    service = InMemoryQuotaService()
    user = CurrentUser(user_id="u1", org_id="o1")

    first = service.reserve(user, daily_free_quota=1, byok_providers=set())
    second = service.reserve(user, daily_free_quota=1, byok_providers={"virustotal"})

    assert first.allowed is True
    assert first.used_byok is False
    assert second.allowed is True
    assert second.used_byok is True


def test_quota_blocks_without_byok_after_free_allowance() -> None:
    service = InMemoryQuotaService()
    user = CurrentUser(user_id="u2", org_id="o1")

    service.reserve(user, daily_free_quota=1, byok_providers=set())
    blocked = service.reserve(user, daily_free_quota=1, byok_providers=set())

    assert blocked.allowed is False
    assert blocked.reason == "quota_exhausted"
