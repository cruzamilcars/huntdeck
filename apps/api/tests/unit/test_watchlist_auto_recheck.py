import pytest
from fastapi.testclient import TestClient

from app.core.security import CurrentUser, get_current_user
from app.domain.ioc.parser import parse_ioc
from app.domain.quota.service import get_quota_store
from app.infrastructure.store import SqliteStore
from app.main import app
from app.schemas.investigation import InvestigationResponse, RiskSummary
from app.services.orchestrator import get_orchestrator


class FakeOrchestrator:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def investigate(self, raw_ioc: str, **kwargs) -> InvestigationResponse:
        self.calls.append(raw_ioc)
        return InvestigationResponse.model_construct(
            ioc=parse_ioc(raw_ioc),
            risk=RiskSummary(score=55, severity="medium"),
        )


@pytest.fixture()
def watch_env(tmp_path):
    store = SqliteStore(str(tmp_path / "auto.db"))
    user = CurrentUser(user_id="u1", org_id="o1")
    fake = FakeOrchestrator()
    app.dependency_overrides[get_quota_store] = lambda: store
    app.dependency_overrides[get_orchestrator] = lambda: fake
    app.dependency_overrides[get_current_user] = lambda: user
    yield store, user, fake, TestClient(app)
    app.dependency_overrides.clear()


def test_auto_recheck_refreshes_stale_items(watch_env) -> None:
    store, user, fake, client = watch_env
    store.add_watch_item(user, parse_ioc("8.8.8.8"))
    store.add_watch_item(user, parse_ioc("example.com"))
    # Fresh item: must NOT be refreshed.
    store.touch_watch_item(user, "example.com", 5, "low")

    response = client.get("/api/v1/watchlist")

    assert response.status_code == 200
    items = {item["normalized_ioc"]: item for item in response.json()}
    assert len(fake.calls) == 1
    assert fake.calls == ["8.8.8.8"]
    assert items["8.8.8.8"]["last_severity"] == "medium"
    assert items["8.8.8.8"]["last_risk_score"] == 55


def test_auto_recheck_respects_budget(watch_env) -> None:
    store, user, fake, client = watch_env
    store.add_watch_item(user, parse_ioc("8.8.8.8"))
    store.add_watch_item(user, parse_ioc("example.com"))

    response = client.get("/api/v1/watchlist?recheck_max=1")

    assert response.status_code == 200
    assert len(fake.calls) == 1

    response = client.get("/api/v1/watchlist?recheck_max=1")
    assert len(fake.calls) == 2


def test_read_only_listing_skips_rechecks(watch_env) -> None:
    store, user, fake, client = watch_env
    store.add_watch_item(user, parse_ioc("8.8.8.8"))

    response = client.get("/api/v1/watchlist?recheck_max=0")

    assert response.status_code == 200
    assert fake.calls == []
    item = response.json()[0]
    assert item["last_checked_at"] is None


def test_fresh_items_are_not_rechecked(watch_env) -> None:
    store, user, fake, client = watch_env
    store.add_watch_item(user, parse_ioc("example.com"))
    store.touch_watch_item(user, "example.com", 5, "low")

    client.get("/api/v1/watchlist?recheck_ttl_hours=24")

    assert fake.calls == []
