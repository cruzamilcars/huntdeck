from datetime import date

from fastapi.testclient import TestClient

from app.core.security import CurrentUser
from app.domain.ioc.types import IocType, ParsedIoc
from app.infrastructure.store import SqliteStore
from app.main import app
from app.schemas.investigation import InvestigationResponse, RiskSummary


def response_for(ioc: str) -> InvestigationResponse:
    return InvestigationResponse(
        ioc=ParsedIoc(raw=ioc, normalized=ioc, type=IocType.IPV4),
        risk=RiskSummary(score=18, severity="low"),
        modules={},
        mappings={},
        sources=["mock"],
        mcp_servers_queried=["mock"],
        used_byok=False,
        quota={"reason": "platform_quota"},
    )


def test_quota_persists_across_store_instances(tmp_path) -> None:
    db_path = str(tmp_path / "quota.db")
    user = CurrentUser(user_id="u1", org_id="o1")

    store = SqliteStore(db_path)
    first = store.reserve_usage(user, date(2026, 1, 1), 2, set())
    reopened = SqliteStore(db_path)
    second = reopened.reserve_usage(user, date(2026, 1, 1), 2, set())
    third = reopened.reserve_usage(user, date(2026, 1, 1), 2, set())

    assert first == (True, False, 1, 0, "platform_quota")
    assert second == (True, False, 2, 0, "platform_quota")
    assert third == (False, False, 2, 0, "quota_exhausted")


def test_history_saves_and_lists_latest_first(tmp_path) -> None:
    store = SqliteStore(str(tmp_path / "history.db"))
    user = CurrentUser(user_id="u1", org_id="o1")
    other = CurrentUser(user_id="u2", org_id="o1")

    store.save_investigation(user, response_for("8.8.8.8"))
    store.save_investigation(user, response_for("example.com"))
    store.save_investigation(other, response_for("1.1.1.1"))

    history = store.list_investigations(user)
    assert [row["normalized_ioc"] for row in history] == ["example.com", "8.8.8.8"]
    assert history[0]["severity"] == "low"
    assert history[0]["used_byok"] == 0


def test_history_scoped_by_user(tmp_path) -> None:
    store = SqliteStore(str(tmp_path / "history.db"))
    user = CurrentUser(user_id="u1", org_id="o1")
    other = CurrentUser(user_id="u2", org_id="o2")

    store.save_investigation(user, response_for("8.8.8.8"))
    store.save_investigation(other, response_for("1.1.1.1"))

    assert len(store.list_investigations(user)) == 1
    assert len(store.list_investigations(other)) == 1


def test_api_history_endpoint_returns_saved_investigations() -> None:
    client = TestClient(app)

    post = client.post("/api/v1/investigations", json={"ioc": "8.8.8.8"})
    assert post.status_code == 200

    history = client.get("/api/v1/investigations/history")
    assert history.status_code == 200
    rows = history.json()
    assert rows
    assert rows[0]["normalized_ioc"] == "8.8.8.8"
    assert 0 <= rows[0]["risk_score"] <= 100
