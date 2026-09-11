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


def test_stats_aggregates_history(tmp_path) -> None:
    store = SqliteStore(str(tmp_path / "stats.db"))
    user = CurrentUser(user_id="u1", org_id="o1")

    store.save_investigation(user, response_for("8.8.8.8"))
    store.save_investigation(user, response_for("8.8.8.8"))
    store.save_investigation(
        user,
        InvestigationResponse(
            ioc=ParsedIoc(raw="example.com", normalized="example.com", type=IocType.DOMAIN),
            risk=RiskSummary(score=18, severity="low"),
            modules={},
            mappings={},
            sources=["mock"],
            mcp_servers_queried=["mock"],
            used_byok=False,
            quota={"reason": "platform_quota"},
        ),
    )

    stats = store.stats(user)

    assert stats["total"] == 3
    assert stats["by_type"] == {"ipv4": 2, "domain": 1}
    assert stats["by_severity"] == {"low": 3}
    assert stats["avg_risk_score"] == 18.0
    assert stats["byok_count"] == 0
    assert stats["top_iocs"][0] == {"ioc": "8.8.8.8", "count": 2}
    assert stats["daily"][-1]["count"] == 3
    assert stats["sources_used"] == [{"source": "mock", "count": 3}]


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


def test_prune_deletes_only_older_than_retention(tmp_path) -> None:
    store = SqliteStore(str(tmp_path / "retention.db"))
    user = CurrentUser(user_id="u1", org_id="o1")

    store.save_investigation(user, response_for("8.8.8.8"))

    from datetime import UTC, datetime, timedelta

    stale_created = (datetime.now(UTC) - timedelta(days=91)).isoformat()
    with store._lock:
        store._connection.execute(
            "INSERT INTO investigations "
            "(org_id, user_id, raw_ioc, normalized_ioc, ioc_type, risk_score, "
            " severity, sources, result_json, used_byok, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "o1",
                "u1",
                "example.com",
                "example.com",
                "domain",
                18,
                "low",
                '["mock"]',
                "{}",
                0,
                stale_created,
            ),
        )
        store._connection.commit()

    removed = store.prune_investigations(retention_days=90)

    assert removed == 1
    remaining = [row["normalized_ioc"] for row in store.list_investigations(user)]
    assert remaining == ["8.8.8.8"]


def test_prune_zero_days_is_disabled(tmp_path) -> None:
    store = SqliteStore(str(tmp_path / "retention-off.db"))
    user = CurrentUser(user_id="u1", org_id="o1")

    store.save_investigation(user, response_for("8.8.8.8"))

    from datetime import UTC, datetime, timedelta

    stale_created = (datetime.now(UTC) - timedelta(days=365)).isoformat()
    with store._lock:
        store._connection.execute(
            "UPDATE investigations SET created_at = ? WHERE normalized_ioc = '8.8.8.8'",
            (stale_created,),
        )
        store._connection.commit()

    assert store.prune_investigations(retention_days=0) == 0
    assert len(store.list_investigations(user)) == 1


def test_supabase_prune_sends_filtered_delete() -> None:
    import httpx

    from app.infrastructure.supabase_store import SupabaseStore

    captured: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append((request.method, str(request.url)))
        return httpx.Response(200, json=[{"id": "row-1"}, {"id": "row-2"}])

    store = SupabaseStore(
        url="https://project.supabase.co",
        service_role_key="test-service-role",
        transport=httpx.MockTransport(handler),
    )

    removed = store.prune_investigations(retention_days=90)

    assert removed == 2
    method, url = captured[0]
    assert method == "DELETE"
    assert "/rest/v1/investigations" in url
    assert "created_at=lt." in url
    assert store.prune_investigations(retention_days=0) == 0
    assert captured == [(method, url)]  # disabled call made no request


def test_startup_purge_is_best_effort(monkeypatch) -> None:
    from app.main import _purge_expired_history

    def boom(_days: int) -> int:
        raise RuntimeError("store unavailable")

    import app.domain.quota.service as quota_service

    monkeypatch.setattr(quota_service, "get_quota_store", lambda: boom)

    # Must not raise even when the store blows up at startup.
    _purge_expired_history(90)
