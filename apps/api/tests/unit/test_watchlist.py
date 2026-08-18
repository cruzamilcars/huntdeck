import httpx
from fastapi.testclient import TestClient

from app.core.security import CurrentUser
from app.domain.ioc.parser import parse_ioc
from app.infrastructure.supabase_store import SupabaseStore
from app.main import app


def test_watchlist_add_list_remove(tmp_path) -> None:
    from app.infrastructure.store import SqliteStore

    store = SqliteStore(str(tmp_path / "watch.db"))
    user = CurrentUser(user_id="u1", org_id="o1")

    created = store.add_watch_item(user, parse_ioc("8.8.8.8"), note="router")
    assert created["normalized_ioc"] == "8.8.8.8"
    assert created["ioc_type"] == "ipv4"

    items = store.list_watch_items(user)
    assert len(items) == 1
    assert items[0]["note"] == "router"

    store.touch_watch_item(user, "8.8.8.8", 72, "high")
    items = store.list_watch_items(user)
    assert items[0]["last_risk_score"] == 72
    assert items[0]["last_severity"] == "high"

    assert store.remove_watch_item(user, "8.8.8.8") is True
    assert store.list_watch_items(user) == []


def test_watchlist_add_is_idempotent(tmp_path) -> None:
    from app.infrastructure.store import SqliteStore

    store = SqliteStore(str(tmp_path / "watch.db"))
    user = CurrentUser(user_id="u1", org_id="o1")

    store.add_watch_item(user, parse_ioc("8.8.8.8"))
    store.add_watch_item(user, parse_ioc("8.8.8.8"))
    assert len(store.list_watch_items(user)) == 1


def test_watchlist_api_crud() -> None:
    client = TestClient(app)

    created = client.post("/api/v1/watchlist", json={"ioc": "example.com", "note": "campaign A"})
    assert created.status_code == 201
    assert created.json()["normalized_ioc"] == "example.com"

    listing = client.get("/api/v1/watchlist")
    assert listing.status_code == 200
    assert [row["normalized_ioc"] for row in listing.json()] == ["example.com"]

    removed = client.delete("/api/v1/watchlist/example.com")
    assert removed.status_code == 200
    assert removed.json() == {"removed": True}

    missing = client.delete("/api/v1/watchlist/example.com")
    assert missing.status_code == 404


def test_watchlist_api_rejects_unknown_ioc() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/watchlist", json={"ioc": "not an ioc at all"})
    assert response.status_code == 422


def test_watchlist_recheck_runs_investigation() -> None:
    client = TestClient(app)
    client.post("/api/v1/watchlist", json={"ioc": "8.8.8.8"})

    recheck = client.post("/api/v1/watchlist/8.8.8.8/recheck")
    assert recheck.status_code == 200
    body = recheck.json()
    assert body["ioc"]["normalized"] == "8.8.8.8"
    assert body["quota"]["reason"] == "watchlist_recheck"

    rows = client.get("/api/v1/watchlist").json()
    assert rows[0]["last_risk_score"] is not None
    assert rows[0]["last_severity"] == body["risk"]["severity"]


def test_supabase_watchlist_upsert_and_remove() -> None:
    calls: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url), request.headers.get("prefer", "")))
        if request.method == "POST":
            return httpx.Response(
                201,
                json=[
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "normalized_ioc": "8.8.8.8",
                        "ioc_type": "ipv4",
                        "note": None,
                    }
                ],
            )
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(204, json=[])

    transport = httpx.MockTransport(handler)
    store = SupabaseStore(
        url="https://project.supabase.co",
        service_role_key="test-service-role",
        transport=transport,
    )
    user = CurrentUser(user_id="u1", org_id="o1")

    created = store.add_watch_item(user, parse_ioc("8.8.8.8"))
    assert created["normalized_ioc"] == "8.8.8.8"

    assert store.list_watch_items(user) == []
    assert store.remove_watch_item(user, "8.8.8.8") is True

    post_path = next(path for method, path, _ in calls if method == "POST")
    post_prefer = next(prefer for method, _, prefer in calls if method == "POST")
    assert "on_conflict=org_id%2Cuser_id%2Cnormalized_ioc" in post_path
    assert "return=representation" in post_prefer
