from fastapi.testclient import TestClient

from app.core.security import hash_api_key
from app.infrastructure.store import SqliteStore


def test_api_key_crud_and_verification(tmp_path) -> None:
    store = SqliteStore(str(tmp_path / "keys.db"))

    key_id = store.create_api_key("ci-bot", "o1", hash_api_key("hd_secret-token"))
    assert key_id == 1

    rows = store.list_api_keys()
    assert len(rows) == 1
    assert rows[0]["name"] == "ci-bot"
    assert rows[0]["enabled"] == 1

    assert store.verify_api_key(hash_api_key("hd_secret-token")) == "o1"
    assert store.verify_api_key(hash_api_key("hd_wrong")) is None

    assert store.revoke_api_key(key_id) is True
    assert store.verify_api_key(hash_api_key("hd_secret-token")) is None
    assert store.revoke_api_key(key_id) is False


def test_api_key_grant_http_access(tmp_path, monkeypatch) -> None:
    from app.domain.quota import service as quota_service
    from app.infrastructure.store import SqliteStore

    store = SqliteStore(str(tmp_path / "keys.db"))
    key_id = store.create_api_key("ci-bot", "o1", hash_api_key("hd_secret-token"))
    assert key_id == 1

    monkeypatch.setattr(quota_service, "_quota_service", object())
    monkeypatch.setattr(quota_service, "_quota_store", store)

    client = TestClient(__import__("app.main", fromlist=["app"]).app)

    authorized = client.get(
        "/api/v1/investigations/history", headers={"X-API-Key": "hd_secret-token"}
    )
    assert authorized.status_code == 200

    rejected = client.get("/api/v1/investigations/history", headers={"X-API-Key": "hd_wrong"})
    assert rejected.status_code == 401

    dev = client.get("/api/v1/investigations/history")
    assert dev.status_code == 200
    assert dev.json() == []


def test_api_key_works_as_bearer_token(tmp_path, monkeypatch) -> None:
    from app.domain.quota import service as quota_service
    from app.infrastructure.store import SqliteStore

    store = SqliteStore(str(tmp_path / "keys.db"))
    store.create_api_key("ci-bot", "o1", hash_api_key("hd_secret-token"))

    monkeypatch.setattr(quota_service, "_quota_service", object())
    monkeypatch.setattr(quota_service, "_quota_store", store)

    client = TestClient(__import__("app.main", fromlist=["app"]).app)

    response = client.get(
        "/api/v1/investigations/history",
        headers={"Authorization": "Bearer hd_secret-token"},
    )
    assert response.status_code == 200
