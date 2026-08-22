from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware

from app.core.config import Settings
from app.core.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from app.core.security import hash_api_key
from app.domain.quota import service as quota_service
from app.infrastructure.store import SqliteStore
from app.main import create_app


def _client(rate_limit: int = 3, service_limit: int = 6) -> TestClient:
    settings = Settings(
        rate_limit_per_minute=rate_limit, service_rate_limit_per_minute=service_limit
    )
    app_instance = create_app()
    # Rebuild the middleware stack with deterministic limits for the test.
    app_instance.user_middleware.clear()
    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_methods=["GET"],
    )
    app_instance.add_middleware(SecurityHeadersMiddleware)
    app_instance.add_middleware(RateLimitMiddleware, settings=settings)
    return TestClient(app_instance)


def test_anonymous_traffic_hits_ip_limit() -> None:
    client = _client(rate_limit=2)

    assert client.get("/health").status_code == 200  # health is exempt
    assert client.get("/api/v1/system/providers").status_code == 200
    assert client.get("/api/v1/system/providers").status_code == 200
    limited = client.get("/api/v1/system/providers")
    assert limited.status_code == 429
    assert "Rate limit" in limited.json()["detail"]


def test_service_key_gets_separate_higher_budget(tmp_path, monkeypatch) -> None:
    store = SqliteStore(str(tmp_path / "rl.db"))
    store.create_api_key("siem", "o1", hash_api_key("hd_siem-token"))
    monkeypatch.setattr(quota_service, "_quota_service", object())
    monkeypatch.setattr(quota_service, "_quota_store", store)

    client = _client(rate_limit=1, service_limit=5)
    headers = {"X-API-Key": "hd_siem-token"}

    statuses = [
        client.get("/api/v1/system/providers", headers=headers).status_code for _ in range(5)
    ]
    assert all(code == 200 for code in statuses)

    exhausted = client.get("/api/v1/system/providers", headers=headers)
    assert exhausted.status_code == 429

    # Anonymous identity still has its own budget untouched.
    assert client.get("/api/v1/system/providers").status_code == 200


def test_distinct_keys_have_independent_buckets(tmp_path, monkeypatch) -> None:
    store = SqliteStore(str(tmp_path / "rl.db"))
    store.create_api_key("a", "o1", hash_api_key("hd_key-a"))
    store.create_api_key("b", "o1", hash_api_key("hd_key-b"))
    monkeypatch.setattr(quota_service, "_quota_service", object())
    monkeypatch.setattr(quota_service, "_quota_store", store)

    client = _client(rate_limit=1, service_limit=1)

    assert (
        client.get("/api/v1/system/providers", headers={"X-API-Key": "hd_key-a"}).status_code == 200
    )
    assert (
        client.get("/api/v1/system/providers", headers={"X-API-Key": "hd_key-a"}).status_code == 429
    )
    assert (
        client.get("/api/v1/system/providers", headers={"X-API-Key": "hd_key-b"}).status_code == 200
    )
