import json
from datetime import date

import httpx
import pytest

from app.core.security import CurrentUser
from app.domain.ioc.types import IocType, ParsedIoc
from app.infrastructure.supabase_store import SupabaseStore
from app.schemas.investigation import InvestigationResponse, RiskSummary


def response_for(ioc: str) -> InvestigationResponse:
    return InvestigationResponse(
        ioc=ParsedIoc(raw=ioc, normalized=ioc, type=IocType.IPV4),
        risk=RiskSummary(score=42, severity="medium"),
        modules={},
        mappings={},
        sources=["mock"],
        mcp_servers_queried=["mock"],
        used_byok=False,
        quota={"reason": "platform_quota"},
    )


def store_with(handler) -> SupabaseStore:
    transport = httpx.MockTransport(handler)
    return SupabaseStore(
        url="https://project.supabase.co",
        service_role_key="test-service-role",
        transport=transport,
    )


def test_reserve_usage_calls_rpc_and_returns_decision() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/rest/v1/rpc/reserve_daily_usage"
        assert request.headers["apikey"] == "test-service-role"
        payload = json.loads(request.read().decode())
        assert payload["p_org_id"] == "o1"
        assert payload["p_usage_date"] == "2026-01-01"
        assert payload["p_byok_providers"] == ["virustotal"]
        return httpx.Response(
            200,
            json={
                "allowed": True,
                "used_byok": True,
                "free_queries_used": 3,
                "byok_queries_used": 2,
                "reason": "byok",
            },
        )

    store = store_with(handler)
    user = CurrentUser(user_id="u1", org_id="o1")
    decision = store.reserve_usage(user, date(2026, 1, 1), 10, {"virustotal"})

    assert decision == (True, True, 3, 2, "byok")


def test_reserve_usage_exhausted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "allowed": False,
                "used_byok": False,
                "free_queries_used": 10,
                "byok_queries_used": 0,
                "reason": "quota_exhausted",
            },
        )

    store = store_with(handler)
    user = CurrentUser(user_id="u1", org_id="o1")
    decision = store.reserve_usage(user, date(2026, 1, 1), 10, set())

    assert decision == (False, False, 10, 0, "quota_exhausted")


def test_save_investigation_posts_row() -> None:
    seen: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.read())
        return httpx.Response(201, json=[{}])

    store = store_with(handler)
    store.save_investigation(
        CurrentUser(user_id="u1", org_id="o1"),
        response_for("8.8.8.8"),
    )

    payload = json.loads(seen[0].decode())
    assert payload["raw_ioc"] == "8.8.8.8"
    assert payload["ioc_type"] == "ipv4"
    assert payload["org_id"] == "o1"
    assert "result_json" in payload


def test_list_investigations_queries_scoped_and_flattens_sources() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/rest/v1/investigations"
        params = request.url.params
        assert params["org_id"] == "eq.o1"
        assert params["user_id"] == "eq.u1"
        assert params["order"] == "created_at.desc"
        assert params["limit"] == "5"
        assert "sources" in params["select"]
        return httpx.Response(
            200,
            json=[
                {
                    "raw_ioc": "1.1.1.1",
                    "normalized_ioc": "1.1.1.1",
                    "ioc_type": "ipv4",
                    "risk_score": 54,
                    "severity": "medium",
                    "sources": ["mcp-virustotal"],
                    "used_byok": False,
                    "created_at": "2026-08-10T23:50:45+00:00",
                }
            ],
        )

    store = store_with(handler)
    rows = store.list_investigations(CurrentUser(user_id="u1", org_id="o1"), limit=5)

    assert rows[0]["normalized_ioc"] == "1.1.1.1"
    assert rows[0]["sources"] == '["mcp-virustotal"]'


def test_supabase_errors_raise_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Invalid API key"})

    store = store_with(handler)
    user = CurrentUser(user_id="u1", org_id="o1")

    with pytest.raises(httpx.HTTPStatusError):
        store.reserve_usage(user, date(2026, 1, 1), 10, set())
