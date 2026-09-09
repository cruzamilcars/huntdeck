import json

import httpx
import pytest

from app.agents.mcp.intelx import BASE_URL, IntelxMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> IntelxMcpClient:
    transport = httpx.MockTransport(handler)
    return IntelxMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_email_leak_found_is_suspicious() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/intelligent/search":
            return httpx.Response(
                200,
                json={"status": 2, "results": [{"name": "analyst", "bucket": "leaks"}] * 3},
            )
        assert request.url.path == "/email/search"
        assert request.headers["x-key"] == "test-key"
        body = json.loads(request.content)
        assert body["term"] == "analyst@example.com"
        return httpx.Response(200, json={"id": 42, "status": 0})

    obs = await build_client(handler).query(parse_ioc("analyst@example.com"))
    assert obs.raw["entity"] == "analyst@example.com"
    assert obs.raw["search_id"] == 42
    assert obs.reputation["verdict"] == "suspicious"
    assert any("leak-found" in tag for tag in obs.reputation["tags"])


async def test_no_results_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 0, "status": 1})

    obs = await build_client(handler).query(parse_ioc("clean@example.com"))
    assert obs.reputation["verdict"] == "clean"
    assert "intelx:no-leak-found" in obs.reputation["tags"]


async def test_phone_result_includes_carrier_geolocation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/intelligent/search":
            return httpx.Response(200, json={"status": 2, "results": []})
        return httpx.Response(
            200,
            json={
                "id": 7,
                "status": 2,
                "operator": "T-Mobile",
                "country": "US",
                "spam": "yes",
            },
        )

    obs = await build_client(handler).query(parse_ioc("+1 4155550101"))
    assert obs.geolocation is not None
    assert obs.geolocation["carrier"] == "T-Mobile"
    assert obs.reputation["verdict"] == "suspicious"


async def test_domain_supported_and_results_fetched() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/domain/search":
            return httpx.Response(200, json={"id": 9, "status": 0})
        return httpx.Response(
            200,
            json={
                "status": 2,
                "results": [{"name": "analyst", "bucket": "leaks"}] * 4,
            },
        )

    obs = await build_client(handler).query(parse_ioc("example.com"))
    assert obs.reputation["verdict"] == "suspicious"
    assert obs.raw["records_found"] == 4
    assert obs.community_reports


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "intelx_unsupported_ioc"


async def test_unreachable_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    obs = await build_client(handler).query(parse_ioc("analyst@example.com"))
    assert obs.raw["error"] == "intelx_unreachable"


def test_missing_key_rejected() -> None:
    with pytest.raises(ValueError, match="INTELX_API_KEY"):
        IntelxMcpClient(api_key="")
