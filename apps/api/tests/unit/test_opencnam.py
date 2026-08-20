import httpx
import pytest

from app.agents.mcp.opencnam import BASE_URL, OpenCnamMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> OpenCnamMcpClient:
    transport = httpx.MockTransport(handler)
    return OpenCnamMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_phone_with_owner_maps_attribution() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v3/phone/+15555550101"
        assert request.headers["Authorization"] == "Bearer test-key"
        return httpx.Response(
            200,
            json={
                "name": "ACME CORP",
                "number": "+15555550101",
                "carrier": "Verizon",
                "type": "mobile",
            },
        )

    observation = await build_client(handler).query(parse_ioc("+1 (555) 555-0101"))

    assert observation.source == "mcp-opencnam"
    assert observation.raw["mock"] is False
    assert observation.raw["cnam_name"] == "ACME CORP"
    assert observation.reputation["verdict"] == "clean"
    assert "opencnam:attributed" in observation.reputation["tags"]
    assert {"kind": "served_by", "target": "Verizon"} in observation.relationships


async def test_phone_without_owner_is_unknown() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"name": None, "number": "+15555550101"})

    observation = await build_client(handler).query(parse_ioc("+15555550101"))

    assert observation.reputation["verdict"] == "unknown"
    assert "opencnam:no-owner" in observation.reputation["tags"]


async def test_unsupported_ioc_type_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("example.com"))

    assert observation.raw["error"] == "opencnam_unsupported_ioc"
    assert observation.reputation == {}


async def test_http_error_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"error": "invalid"})

    observation = await build_client(handler).query(parse_ioc("+15555550101"))

    assert observation.raw["error"] == "opencnam_invalid_number"
    assert observation.reputation == {}


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="OPENCNAM_API_KEY"):
        OpenCnamMcpClient(api_key="")
