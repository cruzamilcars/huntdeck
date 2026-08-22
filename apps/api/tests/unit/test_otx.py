import httpx
import pytest

from app.agents.mcp.otx import BASE_URL, OtxMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> OtxMcpClient:
    transport = httpx.MockTransport(handler)
    return OtxMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_ip_with_pulses_maps_reputation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/indicators/IPv4/8.8.8.8/general"
        assert request.headers["X-OTX-API-KEY"] == "test-key"
        return httpx.Response(
            200,
            json={
                "pulse_info": {
                    "count": 7,
                    "pulses": [
                        {"name": "Botnet C2", "description": "Known C2", "tags": ["botnet", "c2"]},
                        {"name": "Scanner", "description": "", "tags": []},
                    ],
                },
                "reputation": {"orders": 1},
                "country_name": "United States",
                "asn": "AS15169",
            },
        )

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.source == "mcp-otx"
    assert observation.raw["mock"] is False
    assert observation.raw["pulse_count"] == 7
    assert observation.reputation["verdict"] == "malicious"
    assert observation.reputation["score"] == 85
    assert "otx:pulse:Botnet C2" in observation.reputation["tags"]
    assert len(observation.community_reports) == 2
    assert observation.community_reports[0]["summary"] == "Known C2"
    assert observation.geolocation == {
        "provider": "mcp-otx",
        "country": "United States",
        "asn": "AS15169",
    }


async def test_hash_without_pulses_is_clean() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert (
            request.url.path == "/api/v1/indicators/file/44d88612fea8a8f36de82e1278abb02f/general"
        )
        return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}})

    observation = await build_client(handler).query(parse_ioc("44d88612fea8a8f36de82e1278abb02f"))

    assert observation.reputation["verdict"] == "clean"
    assert observation.reputation["score"] == 0
    assert observation.geolocation is None


async def test_url_is_percent_encoded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert (
            request.url.raw_path.decode()
            == "/api/v1/indicators/url/https%3A%2F%2Fevil.example.com%2Fa/general"
        )
        return httpx.Response(200, json={"pulse_info": {"count": 1, "pulses": [{"name": "Phish"}]}})

    observation = await build_client(handler).query(parse_ioc("https://evil.example.com/a"))

    assert observation.reputation["verdict"] == "suspicious"


async def test_unsupported_ioc_type_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("analyst@example.com"))

    assert observation.raw["error"] == "otx_unsupported_ioc"
    assert observation.reputation == {}


async def test_rate_limit_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"detail": "slow down"})

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "otx_rate_limited"
    assert observation.reputation == {}


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="OTX_API_KEY"):
        OtxMcpClient(api_key="")
