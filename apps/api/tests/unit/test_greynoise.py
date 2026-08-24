import httpx
import pytest

from app.agents.mcp.greynoise import BASE_URL, GreynoiseMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> GreynoiseMcpClient:
    transport = httpx.MockTransport(handler)
    return GreynoiseMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_malicious_noise_maps_high_score() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v3/community/194.26.29.156"
        assert request.headers["key"] == "test-key"
        return httpx.Response(
            200,
            json={
                "ip": "194.26.29.156",
                "noise": True,
                "riot": False,
                "classification": "malicious",
                "name": "unknown",
                "last_seen": "2026-08-20",
                "message": "Observed by GreyNoise",
            },
        )

    observation = await build_client(handler).query(parse_ioc("194.26.29.156"))

    assert observation.source == "mcp-greynoise"
    assert observation.raw["mock"] is False
    assert observation.raw["noise"] is True
    assert observation.reputation["verdict"] == "malicious"
    assert observation.reputation["score"] == 85
    assert "greynoise:malicious-noise" in observation.reputation["tags"]
    assert len(observation.community_reports) == 1
    assert "Classified malicious" in observation.community_reports[0]["summary"]


async def test_riot_benign_service_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "ip": "8.8.8.8",
                "noise": False,
                "riot": True,
                "classification": "benign",
                "name": "Google Public DNS",
                "last_seen": "2026-08-21",
            },
        )

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.reputation["verdict"] == "clean"
    assert observation.reputation["score"] == 0
    assert "greynoise:riot" in observation.reputation["tags"]
    assert {"kind": "known_service", "target": "Google Public DNS"} in observation.relationships
    assert observation.community_reports[0]["title"] == "GreyNoise: Google Public DNS"


async def test_noisy_unknown_classification_is_suspicious() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"noise": True, "riot": False, "classification": "unknown", "name": ""},
        )

    observation = await build_client(handler).query(parse_ioc("1.2.3.4"))

    assert observation.reputation["verdict"] == "suspicious"
    assert observation.reputation["score"] == 45


async def test_unobserved_ip_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    observation = await build_client(handler).query(parse_ioc("192.0.2.1"))

    assert observation.reputation["verdict"] == "clean"
    assert "greynoise:not-observed" in observation.reputation["tags"]
    assert observation.raw["observed"] is False


async def test_ipv6_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("2001:db8::dead:beef"))

    assert observation.raw["error"] == "greynoise_unsupported_ioc"
    assert observation.reputation == {}


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="GREYNOISE_API_KEY"):
        GreynoiseMcpClient(api_key="")
