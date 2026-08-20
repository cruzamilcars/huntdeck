import httpx
import pytest

from app.agents.mcp.hibp import BASE_URL, HibpMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> HibpMcpClient:
    transport = httpx.MockTransport(handler)
    return HibpMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


def breaches_payload() -> list[dict]:
    return [
        {
            "Name": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "PwnCount": 152445165,
            "IsVerified": True,
            "IsSensitive": True,
            "IsSpamList": False,
            "DataClasses": ["Emails", "Passwords", "Password hints"],
        },
        {
            "Name": "LinkedIn",
            "Domain": "linkedin.com",
            "BreachDate": "2012-05-05",
            "PwnCount": 164611595,
            "IsVerified": True,
            "IsSensitive": False,
            "IsSpamList": False,
            "DataClasses": ["Email addresses", "Passwords"],
        },
    ]


async def test_email_with_breaches_maps_reputation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/breachedaccount/test@example.com"
        assert request.headers["hibp-api-key"] == "test-key"
        assert request.headers["User-Agent"] == "huntdeck-osint-hub"
        return httpx.Response(200, json=breaches_payload())

    observation = await build_client(handler).query(parse_ioc("test@example.com"))

    assert observation.source == "mcp-hibp"
    assert observation.raw["mock"] is False
    assert observation.raw["breach_count"] == 2
    assert observation.raw["breaches"][0]["name"] == "Adobe"
    assert observation.reputation["verdict"] == "malicious"
    assert observation.reputation["score"] == 70
    assert "hibp:Adobe" in observation.reputation["tags"]
    assert len(observation.community_reports) == 2
    assert "152,445,165 accounts" in observation.community_reports[0]["summary"]


async def test_email_without_breaches_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    observation = await build_client(handler).query(parse_ioc("clean@example.com"))

    assert observation.reputation["verdict"] == "clean"
    assert observation.reputation["score"] == 0
    assert "hibp:no-breaches" in observation.reputation["tags"]


async def test_unsupported_ioc_type_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "hibp_unsupported_ioc"
    assert observation.reputation == {}


async def test_rate_limit_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "rate limited"})

    observation = await build_client(handler).query(parse_ioc("test@example.com"))

    assert observation.raw["error"] == "hibp_rate_limited"
    assert observation.reputation == {}


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="HIBP_API_KEY"):
        HibpMcpClient(api_key="")
