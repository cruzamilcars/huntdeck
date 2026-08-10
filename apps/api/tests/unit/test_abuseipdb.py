import httpx
import pytest

from app.agents.mcp.abuseipdb import BASE_URL, AbuseIpdbMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> AbuseIpdbMcpClient:
    transport = httpx.MockTransport(handler)
    return AbuseIpdbMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


def check_payload(*, score: int, country: str = "US", is_tor: bool = False) -> dict:
    return {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": score,
            "countryName": country,
            "isp": "Google LLC",
            "domain": "google.com",
            "usageType": "Data Center/Web Hosting/Transit",
            "isTor": is_tor,
            "totalReports": 5,
            "numDistinctUsers": 3,
            "isWhitelisted": False,
            "reports": [
                {
                    "categories": [1],
                    "comment": "Malware host detected by community.",
                    "reporterId": 99,
                }
            ],
        }
    }


async def test_ipv4_check_maps_reputation_and_geolocation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2/check"
        assert dict(request.url.params)["ipAddress"] == "8.8.8.8"
        assert request.headers["Key"] == "test-key"
        return httpx.Response(200, json=check_payload(score=92))

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.source == "mcp-abuseipdb"
    assert observation.raw["mock"] is False
    assert observation.raw["total_reports"] == 5
    assert observation.reputation["score"] == 92
    assert observation.reputation["verdict"] == "malicious"
    assert observation.geolocation == {
        "country": "US",
        "isp": "Google LLC",
        "domain": "google.com",
        "provider": "mcp-abuseipdb",
    }
    assert observation.community_reports
    assert {"kind": "registered_under", "target": "google.com"} in observation.relationships


async def test_low_confidence_maps_to_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=check_payload(score=0))

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.reputation["verdict"] == "clean"
    assert observation.reputation["score"] == 0


async def test_tor_flag_adds_tags_and_relationship() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=check_payload(score=55, is_tor=True))

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert "tor-exit" in observation.reputation["tags"]
    assert {"kind": "traffics_over_tor", "target": "TOR network"} in observation.relationships


async def test_non_ipv4_ioc_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("malware-sample.exe"))

    assert observation.raw["error"] == "abuseipdb_unsupported_ioc"
    assert observation.reputation == {}


async def test_http_error_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"errors": [{"detail": "rate limit"}]})

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "abuseipdb_rate_limited"
    assert observation.reputation == {}


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="ABUSEIPDB_API_KEY"):
        AbuseIpdbMcpClient(api_key="")
