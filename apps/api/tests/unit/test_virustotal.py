import httpx
import pytest

from app.agents.mcp.virustotal import BASE_URL, VirusTotalMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> VirusTotalMcpClient:
    transport = httpx.MockTransport(handler)
    return VirusTotalMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


def attributes_with(stats: dict, *, country: str | None = None) -> httpx.Response:
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": stats,
                "last_analysis_results": {"Kaspersky": {"category": "malicious"}},
                **({"country": country} if country else {}),
            }
        }
    }
    return httpx.Response(200, json=payload)


async def test_hash_with_detections_maps_to_reputation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return attributes_with({"malicious": 3, "suspicious": 2, "harmless": 40, "undetected": 10})

    observation = await build_client(handler).query(parse_ioc("44d88612fea8a8f36de82e1278abb02f"))

    assert observation.source == "mcp-virustotal"
    assert observation.raw["mock"] is False
    assert observation.raw["entity"] == "44d88612fea8a8f36de82e1278abb02f"
    assert observation.reputation["verdict"] == "malicious"
    assert observation.reputation["score"] >= 40
    assert any(tag.startswith("vt:") for tag in observation.reputation["tags"])
    assert observation.community_reports


async def test_clean_ip_maps_verdict_and_geolocation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/ip_addresses/8.8.8.8"
        assert request.headers["x-apikey"] == "test-key"
        return attributes_with(
            {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5},
            country="US",
        )

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.reputation["verdict"] == "clean"
    assert observation.geolocation == {"country": "US", "provider": "mcp-virustotal"}


async def test_domain_resolutions_become_relationships() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {},
                    "resolutions": [{"ip_address": "203.0.113.10"}],
                }
            }
        }
        return httpx.Response(200, json=payload)

    observation = await build_client(handler).query(parse_ioc("example.com"))

    assert observation.relationships == [{"kind": "resolves_to", "target": "203.0.113.10"}]
    assert observation.reputation["verdict"] == "unknown"


async def test_url_uses_sha256_url_id() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return attributes_with({"malicious": 0})

    observation = await build_client(handler).query(parse_ioc("http://evil.example.com/"))

    import hashlib

    expected_id = hashlib.sha256(b"http://evil.example.com/").hexdigest()
    assert seen["path"] == f"/api/v3/urls/{expected_id}"
    assert observation.reputation["verdict"] == "unknown"


async def test_http_error_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "forbidden"}})

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "virus_total_forbidden"
    assert observation.reputation == {}


async def test_timeout_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "virus_total_unreachable"
    assert observation.reputation == {}


async def test_routes_by_ioc_type() -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return attributes_with({"malicious": 0})

    client = build_client(handler)
    await client.query(parse_ioc("44d88612fea8a8f36de82e1278abb02f"))  # md5
    await client.query(parse_ioc("8.8.8.8"))  # ipv4
    await client.query(parse_ioc("172.16.0.1"))  # ipv6

    assert seen == [
        "/api/v3/files/44d88612fea8a8f36de82e1278abb02f",
        "/api/v3/ip_addresses/8.8.8.8",
        "/api/v3/ip_addresses/172.16.0.1",
    ]


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY"):
        VirusTotalMcpClient(api_key="")
