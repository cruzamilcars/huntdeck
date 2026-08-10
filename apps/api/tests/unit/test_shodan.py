import httpx
import pytest

from app.agents.mcp.shodan import BASE_URL, ShodanMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> ShodanMcpClient:
    transport = httpx.MockTransport(handler)
    return ShodanMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


def host_payload(*, with_vulns: bool = False) -> dict:
    payload = {
        "ip_str": "8.8.8.8",
        "asn": "AS15169",
        "hostnames": ["dns.google"],
        "org": "Google LLC",
        "country_name": "United States",
        "city": "Mountain View",
        "ports": [53, 443],
    }
    if with_vulns:
        payload["vulns"] = ["CVE-2020-1234"]
    return payload


async def test_host_maps_ports_geolocation_and_relationships() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/shodan/host/8.8.8.8"
        assert dict(request.url.params)["key"] == "test-key"
        return httpx.Response(200, json=host_payload())

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.source == "mcp-shodan"
    assert observation.raw["mock"] is False
    assert observation.raw["ports"] == [53, 443]
    assert observation.reputation["verdict"] == "clean"
    assert observation.reputation["score"] == 6
    assert observation.geolocation == {
        "country": "United States",
        "city": "Mountain View",
        "org": "Google LLC",
        "asn": "AS15169",
        "provider": "mcp-shodan",
    }
    assert {"kind": "has_hostname", "target": "dns.google"} in observation.relationships


async def test_vulnerabilities_raise_score_and_add_reports() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=host_payload(with_vulns=True))

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.reputation["verdict"] == "suspicious"
    assert observation.reputation["score"] == 31
    assert "shodan:vuln:CVE-2020-1234" in observation.reputation["tags"]
    assert observation.community_reports
    assert {"kind": "affected_by_vuln", "target": "CVE-2020-1234"} in observation.relationships


async def test_domain_resolves_via_dns_endpoint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/dns/resolve"
        assert dict(request.url.params)["hostnames"] == "example.com"
        return httpx.Response(200, json={"example.com": "93.184.216.34"})

    observation = await build_client(handler).query(parse_ioc("example.com"))

    assert observation.raw["resolved_ips"] == ["93.184.216.34"]
    assert observation.relationships == [{"kind": "resolves_to", "target": "93.184.216.34"}]
    assert observation.reputation["verdict"] == "unknown"


async def test_unresolved_domain_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"example.com": None})

    observation = await build_client(handler).query(parse_ioc("example.com"))

    assert observation.raw["error"] == "shodan_dns_no_result"
    assert observation.reputation == {}


async def test_http_error_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "access denied"})

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "shodan_forbidden"
    assert observation.reputation == {}


async def test_timeout_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "shodan_unreachable"
    assert observation.reputation == {}


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="SHODAN_API_KEY"):
        ShodanMcpClient(api_key="")
