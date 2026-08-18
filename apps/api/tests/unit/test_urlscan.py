import httpx

from app.agents.mcp.urlscan import BASE_URL, UrlScanMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> UrlScanMcpClient:
    transport = httpx.MockTransport(handler)
    return UrlScanMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


def search_payload(*, malicious_engines: int = 0, stats_malicious: int = 0) -> dict:
    return {
        "results": [
            {
                "_id": "scan-123",
                "page": {
                    "url": "http://evil.example.com/",
                    "ip": "192.0.2.55",
                    "country": "US",
                    "asn": "AS64512",
                    "domain": "evil.example.com",
                },
                "stats": {
                    "malicious": stats_malicious,
                    "verdicts": {
                        "overall": {"malicious": malicious_engines, "suspicious": 0, "clean": 1}
                    },
                },
                "tags": ["phishing"],
            }
        ]
    }


async def test_url_with_malicious_engines_maps_reputation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/search/"
        assert dict(request.url.params)["q"] == "page.url:http://evil.example.com/"
        assert request.headers["API-Key"] == "test-key"
        return httpx.Response(200, json=search_payload(malicious_engines=2, stats_malicious=3))

    observation = await build_client(handler).query(parse_ioc("http://evil.example.com/"))

    assert observation.source == "mcp-urlscan"
    assert observation.raw["mock"] is False
    assert observation.reputation["verdict"] == "malicious"
    assert observation.reputation["score"] == 80
    assert "urlscan:phishing" in observation.reputation["tags"]
    assert observation.geolocation == {
        "country": "US",
        "ip": "192.0.2.55",
        "asn": "AS64512",
        "domain": "evil.example.com",
        "provider": "mcp-urlscan",
    }
    assert {"kind": "hosted_at", "target": "192.0.2.55"} in observation.relationships
    assert observation.community_reports


async def test_domain_query_and_clean_verdict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert dict(request.url.params)["q"] == "domain:example.com"
        return httpx.Response(200, json=search_payload())

    observation = await build_client(handler).query(parse_ioc("example.com"))

    assert observation.reputation["verdict"] == "clean"
    assert observation.reputation["score"] == 0


async def test_no_scan_found_is_unknown_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [], "total": 0})

    observation = await build_client(handler).query(parse_ioc("http://unknown.example/"))

    assert observation.reputation["verdict"] == "unknown"
    assert observation.raw["scans_found"] == 0
    assert "urlscan:no-scan-found" in observation.reputation["tags"]


async def test_unsupported_ioc_type_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("44d88612fea8a8f36de82e1278abb02f"))

    assert observation.raw["error"] == "urlscan_unsupported_ioc"
    assert observation.reputation == {}


async def test_http_error_becomes_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "rate limited"})

    observation = await build_client(handler).query(parse_ioc("http://evil.example/"))

    assert observation.raw["error"] == "urlscan_rate_limited"
    assert observation.reputation == {}


async def test_anonymous_client_sends_no_api_key_header() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "API-Key" not in request.headers
        return httpx.Response(200, json=search_payload())

    transport = httpx.MockTransport(handler)
    client = UrlScanMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )

    observation = await client.query(parse_ioc("example.com"))

    assert observation.source == "mcp-urlscan"
    assert observation.raw["mock"] is False
    assert observation.reputation["verdict"] == "clean"
