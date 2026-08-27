import httpx
import pytest

from app.agents.mcp.urlhaus import BASE_URL, UrlHausMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> UrlHausMcpClient:
    transport = httpx.MockTransport(handler)
    return UrlHausMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_url_listed_is_malicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/url/"
        assert request.headers["Auth-Key"] == "test-key"
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "threat": "malware_download",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
                "tags": ["32-bit", "exe"],
            },
        )

    obs = await build_client(handler).query(parse_ioc("http://evil.example.com/malware.exe"))
    assert obs.reputation["verdict"] == "malicious"
    assert obs.reputation["score"] == 85
    assert "urlhaus:malware_download" in obs.reputation["tags"]
    assert obs.community_reports[0]["confidence"] == "high"


async def test_domain_with_urls_creates_relationships() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "host": "evil.example.com",
                "threat": "malware_download",
                "urls": [
                    {"url": "http://evil.example.com/a.exe", "threat": "malware_download"},
                    {"url": "http://evil.example.com/b.exe", "threat": "malware_download"},
                ],
            },
        )

    obs = await build_client(handler).query(parse_ioc("evil.example.com"))
    assert obs.reputation["verdict"] == "malicious"
    assert len(obs.relationships) == 2
    assert obs.relationships[0]["kind"] == "hosts_malware"


async def test_hash_not_listed_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_results"})

    obs = await build_client(handler).query(parse_ioc("d41d8cd98f00b204e9800998ecf8427e"))
    assert obs.reputation["verdict"] == "clean"
    assert "urlhaus:not-listed" in obs.reputation["tags"]


async def test_invalid_url_is_unknown() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "invalid_url"})

    obs = await build_client(handler).query(parse_ioc("http://bad url"))
    assert obs.reputation["verdict"] == "unknown"


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "urlhaus_unsupported_ioc"


def test_missing_key_rejected() -> None:
    with pytest.raises(ValueError, match="URLHAUS_API_KEY"):
        UrlHausMcpClient(api_key="")
