import httpx

from app.agents.mcp.crtsh import BASE_URL, CrtshMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> CrtshMcpClient:
    transport = httpx.MockTransport(handler)
    return CrtshMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_domain_with_certificates_builds_relationships() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "%25.example.com"
        assert request.url.params["output"] == "json"
        return httpx.Response(
            200,
            json=[
                {
                    "common_name": "example.com",
                    "name_value": "example.com\nwww.example.com\napi.example.com",
                    "issuer_name": "C=US, O=Let's Encrypt",
                },
                {
                    "common_name": "admin.example.com",
                    "name_value": "admin.example.com",
                    "issuer_name": "C=US, O=DigiCert",
                },
            ],
        )

    obs = await build_client(handler).query(parse_ioc("example.com"))
    assert obs.reputation["verdict"] == "clean"
    assert len(obs.relationships) == 4, obs.relationships
    assert obs.reputation["tags"] == [
        "crtsh:certificates:2",
        "crtsh:subdomains:4",
        "crtsh:issuers:2",
    ]


async def test_no_certificates_is_empty_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    obs = await build_client(handler).query(parse_ioc("nowhere.example.com"))
    assert obs.reputation["verdict"] == "clean"
    assert "crtsh:certificates:0" in obs.reputation["tags"]


async def test_rate_limited_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited")

    obs = await build_client(handler).query(parse_ioc("example.com"))
    assert obs.raw["error"] == "crtsh_rate_limited"


async def test_html_error_page_degrades_to_unreachable() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>blocked by proxy</html>")

    obs = await build_client(handler).query(parse_ioc("example.com"))
    assert obs.raw["error"] == "crtsh_unreachable"


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "crtsh_unsupported_ioc"
