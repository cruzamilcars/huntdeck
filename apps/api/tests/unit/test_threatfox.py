import json

import httpx
import pytest

from app.agents.mcp.threatfox import BASE_URL, ThreatfoxMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> ThreatfoxMcpClient:
    transport = httpx.MockTransport(handler)
    return ThreatfoxMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_domain_flagged_by_threatfox_is_malicious() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Auth-Key"] == "test-key"
        body = json.loads(request.content)
        assert body["query"] == "search_ioc"
        assert body["search_term"] == "w-diarium.pw"
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "malware_printable": "RedLine Stealer",
                        "confidence_level": 90,
                        "first_seen": "2026-01-01T00:00:00Z",
                        "ioc": "w-diarium.pw",
                    }
                ],
            },
        )

    obs = await build_client(handler).query(parse_ioc("w-diarium.pw"))
    assert obs.reputation["verdict"] == "malicious"
    assert obs.reputation["score"] == 90
    assert "threatfox:malware:RedLine Stealer" in obs.reputation["tags"]
    assert obs.community_reports[0]["confidence"] == "high"


async def test_no_result_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_result"})

    obs = await build_client(handler).query(parse_ioc("clean.example.com"))
    assert obs.reputation["verdict"] == "clean"
    assert "threatfox:no_result" in obs.reputation["tags"]


async def test_hash_route_uses_search_term_hash() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["search_term"] == "d41d8cd98f00b204e9800998ecf8427e"
        return httpx.Response(200, json={"query_status": "no_result"})

    obs = await build_client(handler).query(parse_ioc("d41d8cd98f00b204e9800998ecf8427e"))
    assert obs.reputation["verdict"] == "clean"


async def test_unauthorized_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Unauthorized"})

    obs = await build_client(handler).query(parse_ioc("w-diarium.pw"))
    assert obs.raw["error"] == "threatfox_unauthorized"


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "threatfox_unsupported_ioc"


def test_missing_key_rejected() -> None:
    with pytest.raises(ValueError, match="THREATFOX_API_KEY"):
        ThreatfoxMcpClient(api_key="")
