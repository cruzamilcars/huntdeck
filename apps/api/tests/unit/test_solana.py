import json

import httpx

from app.agents.mcp.solana import BASE_URL, SolanaMcpClient
from app.domain.ioc.parser import parse_ioc

ADDR = "So11111111111111111111111111111111111111112"


def build_client(handler) -> SolanaMcpClient:
    transport = httpx.MockTransport(handler)
    return SolanaMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_active_wallet_enriches_balance_and_signatures() -> None:
    requests_seen = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(json.loads(request.content))
        body = json.loads(request.content)
        if body["method"] == "getBalance":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "result": {"context": {"slot": 445547479}, "value": 1000000000},
                    "id": 1,
                },
            )
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "result": [{"signature": "5sig"}], "id": 1},
        )

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert len(requests_seen) == 2
    assert obs.reputation["verdict"] == "clean"
    assert "solana:sol:1.000000" in obs.reputation["tags"]
    assert "solana:has-transactions" in obs.reputation["tags"]


async def test_funded_but_inactive_wallet_is_flagged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "getBalance":
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "result": {"value": 500000000}, "id": 1},
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": [], "id": 1})

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.reputation["verdict"] == "low"
    assert obs.community_reports


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "solana_unsupported_ioc"


async def test_unreachable_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.raw["error"] == "solana_unreachable"
