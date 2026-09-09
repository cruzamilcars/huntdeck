import httpx

from app.agents.mcp.mempool import BASE_URL, MempoolspaceMcpClient
from app.domain.ioc.parser import parse_ioc

_PATH = httpx.URL(BASE_URL).path


def build_client(handler) -> MempoolspaceMcpClient:
    transport = httpx.MockTransport(handler)
    return MempoolspaceMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_active_address_is_clean_enrichment() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{_PATH}/address/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        return httpx.Response(
            200,
            json={
                "address": "bc1q...",
                "chain_stats": {
                    "funded_txo_count": 100,
                    "funded_txo_sum": 5000000000,
                    "spent_txo_count": 90,
                    "spent_txo_sum": 4000000000,
                    "tx_count": 150,
                },
                "mempool_stats": {"funded_txo_sum": 0, "tx_count": 0},
            },
        )

    obs = await build_client(handler).query(parse_ioc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
    assert obs.reputation["verdict"] == "clean"
    assert obs.raw["tx_count"] == 150
    assert "mempoolspace:received_btc:50.000000" in obs.reputation["tags"]


async def test_accumulation_wallet_is_flagged() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "chain_stats": {
                    "funded_txo_sum": 20_000_000_000,
                    "spent_txo_sum": 0,
                    "tx_count": 5,
                },
                "mempool_stats": {},
            },
        )

    obs = await build_client(handler).query(parse_ioc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
    assert obs.reputation["verdict"] == "low"
    assert obs.community_reports[0]["title"].lower().startswith("bitcoin accumulation")


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "mempoolspace_unsupported_ioc"


async def test_unreachable_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    obs = await build_client(handler).query(parse_ioc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
    assert obs.raw["error"] == "mempoolspace_unreachable"
