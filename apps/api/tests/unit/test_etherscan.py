import httpx
import pytest

from app.agents.mcp.etherscan import BASE_URL, EtherscanMcpClient
from app.domain.ioc.parser import parse_ioc

ADDR = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


def build_client(handler) -> EtherscanMcpClient:
    transport = httpx.MockTransport(handler)
    return EtherscanMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_address_enriches_balance_and_latest_tx() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        action = request.url.params["action"]
        if action == "balance":
            return httpx.Response(200, json={"status": "1", "result": "0xde0b6b3a7640000"})
        return httpx.Response(
            200,
            json={
                "status": "1",
                "result": [{"hash": "0x" + "ab" * 32, "from": ADDR, "to": "0x" + "bb" * 20}],
            },
        )

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.reputation["verdict"] == "clean"
    assert "etherscan:has-transactions" in obs.reputation["tags"]
    assert obs.raw["latest_tx_hash"] == "0x" + "ab" * 32


async def test_transaction_enriches_sender_recipient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["action"] == "eth_getTransactionByHash"
        return httpx.Response(
            200,
            json={
                "status": "1",
                "result": {
                    "hash": "0x" + "ab" * 32,
                    "from": "0x" + "aa" * 20,
                    "to": "0x" + "bb" * 20,
                    "value": "0x1",
                    "blockNumber": "0x1389",
                },
            },
        )

    obs = await build_client(handler).query(parse_ioc("0x" + "ab" * 32))
    assert "etherscan:confirmed" in obs.reputation["tags"]
    assert {"kind": "sent_from", "target": "0x" + "aa" * 20} in obs.relationships
    assert {"kind": "received_by", "target": "0x" + "bb" * 20} in obs.relationships


async def test_unknown_transaction_is_clean_not_found() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "0", "result": None})

    obs = await build_client(handler).query(parse_ioc("0x" + "cd" * 32))
    assert "etherscan:tx-not-found" in obs.reputation["tags"]
    assert obs.raw["found"] is False


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "etherscan_unsupported_ioc"


def test_missing_key_rejected() -> None:
    with pytest.raises(ValueError, match="ETHERSCAN_API_KEY"):
        EtherscanMcpClient(api_key="")
