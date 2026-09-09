import httpx

from app.agents.mcp.blockscout import BASE_URL, BlockscoutMcpClient
from app.domain.ioc.parser import parse_ioc

_PATH = httpx.URL(BASE_URL).path


def build_client(handler) -> BlockscoutMcpClient:
    transport = httpx.MockTransport(handler)
    return BlockscoutMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_scam_flagged_address_is_malicious() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{_PATH}/addresses/0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
        return httpx.Response(
            200,
            json={
                "coin_balance": "123456",
                "is_contract": True,
                "is_scam": True,
                "is_verified": False,
                "reputation": "ok",
                "ens_domain_name": "vitalik.eth",
                "creator_address_hash": "0x000000000000000000000000000000000000dEaD",
            },
        )

    obs = await build_client(handler).query(parse_ioc("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
    assert obs.reputation["verdict"] == "malicious"
    assert obs.reputation["score"] == 90
    assert "blockscout:flagged-scam" in obs.reputation["tags"]
    assert obs.community_reports
    assert {"kind": "has_ens", "target": "vitalik.eth"} in obs.relationships
    assert {"kind": "deployed_by", "target": "0x000000000000000000000000000000000000dEaD"} in (
        obs.relationships
    )


async def test_clean_contract_address_is_low_risk() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "is_contract": True,
                "is_scam": False,
                "is_verified": True,
                "reputation": "ok",
            },
        )

    obs = await build_client(handler).query(parse_ioc("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
    assert obs.reputation["verdict"] == "clean"
    assert "blockscout:is-contract" in obs.reputation["tags"]
    assert "blockscout:verified" in obs.reputation["tags"]


async def test_suspicious_reputation_is_suspicious() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"is_scam": False, "reputation": "suspicious"},
        )

    obs = await build_client(handler).query(parse_ioc("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
    assert obs.reputation["verdict"] == "suspicious"
    assert "blockscout:reputation:suspicious" in obs.reputation["tags"]


async def test_transaction_creates_sender_recipient_edges() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{_PATH}/transactions/0x" + "ab" * 32
        return httpx.Response(
            200,
            json={
                "hash": "0x" + "ab" * 32,
                "status": "ok",
                "from": {"hash": "0x" + "aa" * 20},
                "to": {"hash": "0x" + "bb" * 20},
                "value": "1000000000000000000",
                "block_number": 20500000,
            },
        )

    obs = await build_client(handler).query(parse_ioc("0x" + "ab" * 32))
    assert obs.reputation["tags"] == ["blockscout:transaction", "blockscout:status:ok"]
    assert {"kind": "sent_from", "target": "0x" + "aa" * 20} in obs.relationships
    assert {"kind": "received_by", "target": "0x" + "bb" * 20} in obs.relationships


async def test_ens_resolves_to_controlling_address() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{_PATH}/search"
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "type": "address",
                        "address_hash": "0x" + "aa" * 20,
                    },
                    {
                        "type": "ens_domain",
                        "ens_info": {"address_hash": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"},
                    },
                ]
            },
        )

    obs = await build_client(handler).query(parse_ioc("vitalik.eth"))
    assert "blockscout:ens-resolved" in obs.reputation["tags"]
    assert {"kind": "resolves_to", "target": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"} in (
        obs.relationships
    )


async def test_ens_not_found_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": []})

    obs = await build_client(handler).query(parse_ioc("nonexistent-name.eth"))
    assert "blockscout:ens-not-found" in obs.reputation["tags"]
    assert obs.reputation["verdict"] == "clean"


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "blockscout_unsupported_ioc"
