import httpx

from app.agents.mcp.dexscreener import BASE_URL, DexscreenerMcpClient
from app.domain.ioc.parser import parse_ioc

ADDR = "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"
_PATH = httpx.URL(BASE_URL).path


def build_client(handler) -> DexscreenerMcpClient:
    transport = httpx.MockTransport(handler)
    return DexscreenerMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


def _pairs(**overrides: object) -> list[dict]:
    pair = {
        "chainId": "ethereum",
        "dexId": "uniswap-v2",
        "baseToken": {"symbol": "SHIB", "name": "Shiba Inu"},
        "quoteToken": {"symbol": "WETH"},
        "priceUsd": "0.0001",
        "priceChange": {"h24": 5.0, "m5": 1.0},
        "liquidity": {"usd": 3000000},
        "fdv": 5000000,
        "txns": {"h24": {"buys": 300, "sells": 250}},
    }
    pair.update(overrides)
    return [pair]


async def test_liquid_token_is_clean() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{_PATH}/tokens/{ADDR.lower()}"
        return httpx.Response(200, json={"pairs": _pairs()})

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.reputation["verdict"] == "clean"
    assert "dexscreener:ethereum" in obs.reputation["tags"]
    assert obs.raw["liquidity_usd"] == 3000000


async def test_thin_liquidity_is_suspicious() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"pairs": _pairs(liquidity={"usd": 200})})

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.reputation["verdict"] == "suspicious"
    assert "dexscreener:thin-liquidity" in obs.reputation["tags"]


async def test_extreme_price_move_is_signaled() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"pairs": _pairs(priceChange={"h24": 120.0}, liquidity={"usd": 50000})},
        )

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert "dexscreener:extreme-24h-move" in obs.reputation["tags"]
    assert obs.reputation["score"] >= 35


async def test_not_listed_is_clean_tag() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"pairs": []})

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert "dexscreener:not-listed" in obs.reputation["tags"]
    assert obs.reputation["verdict"] == "clean"


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "dexscreener_unsupported_ioc"
