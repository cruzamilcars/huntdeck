import httpx

from app.agents.mcp.goplus import BASE_URL, GoplusMcpClient
from app.domain.ioc.parser import parse_ioc

ADDR = "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"


def build_client(handler) -> GoplusMcpClient:
    transport = httpx.MockTransport(handler)
    return GoplusMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


def _token_security(**overrides: object) -> dict:
    payload = {
        "is_honeypot": "0",
        "is_blacklisted": "0",
        "cannot_buy": "0",
        "cannot_sell_all": "0",
        "can_take_back_ownership": "0",
        "is_mintable": "0",
        "buy_tax": "0",
        "sell_tax": "0",
        "creator_in_top_holders": "0",
        "dex": [{"name": "Uniswap V2", "liquidity": "120000"}],
    }
    payload.update(overrides)
    return {"code": 1, "result": {ADDR: payload}}


def _address_security(**overrides: object) -> dict:
    payload = {"is_contract": "1", "tags": []}
    payload.update(overrides)
    return {"code": 1, "result": {ADDR: payload}}


async def test_honeypot_token_is_malicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "token_security" in str(request.url):
            return httpx.Response(200, json=_token_security(is_honeypot="1"))
        return httpx.Response(200, json=_address_security())

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.reputation["verdict"] == "malicious"
    assert obs.reputation["score"] == 92
    assert "goplus:honeypot" in obs.reputation["tags"]
    assert obs.community_reports


async def test_thin_liquidity_is_suspicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "token_security" in str(request.url):
            return httpx.Response(
                200, json=_token_security(dex=[{"name": "Pancake", "liquidity": "800"}])
            )
        return httpx.Response(200, json=_address_security())

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.reputation["verdict"] == "suspicious"
    assert "goplus:thin-liquidity" in obs.reputation["tags"]


async def test_clean_token_is_clean() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "token_security" in str(request.url):
            return httpx.Response(200, json=_token_security())
        return httpx.Response(200, json=_address_security())

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert obs.reputation["verdict"] == "clean"
    assert "goplus:no-risk-flags" in obs.reputation["tags"]


async def test_address_risk_lines_add_signal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "token_security" in str(request.url):
            return httpx.Response(200, json=_token_security())
        return httpx.Response(
            200, json=_address_security(risk_lines=[{"risk": "blacklist", "detail": []}])
        )

    obs = await build_client(handler).query(parse_ioc(ADDR))
    assert "goplus:address-risk" in obs.reputation["tags"]


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "goplus_unsupported_ioc"
