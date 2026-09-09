import httpx
import pytest

from app.agents.mcp.hunterio import BASE_URL, HunterioMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> HunterioMcpClient:
    transport = httpx.MockTransport(handler)
    return HunterioMcpClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE_URL),
    )


async def test_deliverable_email_is_clean() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["email"] == "analyst@example.com"
        assert request.url.params["api_key"] == "test-key"
        return httpx.Response(
            200,
            json={
                "data": {
                    "result": "deliverable",
                    "score": 100,
                    "smtp_check": True,
                    "disposable": False,
                }
            },
        )

    obs = await build_client(handler).query(parse_ioc("analyst@example.com"))
    assert obs.reputation["verdict"] == "clean"
    assert "hunterio:deliverable" in obs.reputation["tags"]


async def test_risky_email_is_suspicious() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "result": "risky",
                    "smtp_check": False,
                    "disposable": False,
                }
            },
        )

    obs = await build_client(handler).query(parse_ioc("risky@example.com"))
    assert obs.reputation["verdict"] == "suspicious"
    assert "hunterio:risky" in obs.reputation["tags"]


async def test_disposable_address_adds_score() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "result": "deliverable",
                    "smtp_check": True,
                    "disposable": True,
                }
            },
        )

    obs = await build_client(handler).query(parse_ioc("temp@example.com"))
    assert "hunterio:disposable" in obs.reputation["tags"]
    assert obs.reputation["score"] >= 30


async def test_unsupported_type_is_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    obs = await build_client(handler).query(parse_ioc("8.8.8.8"))
    assert obs.raw["error"] == "hunterio_unsupported_ioc"


async def test_unreachable_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    obs = await build_client(handler).query(parse_ioc("analyst@example.com"))
    assert obs.raw["error"] == "hunterio_unreachable"


def test_missing_key_rejected() -> None:
    with pytest.raises(ValueError, match="HUNTERIO_API_KEY"):
        HunterioMcpClient(api_key="")
