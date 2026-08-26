import httpx
import pytest

from app.agents.mcp.misp import MispMcpClient
from app.domain.ioc.parser import parse_ioc

BASE = "https://misp.example.org"


def build_client(handler) -> MispMcpClient:
    transport = httpx.MockTransport(handler)
    return MispMcpClient(
        base_url=BASE,
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE),
    )


def attribute(
    event_id: str, level: int, category: str = "Network activity", info: str = "C2 infra"
) -> dict:
    return {
        "id": "42",
        "event_id": event_id,
        "type": "ip-dst",
        "category": category,
        "comment": "seen in campaign",
        "value": "194.26.29.156",
        "Event": {"id": event_id, "info": info, "threat_level_id": level, "date": "2026-08-20"},
    }


async def test_high_threat_event_scores_malicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/attributes/restSearch/json"
        assert request.headers["Authorization"] == "test-key"
        assert b'"value":"194.26.29.156"' in request.content
        return httpx.Response(200, json={"response": {"Attribute": [attribute("7", 1)]}})

    observation = await build_client(handler).query(parse_ioc("194.26.29.156"))

    assert observation.source == "mcp-misp"
    assert observation.raw["mock"] is False
    assert observation.raw["attribute_count"] == 1
    assert observation.reputation["verdict"] == "malicious"
    assert observation.reputation["score"] == 85
    assert "misp:network-activity" in observation.reputation["tags"]
    assert {"kind": "reported_in", "target": "MISP event #7: C2 infra"} in observation.relationships
    assert "seen in campaign" in observation.community_reports[0]["summary"]


async def test_low_threat_event_is_suspicious() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": {"Attribute": [attribute("9", 3)]}})

    observation = await build_client(handler).query(parse_ioc("example.com"))

    assert observation.reputation["verdict"] == "suspicious"
    assert observation.reputation["score"] == 40


async def test_best_threat_level_wins_across_attributes() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        attribute("11", 3, category="Payload delivery"),
                        attribute("12", 1, category="Network activity"),
                    ]
                }
            },
        )

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.reputation["score"] == 85
    assert len(observation.relationships) == 2


async def test_no_attributes_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": {"Attribute": []}})

    observation = await build_client(handler).query(parse_ioc("192.0.2.99"))

    assert observation.reputation["verdict"] == "clean"
    assert "misp:no-reports" in observation.reputation["tags"]
    assert observation.relationships == []


async def test_flat_response_format_supported() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        # Some MISP versions omit the "response" wrapper.
        return httpx.Response(200, json={"Attribute": [attribute("13", 4)]})

    observation = await build_client(handler).query(parse_ioc("analyst@example.com"))

    assert observation.reputation["score"] == 30


async def test_phone_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("+15555550101"))

    assert observation.raw["error"] == "misp_unsupported_ioc"


def test_missing_credentials_are_rejected() -> None:
    with pytest.raises(ValueError, match="MISP_URL"):
        MispMcpClient(base_url="", api_key="k")
