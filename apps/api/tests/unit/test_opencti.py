import json

import httpx
import pytest

from app.agents.mcp.opencti import OpenCtiMcpClient
from app.domain.ioc.parser import parse_ioc

BASE = "https://opencti.example.org"


def build_client(handler) -> OpenCtiMcpClient:
    transport = httpx.MockTransport(handler)
    return OpenCtiMcpClient(
        base_url=BASE,
        api_key="test-key",
        client=httpx.AsyncClient(transport=transport, base_url=BASE),
    )


def observable(
    value: str,
    entity_type: str = "Domain-Name",
    score: int | None = None,
    description: str = "Known phishing domain",
    labels: list[str] | None = None,
) -> dict:
    return {
        "id": "obs-1",
        "entity_type": entity_type,
        "observable_value": value,
        "x_opencti_description": description,
        "x_opencti_score": score,
        "created_at": "2026-08-20T00:00:00Z",
        "objectLabel": [{"id": "l1", "value": label} for label in labels or []],
        "indicators": {
            "edges": [
                {
                    "node": {
                        "id": "ind-1",
                        "name": "phishing-domain",
                        "pattern": "[domain-name:value = 'w-diarium.pw']",
                    }
                }
            ]
        },
    }


async def test_graphql_query_shape_and_auth() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/graphql"
        assert request.headers["Authorization"] == "Bearer test-key"
        body = json.loads(request.content)
        assert body["query"].strip().startswith("query HuntDeck")
        variables = body["variables"]
        assert variables["types"] == ["Domain-Name"]
        assert variables["filters"]["filters"] == [
            {"key": "value", "values": ["w-diarium.pw"], "operator": "eq"}
        ]
        return httpx.Response(
            200,
            json={
                "data": {
                    "stixCyberObservables": {
                        "edges": [{"node": observable("w-diarium.pw")}],
                        "pageInfo": {"globalCount": 1},
                    }
                }
            },
        )

    observation = await build_client(handler).query(parse_ioc("w-diarium.pw"))

    assert observation.source == "mcp-opencti"
    assert observation.raw["mock"] is False
    assert observation.raw["observable_count"] == 1
    assert observation.raw["observables"][0]["value"] == "w-diarium.pw"
    assert observation.raw["observables"][0]["indicators"] == ["phishing-domain"]
    assert observation.reputation["verdict"] == "suspicious"
    assert observation.reputation["score"] == 50
    assert "opencti:sighted" in observation.reputation["tags"]
    assert {"kind": "reported_in", "target": "OpenCTI Domain-Name: w-diarium.pw"} in (
        observation.relationships or []
    )
    assert "Known phishing domain" in observation.community_reports[0]["summary"]


async def test_platform_score_drives_verdict() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "stixCyberObservables": {
                        "edges": [{"node": observable("194.26.29.156", "IPv4-Addr", score=85)}],
                    }
                }
            },
        )

    observation = await build_client(handler).query(parse_ioc("194.26.29.156"))

    assert observation.reputation["verdict"] == "malicious"
    assert observation.reputation["score"] == 85


async def test_no_observables_is_clean() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"stixCyberObservables": {"edges": [], "pageInfo": {"globalCount": 0}}}},
        )

    observation = await build_client(handler).query(parse_ioc("192.0.2.99"))

    assert observation.reputation["verdict"] == "clean"
    assert "opencti:no-reports" in observation.reputation["tags"]
    assert observation.relationships == []


async def test_graphql_errors_degrade_to_structured_observation() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        # GraphQL endpoints return 200 with an errors array on failure.
        return httpx.Response(200, json={"errors": [{"message": "Forbidden access to entity"}]})

    observation = await build_client(handler).query(parse_ioc("w-diarium.pw"))

    assert observation.raw["error"] == "opencti_graphql_error"
    assert observation.raw["mock"] is False


async def test_unauthorized_maps_to_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"errors": [{"message": "Unauthorized"}]})

    observation = await build_client(handler).query(parse_ioc("w-diarium.pw"))

    assert observation.raw["error"] == "opencti_unauthorized"


async def test_unreachable_instance_maps_to_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    observation = await build_client(handler).query(parse_ioc("w-diarium.pw"))

    assert observation.raw["error"] == "opencti_unreachable"


async def test_hash_maps_to_stixfile_type() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["variables"]["types"] == ["StixFile"]
        return httpx.Response(
            200,
            json={
                "data": {
                    "stixCyberObservables": {
                        "edges": [
                            {
                                "node": observable(
                                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                                    "StixFile",
                                )
                            }
                        ]
                    }
                }
            },
        )

    observation = await build_client(handler).query(
        parse_ioc("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    )

    assert observation.reputation["verdict"] == "suspicious"


async def test_phone_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("+15555550101"))

    assert observation.raw["error"] == "opencti_unsupported_ioc"


def test_missing_credentials_are_rejected() -> None:
    with pytest.raises(ValueError, match="OPENCTI_URL"):
        OpenCtiMcpClient(base_url="", api_key="k")
