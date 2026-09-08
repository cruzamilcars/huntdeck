"""Hermetic tests for the /mcp Streamable HTTP endpoint and investigate tool.

An orchestrator built purely from MockMcpClient is injected so these tests
never touch the network or real provider keys.
"""

import json
from contextlib import contextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.agents.mcp.mock_server import MockMcpClient
from app.mcp.server import create_mcp_server, mount_mcp
from app.services.orchestrator import InvestigationOrchestrator

_JSON = {"Accept": "application/json"}


def _mock_orchestrator() -> InvestigationOrchestrator:
    clients = {
        provider_name: MockMcpClient(provider_name)
        for provider_name in (
            "mcp-virustotal",
            "mcp-shodan",
            "mcp-abuseipdb",
            "mcp-hibp",
            "mcp-opencnam",
            "mcp-otx",
            "mcp-greynoise",
            "mcp-misp",
            "mcp-urlhaus",
            "mcp-rdap",
            "mcp-urlscan",
            "mcp-social",
        )
    }
    return InvestigationOrchestrator(clients=clients)


@contextmanager
def _client():
    mcp_app = create_mcp_server(orchestrator=_mock_orchestrator()).http_app(
        path="/", transport="streamable-http", json_response=True
    )
    # Same instance provides lifespan + mount handler. TestClient only runs
    # the lifespan when used as a context manager (starlette >= 0.29).
    app = FastAPI(lifespan=mcp_app.lifespan)
    mount_mcp(app, http_app=mcp_app)
    with TestClient(app) as client:
        yield client


def _init_session(client: TestClient) -> str:
    initialize = client.post(
        "/mcp",
        headers=_JSON,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        },
    )
    assert initialize.status_code == 200, initialize.text
    session_id = initialize.headers.get("mcp-session-id")
    client.post(
        "/mcp",
        headers={**({"mcp-session-id": session_id} if session_id else {}), **_JSON},
        json={"jsonrpc": "2.0", "id": 2, "method": "notifications/initialized", "params": {}},
    )
    return session_id


def _post(client: TestClient, session_id: str, method: str, params: dict, msg_id: int):
    headers = {**({"mcp-session-id": session_id} if session_id else {}), **_JSON}
    return client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params},
    )


def test_mcp_initialize_advertises_huntdeck() -> None:
    with _client() as client:
        response = client.post(
            "/mcp",
            headers=_JSON,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["serverInfo"]["name"] == "huntdeck"
        assert "protocolVersion" in result


def test_mcp_tools_include_investigate() -> None:
    with _client() as client:
        session_id = _init_session(client)
        response = _post(client, session_id, "tools/list", {}, 3)
        assert response.status_code == 200, response.text
        tools = {tool["name"]: tool["inputSchema"] for tool in response.json()["result"]["tools"]}
        assert "investigate" in tools
        assert "ioc" in tools["investigate"]["properties"]


def test_mcp_investigate_tool_returns_tactical_report() -> None:
    with _client() as client:
        session_id = _init_session(client)
        response = _post(
            client,
            session_id,
            "tools/call",
            {"name": "investigate", "arguments": {"ioc": "8.8.8.8"}},
            4,
        )
        assert response.status_code == 200, response.text
        content = response.json()["result"]["content"]
        report = json.loads(content[0]["text"])
        assert report["ioc"]["normalized"] == "8.8.8.8"
        assert report["ioc"]["type"] == "ipv4"
        assert "risk" in report and report["risk"]["severity"] in {
            "low",
            "medium",
            "high",
            "unknown",
            "critical",
        }
        assert report["modules"]["reputation"]
        assert report["mappings"]["mitre_attack"]


def test_mcp_investigate_rejects_unknown_ioc() -> None:
    with _client() as client:
        session_id = _init_session(client)
        response = _post(
            client,
            session_id,
            "tools/call",
            {"name": "investigate", "arguments": {"ioc": "not an ioc"}},
            5,
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result.get("isError") is True
        assert "not a recognizable IOC" in result["content"][0]["text"]
