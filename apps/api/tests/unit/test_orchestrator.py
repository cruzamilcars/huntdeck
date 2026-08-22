from app.domain.ioc.types import IocType
from app.services.orchestrator import InvestigationOrchestrator


async def test_orchestrator_returns_tactical_contract_for_ipv4() -> None:
    response = await InvestigationOrchestrator().investigate(
        "8.8.8.8",
        used_byok=True,
        quota={"reason": "byok"},
    )

    assert response.ioc.type == IocType.IPV4
    assert response.risk.score > 0
    assert response.modules.reputation
    assert response.modules.geolocation
    assert response.modules.relationship_graph["nodes"]
    assert response.modules.community_reports
    assert response.mappings.mitre_attack
    assert response.mappings.nist
    assert response.mappings.iso
    assert response.playbooks
    assert response.playbooks[0]["steps"]
    assert response.playbooks[0]["reference"].startswith("https://github.com/mukul975/")
    assert response.used_byok is True
    assert response.quota["reason"] == "byok"
    assert response.mcp_servers_queried == [
        "mcp-virustotal",
        "mcp-shodan",
        "mcp-abuseipdb",
        "mcp-rdap",
        "mcp-otx",
    ]


async def test_orchestrator_rejects_unknown_without_provider_calls() -> None:
    response = await InvestigationOrchestrator().investigate("not an ioc")

    assert response.ioc.type == IocType.UNKNOWN
    assert response.risk.severity == "unknown"
    assert response.sources == []


async def test_email_uses_hibp_provider() -> None:
    response = await InvestigationOrchestrator().investigate("analyst@example.com")

    assert response.ioc.type == IocType.EMAIL
    assert response.mcp_servers_queried == ["mcp-hibp"]
    assert response.sources == ["mcp-hibp"]


async def test_phone_uses_opencnam_provider() -> None:
    response = await InvestigationOrchestrator().investigate("+1 (415) 555-0101")

    assert response.ioc.type == IocType.PHONE
    assert response.mcp_servers_queried == ["mcp-opencnam"]
    assert response.sources == ["mcp-opencnam"]


async def test_social_handle_uses_social_presence_provider() -> None:
    response = await InvestigationOrchestrator().investigate("@octocat")

    assert response.ioc.type == IocType.SOCIAL_HANDLE
    assert response.mcp_servers_queried == ["mcp-social"]
    assert response.sources == ["mcp-social"]
