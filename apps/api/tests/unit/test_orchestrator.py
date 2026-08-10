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
    assert response.used_byok is True
    assert response.quota["reason"] == "byok"
    assert response.mcp_servers_queried == ["mcp-virustotal", "mcp-shodan", "mcp-abuseipdb"]


async def test_orchestrator_rejects_unknown_without_provider_calls() -> None:
    response = await InvestigationOrchestrator().investigate("not an ioc")

    assert response.ioc.type == IocType.UNKNOWN
    assert response.risk.severity == "unknown"
    assert response.sources == []
