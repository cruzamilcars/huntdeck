"""Hermetic orchestrator tests.

Every test injects a fully-mocked provider dictionary so no live network
calls are made (keyless adapters like rdap/crt.sh/blockscout never fire).
Routing assertions pin the exact provider list per IOC type.
"""

from app.agents.mcp.mock_server import MockMcpClient
from app.domain.ioc.types import IocType
from app.services.orchestrator import InvestigationOrchestrator

_PROVIDER_NAMES = [
    "mcp-virustotal",
    "mcp-shodan",
    "mcp-abuseipdb",
    "mcp-rdap",
    "mcp-otx",
    "mcp-greynoise",
    "mcp-misp",
    "mcp-hibp",
    "mcp-hunterio",
    "mcp-intelx",
    "mcp-opencnam",
    "mcp-social",
    "mcp-urlscan",
    "mcp-urlhaus",
    "mcp-crtsh",
    "mcp-threatfox",
    "mcp-etherscan",
    "mcp-blockscout",
    "mcp-goplus",
    "mcp-dexscreener",
    "mcp-mempoolspace",
    "mcp-solana",
]


def _mock_orchestrator() -> InvestigationOrchestrator:
    return InvestigationOrchestrator(
        clients={name: MockMcpClient(name) for name in _PROVIDER_NAMES}
    )


async def test_orchestrator_returns_tactical_contract_for_ipv4() -> None:
    response = await _mock_orchestrator().investigate("8.8.8.8")

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
    assert response.mcp_servers_queried == [
        "mcp-virustotal",
        "mcp-shodan",
        "mcp-abuseipdb",
        "mcp-rdap",
        "mcp-otx",
        "mcp-greynoise",
        "mcp-misp",
    ]


async def test_domain_route_adds_ct_and_threat_intel_providers() -> None:
    response = await _mock_orchestrator().investigate("w-diarium.pw")

    assert response.ioc.type == IocType.DOMAIN
    assert response.mcp_servers_queried == [
        "mcp-virustotal",
        "mcp-shodan",
        "mcp-urlscan",
        "mcp-rdap",
        "mcp-otx",
        "mcp-misp",
        "mcp-urlhaus",
        "mcp-crtsh",
        "mcp-threatfox",
        "mcp-intelx",
    ]


async def test_url_route_adds_threatfox() -> None:
    response = await _mock_orchestrator().investigate("http://w-diarium.pw/malware.exe")

    assert response.ioc.type == IocType.URL
    assert response.mcp_servers_queried == [
        "mcp-virustotal",
        "mcp-urlscan",
        "mcp-otx",
        "mcp-misp",
        "mcp-urlhaus",
        "mcp-threatfox",
    ]


async def test_hash_route_adds_threatfox() -> None:
    response = await _mock_orchestrator().investigate(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )

    assert response.ioc.type == IocType.SHA256
    assert response.mcp_servers_queried == [
        "mcp-virustotal",
        "mcp-otx",
        "mcp-misp",
        "mcp-urlhaus",
        "mcp-threatfox",
    ]


async def test_email_route_uses_hibp_hunterio_intelx_and_misp() -> None:
    response = await _mock_orchestrator().investigate("analyst@example.com")

    assert response.ioc.type == IocType.EMAIL
    assert response.mcp_servers_queried == [
        "mcp-hibp",
        "mcp-hunterio",
        "mcp-intelx",
        "mcp-misp",
    ]
    assert response.sources == response.mcp_servers_queried


async def test_phone_route_uses_intelx_and_opencnam() -> None:
    response = await _mock_orchestrator().investigate("+1 (415) 555-0101")

    assert response.ioc.type == IocType.PHONE
    assert response.mcp_servers_queried == ["mcp-intelx", "mcp-opencnam"]


async def test_social_handle_uses_social_presence_provider() -> None:
    response = await _mock_orchestrator().investigate("@octocat")

    assert response.ioc.type == IocType.SOCIAL_HANDLE
    assert response.mcp_servers_queried == ["mcp-social"]


async def test_ethereum_address_route_uses_on_chain_providers() -> None:
    response = await _mock_orchestrator().investigate("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")

    assert response.ioc.type == IocType.ETHEREUM_ADDRESS
    assert response.mcp_servers_queried == [
        "mcp-etherscan",
        "mcp-blockscout",
        "mcp-goplus",
        "mcp-dexscreener",
    ]
    assert response.playbooks[0]["title"] == "Crypto wallet fraud triage"


async def test_bitcoin_address_route_uses_mempoolspace() -> None:
    response = await _mock_orchestrator().investigate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    assert response.ioc.type == IocType.BITCOIN_ADDRESS
    assert response.mcp_servers_queried == ["mcp-mempoolspace"]


async def test_solana_address_route_uses_solana_rpc() -> None:
    response = await _mock_orchestrator().investigate("So11111111111111111111111111111111111111112")

    assert response.ioc.type == IocType.SOLANA_ADDRESS
    assert response.mcp_servers_queried == ["mcp-solana"]


async def test_tx_hash_route_uses_etherscan_and_blockscout() -> None:
    response = await _mock_orchestrator().investigate("0x" + "ab" * 32)

    assert response.ioc.type == IocType.TX_HASH
    assert response.mcp_servers_queried == ["mcp-etherscan", "mcp-blockscout"]
    assert response.playbooks[0]["title"] == "On-chain transaction tracing"


async def test_ens_name_route_uses_blockscout() -> None:
    response = await _mock_orchestrator().investigate("vitalik.eth")

    assert response.ioc.type == IocType.ENS_NAME
    assert response.mcp_servers_queried == ["mcp-blockscout"]
    assert response.playbooks[0]["title"] == "ENS name attribution"


async def test_crypto_risk_escalates_with_mappings() -> None:
    response = await _mock_orchestrator().investigate("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")

    assert response.mappings.mitre_attack
    assert any("T1496" == mapping["id"] for mapping in response.mappings.mitre_attack)
    assert "wallet" in response.playbooks[-1]["title"].lower()


async def test_orchestrator_rejects_unknown_without_provider_calls() -> None:
    response = await _mock_orchestrator().investigate("not an ioc")

    assert response.ioc.type == IocType.UNKNOWN
    assert response.risk.severity == "unknown"
    assert response.sources == []


class _CountingClient(MockMcpClient):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.calls = 0

    async def query(self, ioc):
        self.calls += 1
        return await super().query(ioc)


async def test_orchestrator_serves_repeat_requests_from_cache() -> None:
    counting = _CountingClient("mcp-blockscout")
    clients = {"mcp-blockscout": counting, "mcp-goplus": _CountingClient("mcp-goplus")}
    orchestrator = InvestigationOrchestrator(clients=clients)
    seed = f"0x{'abcd' * 10}"

    first = await orchestrator.investigate(seed)
    cached = await orchestrator.investigate(seed)

    assert first.ioc.type == IocType.ETHEREUM_ADDRESS
    assert cached.ioc.normalized == first.ioc.normalized
    assert counting.calls == 1, "second identical investigation must be served from cache"
