import asyncio
import logging
from functools import lru_cache

from app.agents.mcp.client import McpClient
from app.agents.mcp.mock_server import MockMcpClient
from app.core.config import get_settings
from app.domain.ioc.parser import parse_ioc
from app.domain.ioc.types import IocType
from app.schemas.investigation import (
    InvestigationResponse,
    McpObservation,
    ResultModules,
    RiskSummary,
    TacticalMappings,
)
from app.services.cache import get_cache_backend
from app.services.playbooks import playbook_for

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 5 * 60
_CACHE_MAX_ENTRIES = 256

_MOCK_NAMES = (
    "mcp-virustotal",
    "mcp-shodan",
    "mcp-abuseipdb",
    "mcp-hibp",
    "mcp-opencnam",
    "mcp-otx",
    "mcp-greynoise",
    "mcp-misp",
    "mcp-opencti",
    "mcp-urlhaus",
    "mcp-rdap",
    "mcp-urlscan",
    "mcp-social",
    "mcp-intelx",
    "mcp-hunterio",
    "mcp-crtsh",
    "mcp-threatfox",
    "mcp-blockscout",
    "mcp-mempoolspace",
    "mcp-goplus",
    "mcp-dexscreener",
    "mcp-solana",
    "mcp-etherscan",
)

# Investigation result cache (see app/services/cache.py). Default backend is an
# in-process dict; setting REDIS_URL swaps to a shared Redis cache so hits
# survive across `--workers > 1` or multiple replicas.
#
# KNOWN LIMITATION (in-memory only): the dict backend lives in the uvicorn
# worker process, so cache hits are NOT shared across `--workers > 1` or
# multiple replicas. Rate limiting has the same property. Both are correct
# for the MVP (one worker, quota enforced durably in SQLite/Supabase), but
# scaling out requires a shared cache (Redis) — see docs/architecture.md.
_CACHE_TTL_SECONDS = 5 * 60
_CACHE_MAX_ENTRIES = 256


def _default_clients() -> dict[str, McpClient]:
    from app.agents.mcp.abuseipdb import AbuseIpdbMcpClient
    from app.agents.mcp.blockscout import BlockscoutMcpClient
    from app.agents.mcp.crtsh import CrtshMcpClient
    from app.agents.mcp.dexscreener import DexscreenerMcpClient
    from app.agents.mcp.etherscan import EtherscanMcpClient
    from app.agents.mcp.goplus import GoplusMcpClient
    from app.agents.mcp.greynoise import GreynoiseMcpClient
    from app.agents.mcp.hibp import HibpMcpClient
    from app.agents.mcp.hunterio import HunterioMcpClient
    from app.agents.mcp.intelx import IntelxMcpClient
    from app.agents.mcp.mempool import MempoolspaceMcpClient
    from app.agents.mcp.misp import MispMcpClient
    from app.agents.mcp.opencnam import OpenCnamMcpClient
    from app.agents.mcp.opencti import OpenCtiMcpClient
    from app.agents.mcp.otx import OtxMcpClient
    from app.agents.mcp.rdap import RdapMcpClient
    from app.agents.mcp.shodan import ShodanMcpClient
    from app.agents.mcp.social import SocialPresenceMcpClient
    from app.agents.mcp.solana import SolanaMcpClient
    from app.agents.mcp.threatfox import ThreatfoxMcpClient
    from app.agents.mcp.urlhaus import UrlHausMcpClient
    from app.agents.mcp.urlscan import UrlScanMcpClient
    from app.agents.mcp.virustotal import VirusTotalMcpClient

    settings = get_settings()
    if settings.mcp_mock_all:
        return {provider_name: MockMcpClient(provider_name) for provider_name in _MOCK_NAMES}
    clients: dict[str, McpClient] = {
        "mcp-virustotal": MockMcpClient("mcp-virustotal"),
        "mcp-shodan": MockMcpClient("mcp-shodan"),
        "mcp-abuseipdb": MockMcpClient("mcp-abuseipdb"),
        "mcp-hibp": MockMcpClient("mcp-hibp"),
        "mcp-opencnam": MockMcpClient("mcp-opencnam"),
        "mcp-otx": MockMcpClient("mcp-otx"),
        "mcp-greynoise": MockMcpClient("mcp-greynoise"),
        "mcp-misp": MockMcpClient("mcp-misp"),
        "mcp-opencti": MockMcpClient("mcp-opencti"),
        "mcp-urlhaus": MockMcpClient("mcp-urlhaus"),
        "mcp-rdap": RdapMcpClient(),
        "mcp-urlscan": UrlScanMcpClient(api_key=settings.urlscan_api_key),
        "mcp-social": SocialPresenceMcpClient(),
        "mcp-intelx": MockMcpClient("mcp-intelx"),
        "mcp-hunterio": MockMcpClient("mcp-hunterio"),
        "mcp-crtsh": CrtshMcpClient(),
        "mcp-threatfox": MockMcpClient("mcp-threatfox"),
        "mcp-blockscout": BlockscoutMcpClient(),
        "mcp-mempoolspace": MempoolspaceMcpClient(),
        "mcp-goplus": GoplusMcpClient(),
        "mcp-dexscreener": DexscreenerMcpClient(),
        "mcp-solana": SolanaMcpClient(),
        "mcp-etherscan": MockMcpClient("mcp-etherscan"),
    }
    if settings.virustotal_api_key:
        clients["mcp-virustotal"] = VirusTotalMcpClient(api_key=settings.virustotal_api_key)
    if settings.abuseipdb_api_key:
        clients["mcp-abuseipdb"] = AbuseIpdbMcpClient(api_key=settings.abuseipdb_api_key)
    if settings.shodan_api_key:
        clients["mcp-shodan"] = ShodanMcpClient(api_key=settings.shodan_api_key)
    if settings.hibp_api_key:
        clients["mcp-hibp"] = HibpMcpClient(api_key=settings.hibp_api_key)
    if settings.opencnam_api_key:
        clients["mcp-opencnam"] = OpenCnamMcpClient(api_key=settings.opencnam_api_key)
    if settings.otx_api_key:
        clients["mcp-otx"] = OtxMcpClient(api_key=settings.otx_api_key)
    if settings.greynoise_api_key:
        clients["mcp-greynoise"] = GreynoiseMcpClient(api_key=settings.greynoise_api_key)
    if settings.misp_url and settings.misp_api_key:
        clients["mcp-misp"] = MispMcpClient(
            base_url=settings.misp_url,
            api_key=settings.misp_api_key,
            verify_ssl=settings.misp_verify_ssl,
        )
    if settings.opencti_url and settings.opencti_api_key:
        clients["mcp-opencti"] = OpenCtiMcpClient(
            base_url=settings.opencti_url,
            api_key=settings.opencti_api_key,
            verify_ssl=settings.opencti_verify_ssl,
        )
    if settings.urlhaus_api_key:
        clients["mcp-urlhaus"] = UrlHausMcpClient(api_key=settings.urlhaus_api_key)
    if settings.intelx_api_key:
        clients["mcp-intelx"] = IntelxMcpClient(api_key=settings.intelx_api_key)
    if settings.hunterio_api_key:
        clients["mcp-hunterio"] = HunterioMcpClient(api_key=settings.hunterio_api_key)
    if settings.threatfox_api_key:
        clients["mcp-threatfox"] = ThreatfoxMcpClient(api_key=settings.threatfox_api_key)
    if settings.etherscan_api_key:
        clients["mcp-etherscan"] = EtherscanMcpClient(api_key=settings.etherscan_api_key)
    return clients


class InvestigationOrchestrator:
    def __init__(self, clients: dict[str, McpClient] | None = None) -> None:
        self.clients = clients or _default_clients()

    async def investigate(
        self,
        raw_ioc: str,
        *,
        used_byok: bool = False,
        quota: dict[str, int | str | bool] | None = None,
    ) -> InvestigationResponse:
        parsed_ioc = parse_ioc(raw_ioc)
        provider_names = self._select_providers(parsed_ioc.type)

        use_cache = not used_byok and not quota
        backend = await get_cache_backend() if use_cache else None
        # Cache lookup with TTL (skip cache when BYOK used or when caller supplies quota)
        if backend is not None:
            cache_key = f"{parsed_ioc.normalized}:{parsed_ioc.type}"
            cached = await backend.get(cache_key)
            if cached is not None:
                logger.debug("orchestrator.cache.hit", extra={"ioc": parsed_ioc.normalized})
                try:
                    return InvestigationResponse.model_validate(cached)
                except Exception:  # noqa: BLE001 - a corrupt cache entry is a miss
                    logger.warning(
                        "orchestrator.cache.corrupt", extra={"ioc": parsed_ioc.normalized}
                    )

        # Concurrent queries to all selected providers
        tasks = [
            self.clients[provider_name].query(parsed_ioc)
            for provider_name in provider_names
            if provider_name in self.clients
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        observations = []
        for provider_name, result in zip([p for p in provider_names if p in self.clients], results):
            if isinstance(result, Exception):
                logger.warning(
                    "orchestrator.provider.error",
                    extra={"provider": provider_name, "error": str(result)},
                )
                continue
            observations.append(result)
        risk = self._summarize_risk(observations)

        response = InvestigationResponse(
            ioc=parsed_ioc,
            risk=risk,
            modules=self._merge_modules(observations),
            mappings=self._map_controls(parsed_ioc.type, risk),
            playbooks=playbook_for(parsed_ioc.type, risk.severity),
            sources=[observation.source for observation in observations],
            mcp_servers_queried=[observation.source for observation in observations],
            used_byok=used_byok,
            quota=quota or {},
        )
        if backend is not None:
            await backend.put(cache_key, response.model_dump(mode="json"))
        return response

    def _select_providers(self, ioc_type: IocType | str) -> list[str]:
        match IocType(ioc_type):
            case IocType.IPV4:
                return [
                    "mcp-virustotal",
                    "mcp-shodan",
                    "mcp-abuseipdb",
                    "mcp-rdap",
                    "mcp-otx",
                    "mcp-greynoise",
                    "mcp-misp",
                    "mcp-opencti",
                ]
            case IocType.IPV6:
                # GreyNoise Community only accepts IPv4.
                return [
                    "mcp-virustotal",
                    "mcp-shodan",
                    "mcp-abuseipdb",
                    "mcp-rdap",
                    "mcp-otx",
                    "mcp-misp",
                    "mcp-opencti",
                ]
            case IocType.DOMAIN:
                return [
                    "mcp-virustotal",
                    "mcp-shodan",
                    "mcp-urlscan",
                    "mcp-rdap",
                    "mcp-otx",
                    "mcp-misp",
                    "mcp-opencti",
                    "mcp-urlhaus",
                    "mcp-crtsh",
                    "mcp-threatfox",
                    "mcp-intelx",
                ]
            case IocType.URL:
                return [
                    "mcp-virustotal",
                    "mcp-urlscan",
                    "mcp-otx",
                    "mcp-misp",
                    "mcp-opencti",
                    "mcp-urlhaus",
                    "mcp-threatfox",
                ]
            case IocType.MD5 | IocType.SHA1 | IocType.SHA256:
                return [
                    "mcp-virustotal",
                    "mcp-otx",
                    "mcp-misp",
                    "mcp-opencti",
                    "mcp-urlhaus",
                    "mcp-threatfox",
                ]
            case IocType.EMAIL:
                return ["mcp-hibp", "mcp-hunterio", "mcp-intelx", "mcp-misp", "mcp-opencti"]
            case IocType.PHONE:
                return ["mcp-intelx", "mcp-opencnam"]
            case IocType.SOCIAL_HANDLE:
                return ["mcp-social"]
            case IocType.ETHEREUM_ADDRESS:
                return [
                    "mcp-etherscan",
                    "mcp-blockscout",
                    "mcp-goplus",
                    "mcp-dexscreener",
                ]
            case IocType.BITCOIN_ADDRESS:
                return ["mcp-mempoolspace"]
            case IocType.SOLANA_ADDRESS:
                return ["mcp-solana"]
            case IocType.TX_HASH:
                return ["mcp-etherscan", "mcp-blockscout"]
            case IocType.ENS_NAME:
                return ["mcp-blockscout"]
            case IocType.UNKNOWN:
                return []

    def provider_coverage(self) -> dict[str, list[str]]:
        coverage: dict[str, list[str]] = {}
        for ioc_type in IocType:
            for provider_name in self._select_providers(ioc_type):
                coverage.setdefault(provider_name, []).append(str(ioc_type))
        return {name: sorted(types) for name, types in sorted(coverage.items())}

    def provider_modes(self) -> dict[str, str]:
        return {
            name: "mock" if isinstance(client, MockMcpClient) else "real"
            for name, client in self.clients.items()
        }

    def _summarize_risk(self, observations: list[McpObservation]) -> RiskSummary:
        if not observations:
            return RiskSummary(score=0, severity="unknown")

        max_score = max(int(obs.reputation.get("score", 0)) for obs in observations)
        if max_score >= 85:
            severity = "critical"
        elif max_score >= 70:
            severity = "high"
        elif max_score >= 40:
            severity = "medium"
        elif max_score > 0:
            severity = "low"
        else:
            severity = "unknown"
        return RiskSummary(score=max_score, severity=severity)

    def _merge_modules(self, observations: list[McpObservation]) -> ResultModules:
        return ResultModules(
            reputation={
                observation.source: observation.reputation
                for observation in observations
                if observation.reputation
            },
            geolocation={
                observation.source: observation.geolocation
                for observation in observations
                if observation.geolocation
            },
            relationship_graph={
                "nodes": self._relationship_nodes(observations),
                "edges": self._relationship_edges(observations),
            },
            community_reports=[
                {**report, "source": observation.source}
                for observation in observations
                for report in observation.community_reports
            ],
        )

    def _relationship_nodes(self, observations: list[McpObservation]) -> list[dict[str, str]]:
        nodes: dict[str, dict[str, str]] = {}
        for observation in observations:
            nodes[observation.source] = {"id": observation.source, "type": "source"}
            entity = str(observation.raw.get("entity", "unknown"))
            nodes[entity] = {"id": entity, "type": str(observation.raw.get("entity_type", "ioc"))}
            for relationship in observation.relationships:
                target = str(relationship["target"])
                nodes[target] = {"id": target, "type": str(relationship["kind"])}
        return list(nodes.values())

    def _relationship_edges(self, observations: list[McpObservation]) -> list[dict[str, str]]:
        edges: list[dict[str, str]] = []
        for observation in observations:
            entity = str(observation.raw.get("entity", "unknown"))
            edges.append({"source": observation.source, "target": entity, "kind": "observed"})
            edges.extend(
                {
                    "source": entity,
                    "target": str(relationship["target"]),
                    "kind": str(relationship["kind"]),
                }
                for relationship in observation.relationships
            )
        return edges

    def _map_controls(self, ioc_type: IocType | str, risk: RiskSummary) -> TacticalMappings:
        ioc_type = IocType(ioc_type)
        attack = [
            {
                "id": technique,
                "name": name,
                "reason": reason,
            }
            for technique, name, reason in _ATTACK_MAPPINGS[ioc_type]
        ]

        if risk.severity in {"high", "critical"}:
            attack.append(
                {
                    "id": "T1071.001",
                    "name": "Application Layer Protocol: Web Protocols",
                    "reason": "High-risk IOC may indicate command-and-control activity.",
                }
            )

        nist = [
            {
                "id": "DE.AE-02",
                "name": "Analysis of Events",
                "reason": "Enrichment supports correlation and triage of security events.",
            },
            {
                "id": "DE.CM-01",
                "name": "Continuous Monitoring",
                "reason": "IOC reputation and infrastructure telemetry feed detection coverage.",
            },
        ]
        if risk.severity in {"medium", "high", "critical"}:
            nist.append(
                {
                    "id": "RS.AN-03",
                    "name": "Analysis (forensics, impact, scope)",
                    "reason": "Suspicious IOC requires formal analysis and scope determination.",
                }
            )
        if risk.severity == "critical":
            nist.append(
                {
                    "id": "ID.RA-01",
                    "name": "Risk Identification",
                    "reason": "Critical IOC triggers risk identification and impact assessment.",
                }
            )

        iso = [
            {
                "id": "A.5.7",
                "name": "Threat intelligence",
                "reason": "Investigation output is structured as threat intelligence evidence.",
            },
            {
                "id": "A.8.23",
                "name": "Information security incident management",
                "reason": "Malicious IOCs escalate into the incident management process.",
            },
        ]
        if risk.severity in {"high", "critical"}:
            iso.append(
                {
                    "id": "A.8.9",
                    "name": "Configuration management",
                    "reason": "High-risk IOCs require containment and configuration changes.",
                }
            )

        return TacticalMappings(
            mitre_attack=attack,
            nist=nist,
            iso=iso,
        )


_ATTACK_MAPPINGS: dict[IocType, list[tuple[str, str, str]]] = {
    IocType.IPV4: [
        (
            "T1595",
            "Active Scanning",
            "Network-facing IOC requires exposure review and scanning attribution.",
        ),
        (
            "T1590.002",
            "Gather Victim Network Information: IP Addresses",
            "IP telemetry may expose victim network ranges and infrastructure.",
        ),
        (
            "T1071.001",
            "Application Layer Protocol: Web Protocols",
            "IP may host C2 or malicious web services.",
        ),
    ],
    IocType.IPV6: [
        (
            "T1595",
            "Active Scanning",
            "Network-facing IOC requires exposure review and scanning attribution.",
        ),
        (
            "T1590.002",
            "Gather Victim Network Information: IP Addresses",
            "IP telemetry may expose victim network ranges and infrastructure.",
        ),
        (
            "T1071.001",
            "Application Layer Protocol: Web Protocols",
            "IP may host C2 or malicious web services.",
        ),
    ],
    IocType.DOMAIN: [
        (
            "T1583.001",
            "Acquire Infrastructure: Domains",
            "Domain may be attacker-acquired infrastructure.",
        ),
        (
            "T1596.004",
            "Search Open Technical Databases: DNS",
            "DNS and registration records support attribution.",
        ),
        (
            "T1568.002",
            "Dynamic Resolution: Domain Generation Algorithms",
            "Domain may be DGA-generated or fast-flux infrastructure.",
        ),
    ],
    IocType.URL: [
        (
            "T1566.002",
            "Phishing: Spearphishing Link",
            "URL may be delivered as a phishing link.",
        ),
        (
            "T1204.001",
            "User Execution: Malicious Link",
            "URL requires victim interaction to trigger the payload.",
        ),
        (
            "T1189",
            "Drive-by Compromise",
            "URL may be used for drive-by exploitation.",
        ),
    ],
    IocType.MD5: [
        (
            "T1204",
            "User Execution",
            "File hash should be correlated with malware delivery chains.",
        ),
        (
            "T1027",
            "Obfuscated Files or Information",
            "Malicious binaries often use packing or obfuscation.",
        ),
    ],
    IocType.SHA1: [
        (
            "T1204",
            "User Execution",
            "File hash should be correlated with malware delivery chains.",
        ),
        (
            "T1027",
            "Obfuscated Files or Information",
            "Malicious binaries often use packing or obfuscation.",
        ),
    ],
    IocType.SHA256: [
        (
            "T1204",
            "User Execution",
            "File hash should be correlated with malware delivery chains.",
        ),
        (
            "T1027",
            "Obfuscated Files or Information",
            "Malicious binaries often use packing or obfuscation.",
        ),
    ],
    IocType.EMAIL: [
        (
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Email may be a phishing vector for the attached indicators.",
        ),
        (
            "T1114.002",
            "Email Collection: Remote Email Collection",
            "Compromised mailboxes may be used for BEC or exfiltration.",
        ),
        (
            "T1534",
            "Internal Spearphishing",
            "Compromised accounts are often reused for internal phishing.",
        ),
    ],
    IocType.PHONE: [
        (
            "T1598.003",
            "Phishing for Information: Spearphishing via Service",
            "Phone numbers are used in vishing and fraud operations.",
        ),
        (
            "T1585.002",
            "Establish Accounts: Email Accounts",
            "Numbers are linked to fraud personas and account seeding.",
        ),
    ],
    IocType.SOCIAL_HANDLE: [
        (
            "T1585.001",
            "Establish Accounts: Social Media Accounts",
            "Handles are used to build fraud personas.",
        ),
        (
            "T1534",
            "Internal Spearphishing",
            "Impersonated accounts may enable internal phishing.",
        ),
    ],
    IocType.ETHEREUM_ADDRESS: [
        (
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Address may fund or receive approval-phishing / drainer campaigns.",
        ),
        (
            "T1496",
            "Resource Hijacking",
            "Wallet may be a cryptocurrency-mining payout address.",
        ),
        (
            "T1078",
            "Valid Accounts",
            "Stolen credentials frequently covert value through such addresses.",
        ),
    ],
    IocType.BITCOIN_ADDRESS: [
        (
            "T1496",
            "Resource Hijacking",
            "Wallet may be a cryptocurrency-mining payout address.",
        ),
        (
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Address may be tied to extortion or phishing payment demands.",
        ),
    ],
    IocType.SOLANA_ADDRESS: [
        (
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Address may fund drainer or fake-airdrop campaigns.",
        ),
        (
            "T1496",
            "Resource Hijacking",
            "Wallet may receive illicit mining or staking payouts.",
        ),
    ],
    IocType.TX_HASH: [
        (
            "T1071.001",
            "Application Layer Protocol",
            "Transactions are the value-transfer channel for the campaign.",
        ),
        (
            "T1048.003",
            "Exfiltration Over Alternative Protocol",
            "Funds taint flows through the transaction graph.",
        ),
        (
            "T1496",
            "Resource Hijacking",
            "On-chain payouts can be traced across the transaction chain.",
        ),
    ],
    IocType.ENS_NAME: [
        (
            "T1583.001",
            "Acquire Infrastructure: Domains",
            "ENS name may front an attacker-controlled address.",
        ),
        (
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Fraudulent ENS names are used in phishing and wallet drains.",
        ),
    ],
    IocType.UNKNOWN: [
        (
            "T1595",
            "Active Scanning",
            "Unclassified IOC still requires exposure review.",
        ),
    ],
}


@lru_cache
def get_orchestrator() -> InvestigationOrchestrator:
    return InvestigationOrchestrator(clients=_default_clients())
