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
from app.services.playbooks import playbook_for


def _default_clients() -> dict[str, McpClient]:
    from app.agents.mcp.abuseipdb import AbuseIpdbMcpClient
    from app.agents.mcp.hibp import HibpMcpClient
    from app.agents.mcp.opencnam import OpenCnamMcpClient
    from app.agents.mcp.otx import OtxMcpClient
    from app.agents.mcp.rdap import RdapMcpClient
    from app.agents.mcp.shodan import ShodanMcpClient
    from app.agents.mcp.social import SocialPresenceMcpClient
    from app.agents.mcp.urlscan import UrlScanMcpClient
    from app.agents.mcp.virustotal import VirusTotalMcpClient

    settings = get_settings()
    clients: dict[str, McpClient] = {
        "mcp-virustotal": MockMcpClient("mcp-virustotal"),
        "mcp-shodan": MockMcpClient("mcp-shodan"),
        "mcp-abuseipdb": MockMcpClient("mcp-abuseipdb"),
        "mcp-hibp": MockMcpClient("mcp-hibp"),
        "mcp-opencnam": MockMcpClient("mcp-opencnam"),
        "mcp-otx": MockMcpClient("mcp-otx"),
        "mcp-rdap": RdapMcpClient(),
        "mcp-urlscan": UrlScanMcpClient(api_key=settings.urlscan_api_key),
        "mcp-social": SocialPresenceMcpClient(),
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
        observations = [
            await self.clients[provider_name].query(parsed_ioc)
            for provider_name in provider_names
            if provider_name in self.clients
        ]
        risk = self._summarize_risk(observations)

        return InvestigationResponse(
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

    def _select_providers(self, ioc_type: IocType | str) -> list[str]:
        match IocType(ioc_type):
            case IocType.IPV4 | IocType.IPV6:
                return ["mcp-virustotal", "mcp-shodan", "mcp-abuseipdb", "mcp-rdap", "mcp-otx"]
            case IocType.DOMAIN:
                return ["mcp-virustotal", "mcp-shodan", "mcp-urlscan", "mcp-rdap", "mcp-otx"]
            case IocType.URL:
                return ["mcp-virustotal", "mcp-urlscan", "mcp-otx"]
            case IocType.MD5 | IocType.SHA1 | IocType.SHA256:
                return ["mcp-virustotal", "mcp-otx"]
            case IocType.EMAIL:
                return ["mcp-hibp"]
            case IocType.PHONE:
                return ["mcp-opencnam"]
            case IocType.SOCIAL_HANDLE:
                return ["mcp-social"]
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
    IocType.UNKNOWN: [
        (
            "T1595",
            "Active Scanning",
            "Unclassified IOC still requires exposure review.",
        ),
    ],
}


def get_orchestrator() -> InvestigationOrchestrator:
    return InvestigationOrchestrator(clients=_default_clients())
