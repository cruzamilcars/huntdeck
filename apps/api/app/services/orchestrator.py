from app.agents.mcp.client import McpClient
from app.agents.mcp.mock_server import MockMcpClient
from app.domain.ioc.parser import parse_ioc
from app.domain.ioc.types import IocType
from app.schemas.investigation import (
    InvestigationResponse,
    McpObservation,
    ResultModules,
    RiskSummary,
    TacticalMappings,
)


def _default_clients() -> dict[str, McpClient]:
    from app.agents.mcp.virustotal import VirusTotalMcpClient
    from app.core.config import get_settings

    clients: dict[str, McpClient] = {
        "mcp-virustotal": MockMcpClient("mcp-virustotal"),
        "mcp-shodan": MockMcpClient("mcp-shodan"),
        "mcp-abuseipdb": MockMcpClient("mcp-abuseipdb"),
        "mcp-firecrawl": MockMcpClient("mcp-firecrawl"),
    }
    api_key = get_settings().virustotal_api_key
    if api_key:
        clients["mcp-virustotal"] = VirusTotalMcpClient(api_key=api_key)
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
            sources=[observation.source for observation in observations],
            mcp_servers_queried=[observation.source for observation in observations],
            used_byok=used_byok,
            quota=quota or {},
        )

    def _select_providers(self, ioc_type: IocType | str) -> list[str]:
        match IocType(ioc_type):
            case IocType.IPV4 | IocType.IPV6:
                return ["mcp-virustotal", "mcp-shodan", "mcp-abuseipdb"]
            case IocType.DOMAIN:
                return ["mcp-virustotal", "mcp-shodan", "mcp-firecrawl"]
            case IocType.URL:
                return ["mcp-virustotal", "mcp-firecrawl"]
            case IocType.MD5 | IocType.SHA1 | IocType.SHA256:
                return ["mcp-virustotal"]
            case IocType.EMAIL | IocType.PHONE:
                return ["mcp-firecrawl"]
            case IocType.UNKNOWN:
                return []

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
        attack = [
            {
                "id": "T1595",
                "name": "Active Scanning",
                "reason": "Network or web-facing IOC requires external exposure review.",
            }
        ]
        if IocType(ioc_type) in {IocType.MD5, IocType.SHA1, IocType.SHA256}:
            attack = [
                {
                    "id": "T1204",
                    "name": "User Execution",
                    "reason": "File hash should be correlated with malware delivery chains.",
                }
            ]

        if risk.severity in {"high", "critical"}:
            attack.append(
                {
                    "id": "T1071",
                    "name": "Application Layer Protocol",
                    "reason": "High-risk IOC may indicate command-and-control activity.",
                }
            )

        return TacticalMappings(
            mitre_attack=attack,
            nist=[
                {
                    "id": "DE.CM",
                    "name": "Security Continuous Monitoring",
                    "reason": "IOC enrichment supports detection and monitoring workflows.",
                }
            ],
            iso=[
                {
                    "id": "A.5.7",
                    "name": "Threat intelligence",
                    "reason": "Investigation output is structured as threat intelligence evidence.",
                }
            ],
        )


def get_orchestrator() -> InvestigationOrchestrator:
    return InvestigationOrchestrator(clients=_default_clients())
