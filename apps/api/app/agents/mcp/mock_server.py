from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation


class MockMcpClient:
    def __init__(self, name: str) -> None:
        self.name = name

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        malicious_hint = self._risk_hint(ioc)
        score = self._score(ioc, malicious_hint)
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "risk_hint": malicious_hint,
                "mock": True,
            },
            reputation={
                "score": score,
                "verdict": self._verdict(score),
                "tags": self._tags(ioc),
            },
            geolocation=self._geolocation(ioc),
            relationships=self._relationships(ioc),
            community_reports=[
                {
                    "title": "Simulated community signal",
                    "confidence": "medium",
                    "summary": f"{self.name} returned deterministic mock telemetry.",
                }
            ],
        )

    def _risk_hint(self, ioc: ParsedIoc) -> str:
        lowered = ioc.normalized.lower()
        if any(token in lowered for token in ("malware", "phish", "evil", "botnet")):
            return "high"
        if ioc.type in {IocType.MD5, IocType.SHA1, IocType.SHA256}:
            return "medium"
        return "low"

    def _score(self, ioc: ParsedIoc, hint: str) -> int:
        base = {"low": 18, "medium": 48, "high": 82}[hint]
        provider_bias = sum(ord(char) for char in self.name) % 9
        type_bias = 10 if ioc.type in {IocType.URL, IocType.SHA256} else 0
        return min(100, base + provider_bias + type_bias)

    def _verdict(self, score: int) -> str:
        if score >= 80:
            return "malicious"
        if score >= 45:
            return "suspicious"
        return "clean"

    def _tags(self, ioc: ParsedIoc) -> list[str]:
        tags = ["mcp-simulated"]
        if ioc.type in {IocType.URL, IocType.DOMAIN, IocType.EMAIL}:
            tags.append("external-facing")
        if ioc.type in {IocType.MD5, IocType.SHA1, IocType.SHA256}:
            tags.append("file-artifact")
        return tags

    def _geolocation(self, ioc: ParsedIoc) -> dict[str, str] | None:
        if ioc.type not in {IocType.IPV4, IocType.IPV6, IocType.DOMAIN, IocType.URL}:
            return None
        return {
            "country": "ZZ",
            "region": "Simulated",
            "asn": "AS64512",
            "provider": self.name,
        }

    def _relationships(self, ioc: ParsedIoc) -> list[dict[str, str]]:
        if ioc.type == IocType.DOMAIN:
            return [
                {"kind": "resolves_to", "target": "203.0.113.10"},
                {"kind": "uses_nameserver", "target": f"ns1.{ioc.normalized}"},
            ]
        if ioc.type == IocType.URL:
            return [{"kind": "hosts_path", "target": ioc.normalized}]
        if ioc.type in {IocType.MD5, IocType.SHA1, IocType.SHA256}:
            return [{"kind": "seen_in_campaign", "target": "SIM-CAMPAIGN-001"}]
        return []
