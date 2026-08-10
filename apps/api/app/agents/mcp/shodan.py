import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.shodan.io"


class ShodanMcpClient:
    """Real Shodan adapter implementing the McpClient contract.

    Queries the Shodan host and DNS endpoints. The key is sent as the ``key``
    query parameter (Shodan API convention) and never logged. Failures become
    structured observations with an empty reputation, so the orchestration
    never breaks.
    """

    name = "mcp-shodan"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("SHODAN_API_KEY is required to use the real adapter")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=10.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"403": "forbidden", "404": "not_found", "429": "rate_limited"}.get(
                str(status), f"http_{status}"
            )
            return self._error_observation(f"shodan_{reason}")
        except httpx.RequestError:
            return self._error_observation("shodan_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type in {IocType.IPV4, IocType.IPV6}:
            return await self._query_host(ioc)
        if ioc.type in {IocType.DOMAIN}:
            return await self._query_dns(ioc)
        return self._error_observation("shodan_unsupported_ioc")

    async def _query_host(self, ioc: ParsedIoc) -> McpObservation:
        response = await self._client.get(
            f"/shodan/host/{ioc.normalized}",
            params={"key": self._api_key, "minify": "true"},
        )
        response.raise_for_status()
        return self._observation(response.json(), ioc)

    async def _query_dns(self, ioc: ParsedIoc) -> McpObservation:
        response = await self._client.get(
            "/dns/resolve",
            params={"hostnames": ioc.normalized, "key": self._api_key},
        )
        response.raise_for_status()
        resolved = response.json().get(ioc.normalized)
        if not resolved:
            return self._error_observation("shodan_dns_no_result")
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "resolved_ips": [resolved],
            },
            reputation={"score": 0, "verdict": "unknown", "tags": ["shodan-dns"]},
            relationships=[{"kind": "resolves_to", "target": str(resolved)}],
        )

    def _observation(self, data: dict, ioc: ParsedIoc) -> McpObservation:
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "ports": ports,
                "hostnames": data.get("hostnames") or [],
            },
            reputation={
                "score": min(100, len(vulns) * 25 + len(ports) * 3),
                "verdict": self._verdict(vulns, ports, data),
                "tags": self._tags(vulns, ports),
            },
            geolocation=self._geolocation(data),
            relationships=self._relationships(data),
            community_reports=self._community_reports(vulns),
        )

    @staticmethod
    def _verdict(vulns: list[str], ports: list[int], data: dict) -> str:
        if vulns:
            return "suspicious"
        if ports or data.get("hostnames"):
            return "clean"
        return "unknown"

    def _tags(self, vulns: list[str], ports: list[int]) -> list[str]:
        tags = [f"shodan:vuln:{cve}" for cve in vulns[:10]]
        if ports:
            tags.append(f"exposed:{','.join(str(p) for p in ports[:5])}")
        return tags

    def _geolocation(self, data: dict) -> dict[str, str] | None:
        geo = {}
        if data.get("country_name"):
            geo["country"] = str(data["country_name"])
        if data.get("city"):
            geo["city"] = str(data["city"])
        if data.get("org"):
            geo["org"] = str(data["org"])
        if data.get("asn"):
            geo["asn"] = str(data["asn"])
        if not geo:
            return None
        return {**geo, "provider": self.name}

    def _relationships(self, data: dict) -> list[dict[str, str]]:
        relationships = []
        for hostname in (data.get("hostnames") or [])[:5]:
            relationships.append({"kind": "has_hostname", "target": str(hostname)})
        for cve in (data.get("vulns") or [])[:5]:
            relationships.append({"kind": "affected_by_vuln", "target": str(cve)})
        return relationships

    def _community_reports(self, vulns: list[str]) -> list[dict[str, str]]:
        reports = []
        for cve in vulns[:3]:
            reports.append(
                {
                    "title": f"Exposure: {cve}",
                    "confidence": "high",
                    "summary": f"Shodan found an exposed service affected by {cve}.",
                }
            )
        return reports

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
