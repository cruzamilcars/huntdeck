import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIpdbMcpClient:
    """Real AbuseIPDB adapter implementing the McpClient contract.

    Queries the AbuseIPDB check endpoint (IPv4 only). The key is sent in the
    ``Key`` header and never logged. Failures become structured observations
    with an empty reputation, so the orchestration never breaks.
    """

    name = "mcp-abuseipdb"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("ABUSEIPDB_API_KEY is required to use the real adapter")
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
            return self._error_observation(f"abuseipdb_{reason}")
        except httpx.RequestError:
            return self._error_observation("abuseipdb_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.IPV4:
            return self._error_observation("abuseipdb_unsupported_ioc")

        response = await self._client.get(
            "/check",
            params={"ipAddress": ioc.normalized, "maxAgeInDays": "90", "verbose": ""},
            headers={"Key": self._api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()["data"]
        return self._observation(data, ioc)

    def _observation(self, data: dict, ioc: ParsedIoc) -> McpObservation:
        score = int(data.get("abuseConfidenceScore", 0))
        reports = data.get("reports") or []
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "total_reports": int(data.get("totalReports", 0)),
                "num_distinct_users": data.get("numDistinctUsers"),
                "is_whitelisted": data.get("isWhitelisted", False),
            },
            reputation={
                "score": score,
                "verdict": "malicious" if score >= 80 else "suspicious" if score > 0 else "clean",
                "tags": self._tags(data),
            },
            geolocation=self._geolocation(data),
            relationships=self._relationships(data),
            community_reports=self._community_reports(reports),
        )

    def _tags(self, data: dict) -> list[str]:
        tags = ["abuseipdb"]
        if data.get("isTor"):
            tags.append("tor-exit")
        usage = data.get("usageType")
        if usage:
            tags.append(f"usage:{usage}")
        return tags[:8]

    def _geolocation(self, data: dict) -> dict[str, str] | None:
        geo = {}
        if data.get("countryName"):
            geo["country"] = str(data["countryName"])
        if data.get("isp"):
            geo["isp"] = str(data["isp"])
        if data.get("domain"):
            geo["domain"] = str(data["domain"])
        if not geo:
            return None
        return {**geo, "provider": self.name}

    def _relationships(self, data: dict) -> list[dict[str, str]]:
        relationships = []
        domain = data.get("domain")
        if domain:
            relationships.append({"kind": "registered_under", "target": str(domain)})
        if data.get("isTor"):
            relationships.append({"kind": "traffics_over_tor", "target": "TOR network"})
        return relationships

    def _community_reports(self, reports: list[dict]) -> list[dict[str, str]]:
        community = []
        for report in reports[:3]:
            category = (report.get("categories") or ["reported"])[0]
            community.append(
                {
                    "title": f"AbuseIPDB report ({category})",
                    "confidence": "high",
                    "summary": (report.get("comment") or "Community-reported abusive activity.")[
                        :200
                    ],
                }
            )
        return community

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
