from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://urlscan.io/api/v1"


class UrlScanMcpClient:
    """Real urlscan.io adapter implementing the McpClient contract.

    Evaluated alternative to Firecrawl for the web-harvesting role: urlscan.io
    provides URL reputation (verdicts from security vendors), infrastructure
    attribution (IPs, ASNs, countries), content metadata and tags — richer
    threat-intel signal than raw page scraping, with a free API tier.

    The key is sent in the ``API-Key`` header and never logged. Failures become
    structured observations with an empty reputation.
    """

    name = "mcp-urlscan"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("URLSCAN_API_KEY is required to use the real adapter")
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
            return self._error_observation(f"urlscan_{reason}")
        except httpx.RequestError:
            return self._error_observation("urlscan_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type == IocType.URL:
            query = f"page.url:{ioc.normalized}"
        elif ioc.type == IocType.DOMAIN:
            query = f"domain:{ioc.normalized}"
        else:
            return self._error_observation("urlscan_unsupported_ioc")

        response = await self._client.get(
            "/search/",
            params={"q": query, "size": "1"},
            headers={"API-Key": self._api_key},
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("results"):
            return McpObservation(
                source=self.name,
                raw={
                    "entity": ioc.normalized,
                    "entity_type": ioc.type,
                    "mock": False,
                    "scans_found": 0,
                },
                reputation={
                    "score": 0,
                    "verdict": "unknown",
                    "tags": ["urlscan:no-scan-found"],
                },
            )
        return self._observation(data["results"][0], ioc)

    def _observation(self, result: dict, ioc: ParsedIoc) -> McpObservation:
        page = result.get("page") or {}
        stats = result.get("stats") or {}
        verdicts = stats.get("verdicts") or {}
        overall = verdicts.get("overall", {})
        malicious_engines = int(overall.get("malicious", 0))
        score = min(100, malicious_engines * 25 + int(stats.get("malicious", 0)) * 10)
        verdict = (
            "malicious"
            if malicious_engines or score >= 50
            else "suspicious"
            if score >= 25
            else "clean"
        )

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "scans_found": 1,
                "scan_uuid": result.get("_id"),
                "detected_url": page.get("url"),
            },
            reputation={
                "score": score,
                "verdict": verdict,
                "tags": [
                    *(f"urlscan:{tag}" for tag in (result.get("tags") or [])[:8]),
                    f"urlscan:engines:{int(stats.get('malicious', 0))}",
                ],
            },
            geolocation=self._geolocation(page),
            relationships=self._relationships(page),
            community_reports=self._community_reports(stats),
        )

    def _geolocation(self, page: dict) -> dict[str, Any] | None:
        geo = {}
        for key in ("country", "ip", "asn", "domain"):
            if page.get(key):
                geo[key] = str(page[key])
        if not geo:
            return None
        return {**geo, "provider": self.name}

    def _relationships(self, page: dict) -> list[dict[str, str]]:
        relationships = []
        if page.get("ip"):
            relationships.append({"kind": "hosted_at", "target": str(page["ip"])})
        if page.get("domain"):
            relationships.append({"kind": "registers_under", "target": str(page["domain"])})
        if page.get("server"):
            relationships.append({"kind": "served_by", "target": str(page["server"])})
        return relationships

    def _community_reports(self, stats: dict) -> list[dict[str, str]]:
        malicious = int(stats.get("malicious", 0))
        if not malicious:
            return []
        return [
            {
                "title": f"{malicious} security vendors flagged this page",
                "confidence": "medium",
                "summary": (
                    f"urlscan.io scan shows {malicious} malicious verdict(s) from security vendors."
                ),
            }
        ]

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
