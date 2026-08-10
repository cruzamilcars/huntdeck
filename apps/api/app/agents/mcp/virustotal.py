from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalMcpClient:
    """Real VirusTotal adapter implementing the McpClient contract.

    Calls the VirusTotal REST API v3 directly. The key is only ever sent in
    the ``x-apikey`` header and never logged or echoed into observations.
    Failures are converted into structured observations with an empty
    reputation, so the orchestration never breaks.
    """

    name = "mcp-virustotal"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("VIRUSTOTAL_API_KEY is required to use the real adapter")
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
            return self._error_observation(f"virus_total_{reason}")
        except httpx.RequestError:
            return self._error_observation("virus_total_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        endpoints = {
            IocType.MD5: "files/",
            IocType.SHA1: "files/",
            IocType.SHA256: "files/",
            IocType.IPV4: "ip_addresses/",
            IocType.IPV6: "ip_addresses/",
            IocType.DOMAIN: "domains/",
        }
        if ioc.type in endpoints:
            response = await self._client.get(
                f"{endpoints[ioc.type]}{ioc.normalized.lower()}",
                headers={"x-apikey": self._api_key},
            )
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            return self._observation(attributes, ioc, endpoint="v3")

        if ioc.type == IocType.URL:
            response = await self._client.get(
                f"urls/{self._url_id(ioc.normalized)}",
                headers={"x-apikey": self._api_key},
            )
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            return self._observation(attributes, ioc, endpoint="v3")

        return self._error_observation("virus_total_unsupported_ioc")

    @staticmethod
    def _url_id(url: str) -> str:
        import hashlib

        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def _observation(
        self,
        attributes: dict,
        ioc: ParsedIoc,
        *,
        endpoint: str,
    ) -> McpObservation:
        score, verdict = self._reputation(attributes)
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "endpoint": endpoint,
                "mock": False,
            },
            reputation={"score": score, "verdict": verdict, "tags": self._tags(attributes)},
            geolocation=self._geolocation(attributes),
            relationships=self._relationships(attributes),
            community_reports=self._community_reports(attributes),
        )

    def _reputation(self, attributes: dict) -> tuple[int, str]:
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        score = min(100, malicious * 15 + suspicious * 8)
        if malicious:
            verdict = "malicious"
        elif suspicious:
            verdict = "suspicious"
        elif sum(stats.values()):
            verdict = "clean"
        else:
            verdict = "unknown"
        return score, verdict

    def _tags(self, attributes: dict) -> list[str]:
        results = attributes.get("last_analysis_results") or {}
        return [
            f"vt:{category}:{engine}"
            for engine, result in results.items()
            for category in ("malicious", "suspicious")
            if result.get("category") == category
        ][:15]

    def _geolocation(self, attributes: dict) -> dict[str, Any] | None:
        geo = {}
        for key in ("country", "asn", "network", "regional_internet_registry"):
            if attributes.get(key):
                geo[key] = str(attributes[key])
        if not geo:
            return None
        return {**geo, "provider": self.name}

    def _relationships(self, attributes: dict) -> list[dict[str, str]]:
        for resolution in (attributes.get("resolutions") or [])[:5]:
            ip = resolution.get("ip_address")
            if ip:
                return [{"kind": "resolves_to", "target": str(ip)}]
        return []

    def _community_reports(self, attributes: dict) -> list[dict[str, str]]:
        reports = []
        for engine, result in (attributes.get("last_analysis_results") or {}).items():
            if result.get("category") not in {"malicious", "suspicious"}:
                continue
            reports.append(
                {
                    "title": f"{engine} verdict",
                    "confidence": "high",
                    "summary": f"{engine} reported this IOC as {result['category']}.",
                }
            )
            if len(reports) >= 3:
                break
        return reports

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
