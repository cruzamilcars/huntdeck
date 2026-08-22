"""AlienVault OTX adapter (open threat intelligence pulses).

Real adapter implementing the McpClient contract for IPv4/IPv6, domains,
URLs and file hashes via the OTX ``general`` indicator endpoint. The key is
sent in the ``X-OTX-API-KEY`` header and never logged. Failures become
structured observations with an empty reputation.
"""

from typing import Any
from urllib.parse import quote

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://otx.alienvault.com"


class OtxMcpClient:
    """Real AlienVault OTX adapter (IP/domain/URL/hash pulse intelligence)."""

    name = "mcp-otx"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("OTX_API_KEY is required to use the real adapter")
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
            return self._error_observation(f"otx_{reason}")
        except httpx.RequestError:
            return self._error_observation("otx_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        indicator_type = self._indicator_type(ioc.type)
        if not indicator_type:
            return self._error_observation("otx_unsupported_ioc")

        value = ioc.normalized
        if ioc.type == IocType.URL:
            value = quote(value, safe="")
        response = await self._client.get(
            f"/api/v1/indicators/{indicator_type}/{value}/general",
            headers={"X-OTX-API-KEY": self._api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        return self._observation(response.json(), ioc)

    def _indicator_type(self, ioc_type: str) -> str | None:
        mapping = {
            IocType.IPV4: "IPv4",
            IocType.IPV6: "IPv6",
            IocType.DOMAIN: "domain",
            IocType.URL: "url",
            IocType.MD5: "file",
            IocType.SHA1: "file",
            IocType.SHA256: "file",
        }
        return mapping.get(IocType(ioc_type))

    def _observation(self, data: dict[str, Any], ioc: ParsedIoc) -> McpObservation:
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        count = int(pulse_info.get("count") or len(pulses))
        has_reputation = bool(data.get("reputation"))

        score = min(100, count * 10 + (15 if has_reputation else 0))
        observation = McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "pulse_count": count,
                "has_reputation": has_reputation,
                "pulses": [
                    {
                        "name": pulse.get("name"),
                        "tags": pulse.get("tags", []),
                    }
                    for pulse in pulses[:5]
                ],
            },
            reputation={
                "score": score,
                "verdict": self._verdict(count),
                "tags": self._pulse_tags(pulses),
            },
            community_reports=self._pulse_reports(pulses),
        )
        country = data.get("country_name")
        asn = data.get("asn")
        if country or asn:
            geolocation: dict[str, str] = {"provider": self.name}
            if country:
                geolocation["country"] = str(country)
            if asn:
                geolocation["asn"] = str(asn)
            observation.geolocation = geolocation
        return observation

    def _verdict(self, count: int) -> str:
        if count >= 5:
            return "malicious"
        if count >= 1:
            return "suspicious"
        return "clean"

    def _pulse_tags(self, pulses: list[dict[str, Any]]) -> list[str]:
        tags: list[str] = []
        for pulse in pulses[:8]:
            tags.append(f"otx:pulse:{pulse.get('name', 'unnamed')}")
        return tags[:8]

    def _pulse_reports(self, pulses: list[dict[str, Any]]) -> list[dict[str, str]]:
        reports = []
        for pulse in pulses[:3]:
            summary = str(pulse.get("description") or "").strip()
            if len(summary) > 220:
                summary = f"{summary[:217]}..."
            reports.append(
                {
                    "title": f"OTX pulse: {pulse.get('name', 'unnamed')}",
                    "confidence": "high" if summary else "medium",
                    "summary": summary
                    or f"Pulse tags: {', '.join(pulse.get('tags') or []) or 'none'}",
                }
            )
        return reports

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
