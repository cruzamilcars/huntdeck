"""URLhaus adapter (abuse.ch malware URL/host database).

Real adapter implementing the McpClient contract for URLs, domains and
file hashes via the URLhaus API. Free key at https://auth.abuse.ch/.
The key travels only in the Auth-Key header and is never logged.
"""

from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://urlhaus-api.abuse.ch"

SUPPORTED_TYPES = {
    IocType.URL,
    IocType.DOMAIN,
    IocType.MD5,
    IocType.SHA1,
    IocType.SHA256,
}


class UrlHausMcpClient:
    """Real URLhaus adapter for URL/domain/hash lookups."""

    name = "mcp-urlhaus"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("URLHAUS_API_KEY is required to use the real adapter")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=10.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"401": "unauthorized", "403": "forbidden", "429": "rate_limited"}.get(
                str(status), f"http_{status}"
            )
            return self._error_observation(f"urlhaus_{reason}")
        except httpx.RequestError:
            return self._error_observation("urlhaus_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type not in SUPPORTED_TYPES:
            return self._error_observation("urlhaus_unsupported_ioc")

        headers = {"Auth-Key": self._api_key, "Accept": "application/json"}

        if ioc.type == IocType.URL:
            response = await self._client.post(
                "/v1/url/", data={"url": ioc.normalized}, headers=headers
            )
        elif ioc.type == IocType.DOMAIN:
            response = await self._client.post(
                "/v1/host/", data={"host": ioc.normalized}, headers=headers
            )
        else:
            # hash payload lookup - try sha256 first, fallback to md5
            field = "sha256_hash" if ioc.type == IocType.SHA256 else "md5_hash"
            # SHA1 not directly supported - search via md5 field will return not found gracefully
            if ioc.type == IocType.SHA1:
                field = "md5_hash"
            response = await self._client.post(
                "/v1/payload/", data={field: ioc.normalized}, headers=headers
            )

        response.raise_for_status()
        return self._observation(response.json(), ioc)

    def _observation(self, data: dict[str, Any], ioc: ParsedIoc) -> McpObservation:
        status = str(data.get("query_status") or "")

        if status == "no_results":
            return McpObservation(
                source=self.name,
                raw={
                    "entity": ioc.normalized,
                    "entity_type": ioc.type,
                    "mock": False,
                    "query_status": status,
                },
                reputation={"score": 0, "verdict": "clean", "tags": ["urlhaus:not-listed"]},
            )

        if status in {"invalid_url", "invalid_host", "invalid_md5_hash", "invalid_sha256_hash"}:
            return McpObservation(
                source=self.name,
                raw={
                    "entity": ioc.normalized,
                    "entity_type": ioc.type,
                    "mock": False,
                    "query_status": status,
                },
                reputation={"score": 0, "verdict": "unknown", "tags": [f"urlhaus:{status}"]},
            )

        if status == "ok":
            return self._ok_observation(data, ioc)

        # Unknown status - treat as unknown
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "query_status": status,
            },
            reputation={"score": 0, "verdict": "unknown", "tags": ["urlhaus:unknown"]},
        )

    def _ok_observation(self, data: dict[str, Any], ioc: ParsedIoc) -> McpObservation:
        threat = str(data.get("threat") or data.get("signature") or "malware").lower()
        tags_raw = data.get("tags") or []
        if isinstance(tags_raw, str):
            tags_raw = [tags_raw]

        score = 85 if "malware" in threat or data.get("payloads") or data.get("urls") else 75

        tag_list = ["urlhaus:listed", f"urlhaus:{threat.replace(' ', '-')}"]
        tag_list.extend(f"urlhaus:{t.lower().replace(' ', '-')}" for t in tags_raw[:4])

        raw: dict[str, Any] = {
            "entity": ioc.normalized,
            "entity_type": ioc.type,
            "mock": False,
            "query_status": "ok",
            "threat": threat,
            "tags": tags_raw,
        }
        if data.get("urlhaus_reference"):
            raw["reference"] = data["urlhaus_reference"]
        if data.get("signature"):
            raw["signature"] = data["signature"]

        observation = McpObservation(
            source=self.name,
            raw=raw,
            reputation={"score": score, "verdict": "malicious", "tags": tag_list[:8]},
        )

        # Community reports from payloads or urls
        payloads = data.get("payloads") or []
        urls = data.get("urls") or []
        reports = []
        for item in payloads[:2] if payloads else urls[:2]:
            if isinstance(item, dict):
                url_val = item.get("url") or item.get("signature") or str(item)
                t = item.get("threat") or threat
                reports.append(
                    {
                        "title": f"URLhaus: {t}",
                        "confidence": "high",
                        "summary": f"Listed as {t} — {url_val[:120]}",
                    }
                )
        if not reports:
            reports.append(
                {
                    "title": f"URLhaus: {threat}",
                    "confidence": "high",
                    "summary": f"Indicator listed in URLhaus as {threat} (ref: {data.get('urlhaus_reference', 'n/a')})",
                }
            )
        observation.community_reports = reports

        # Relationships for host payloads
        if urls and ioc.type == IocType.DOMAIN:
            observation.relationships = [
                {"kind": "hosts_malware", "target": str(u.get("url", ""))[:120]}
                for u in urls[:3]
                if u.get("url")
            ]

        return observation

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
