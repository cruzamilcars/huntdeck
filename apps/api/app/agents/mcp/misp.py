"""MISP adapter (internal threat intelligence sharing platform).

Real adapter implementing the McpClient contract. Queries your MISP
instance's ``/attributes/restSearch`` endpoint for indicators matching the
IOC and surfaces the events that reported them. Requires both ``MISP_URL``
and ``MISP_API_KEY``; the key is sent only in the Authorization header.
Failures become structured observations with an empty reputation.

Threat levels follow MISP semantics: 1 (high) → 2 (medium) → 3 (low) →
4 (undefined).
"""

from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

THREAT_LEVEL_SCORE = {1: 85, 2: 60, 3: 40, 4: 30}
SUPPORTED_TYPES = {
    IocType.IPV4,
    IocType.IPV6,
    IocType.DOMAIN,
    IocType.URL,
    IocType.MD5,
    IocType.SHA1,
    IocType.SHA256,
    IocType.EMAIL,
}


class MispMcpClient:
    """Real MISP adapter for org-internal indicator lookups."""

    name = "mcp-misp"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        verify_ssl: bool = True,
    ) -> None:
        if not base_url or not api_key:
            raise ValueError("MISP_URL and MISP_API_KEY are required")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(
            timeout=10.0,
            base_url=base_url.rstrip("/"),
            verify=verify_ssl,
        )

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"401": "unauthorized", "403": "forbidden", "404": "endpoint_not_found"}.get(
                str(status), f"http_{status}"
            )
            return self._error_observation(f"misp_{reason}")
        except httpx.RequestError:
            return self._error_observation("misp_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type not in SUPPORTED_TYPES:
            return self._error_observation("misp_unsupported_ioc")

        response = await self._client.post(
            "/attributes/restSearch/json",
            json={
                "value": ioc.normalized,
                "returnFormat": "json",
                "limit": 20,
            },
            headers={
                "Authorization": self._api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        payload = response.json()
        attributes = self._extract_attributes(payload)
        return self._observation(attributes, ioc)

    def _extract_attributes(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        response_block = payload.get("response") or payload
        attributes = response_block.get("Attribute") or []
        return attributes if isinstance(attributes, list) else []

    def _observation(self, attributes: list[dict[str, Any]], ioc: ParsedIoc) -> McpObservation:
        if not attributes:
            return McpObservation(
                source=self.name,
                raw={
                    "entity": ioc.normalized,
                    "entity_type": ioc.type,
                    "mock": False,
                    "attribute_count": 0,
                },
                reputation={"score": 0, "verdict": "clean", "tags": ["misp:no-reports"]},
            )

        scored: list[tuple[int, dict[str, Any]]] = []
        for attribute in attributes:
            event = attribute.get("Event") or {}
            try:
                level = int(event.get("threat_level_id") or 4)
            except (TypeError, ValueError):
                level = 4
            scored.append((THREAT_LEVEL_SCORE.get(level, 30), attribute))

        best_score = max(score for score, _ in scored)
        observation = McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "attribute_count": len(attributes),
                "attributes": [
                    {
                        "event_id": attr.get("event_id"),
                        "category": attr.get("category"),
                        "type": attr.get("type"),
                        "comment": attr.get("comment"),
                        "event_info": (attr.get("Event") or {}).get("info"),
                    }
                    for _, attr in sorted(scored, key=lambda pair: -pair[0])[:5]
                ],
            },
            reputation={
                "score": best_score,
                "verdict": "malicious" if best_score >= 60 else "suspicious",
                "tags": self._tags(scored),
            },
            community_reports=self._reports(scored),
        )
        seen_events: set[str] = set()
        relationships: list[dict[str, str]] = []
        for score, attr in sorted(scored, key=lambda pair: -pair[0]):
            event_id = str(attr.get("event_id") or "")
            if not event_id or event_id in seen_events:
                continue
            seen_events.add(event_id)
            info = str((attr.get("Event") or {}).get("info") or "").strip()
            target = f"MISP event #{event_id}" + (f": {info[:60]}" if info else "")
            relationships.append({"kind": "reported_in", "target": target})
        observation.relationships = relationships
        return observation

    def _tags(self, scored: list[tuple[int, dict[str, Any]]]) -> list[str]:
        tags: list[str] = ["misp:sighted"]
        categories = {
            str(attr.get("category") or "uncategorized")
            for _, attr in sorted(scored, key=lambda pair: -pair[0])[:5]
        }
        tags.extend(f"misp:{category.lower().replace(' ', '-')}" for category in sorted(categories))
        return tags[:8]

    def _reports(self, scored: list[tuple[int, dict[str, Any]]]) -> list[dict[str, str]]:
        reports = []
        for _, attr in sorted(scored, key=lambda pair: -pair[0])[:3]:
            event = attr.get("Event") or {}
            info = str(event.get("info") or f"event #{attr.get('event_id')}")
            comment = str(attr.get("comment") or "").strip()
            summary = (
                f"{attr.get('type', 'indicator')} in '{info}'"
                + (f" ({event.get('date')})" if event.get("date") else "")
                + (f" — {comment[:120]}" if comment else "")
            )
            reports.append(
                {"title": f"MISP sighting: {info[:70]}", "confidence": "medium", "summary": summary}
            )
        return reports

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
