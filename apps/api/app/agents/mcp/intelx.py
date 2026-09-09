"""IntelX (intelx.io) adapter — leaked-data exposure scoring.

Searches the IntelX compromised-data corpus for emails, phone numbers and
domains. The free tier exposes search hits (status + search id); the result
payload is fetched when possible. All failures become structured
observations with an empty reputation — the hub is never blocked by one
provider being down.
"""

from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://2.intelx.io"


class IntelxMcpClient:
    """Real IntelX adapter (email/phone/domain leak exposure)."""

    name = "mcp-intelx"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("INTELX_API_KEY is required to use the real adapter")
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
            return self._error_observation(f"intelx_{reason}")
        except httpx.RequestError:
            return self._error_observation("intelx_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        intel_type = self._intel_type(ioc.type)
        if not intel_type:
            return self._error_observation("intelx_unsupported_ioc")

        headers = {"x-key": self._api_key, "Content-Type": "application/json"}
        response = await self._client.post(
            f"/{intel_type}/search",
            headers=headers,
            json={"term": ioc.normalized},
        )
        response.raise_for_status()
        data = response.json()
        return await self._observation(data, ioc, intel_type, headers)

    def _intel_type(self, ioc_type: str) -> str | None:
        mapping = {
            IocType.EMAIL: "email",
            IocType.PHONE: "phone",
            IocType.DOMAIN: "domain",
        }
        return mapping.get(IocType(ioc_type))

    async def _observation(
        self, data: dict[str, Any], ioc: ParsedIoc, intel_type: str, headers: dict[str, str]
    ) -> McpObservation:
        no_results = data.get("status") == 1
        search_id = data.get("id")
        results: list[dict[str, Any]] = []
        if search_id and not no_results:
            results = await self._fetch_results(search_id, headers)

        score = 0
        verdict = "clean"
        tags = ["intelx:no-leak-found"]
        reports: list[dict[str, str]] = []
        if no_results is False and (results or search_id):
            found_count = len(results)
            score = min(100, 30 + found_count * 5)
            verdict = "suspicious" if score >= 45 else "low"
            tags = [f"intelx:leak-found:{intel_type}", f"intelx:records:{found_count}"]
            reports = [
                {
                    "title": "Data breach exposure detected",
                    "confidence": "medium",
                    "summary": (
                        f"IntelX found {found_count} exposed record(s) for this "
                        f"{intel_type} in the compromised-data corpus."
                    ),
                }
            ]

        observation = McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "search_id": search_id,
                "records_found": len(results),
                "samples": [r.get("name") for r in results[:5]],
            },
            reputation={"score": score, "verdict": verdict, "tags": tags},
            community_reports=reports,
        )

        if intel_type == "phone" and data.get("operator"):
            geolocation: dict[str, str] = {"provider": self.name}
            if data.get("operator"):
                geolocation["carrier"] = str(data["operator"])
            if data.get("country"):
                geolocation["country"] = str(data["country"])
            observation.geolocation = geolocation
        if intel_type == "phone" and str(data.get("spam", "no")).lower() == "yes":
            observation.reputation = {
                "score": 60,
                "verdict": "suspicious",
                "tags": ["intelx:spam-flagged"],
            }
        return observation

    async def _fetch_results(self, search_id: int, headers: dict[str, str]) -> list[dict[str, Any]]:
        try:
            response = await self._client.post(
                "/intelligent/search",
                headers=headers,
                json={"id": search_id, "limit": 10, "sort": 2},
            )
            response.raise_for_status()
            return (response.json() or {}).get("results") or []
        except (httpx.HTTPStatusError, httpx.RequestError):
            return []

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
