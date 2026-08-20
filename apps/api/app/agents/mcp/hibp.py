"""Have I Been Pwned adapter (email breach intelligence).

Real adapter implementing the McpClient contract. The key is sent in the
``hibp-api-key`` header and never logged. Failures become structured
observations with an empty reputation, so the orchestration never breaks.
"""

from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://haveibeenpwned.com/api/v3"

SENSITIVE_CLASSES = {"Passwords", "Password hashes", "Secret questions", "Credit cards"}


class HibpMcpClient:
    """Real Have I Been Pwned adapter (email only)."""

    name = "mcp-hibp"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("HIBP_API_KEY is required to use the real adapter")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=10.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"403": "forbidden", "429": "rate_limited"}.get(str(status), f"http_{status}")
            return self._error_observation(f"hibp_{reason}")
        except httpx.RequestError:
            return self._error_observation("hibp_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.EMAIL:
            return self._error_observation("hibp_unsupported_ioc")

        response = await self._client.get(
            f"breachedaccount/{ioc.normalized}",
            params={"truncateResponse": "false"},
            headers={
                "hibp-api-key": self._api_key,
                "User-Agent": "huntdeck-osint-hub",
                "Accept": "application/json",
            },
        )
        if response.status_code == 404:
            return self._observation([], ioc)
        response.raise_for_status()
        return self._observation(response.json(), ioc)

    def _observation(self, breaches: list[dict[str, Any]], ioc: ParsedIoc) -> McpObservation:
        if not breaches:
            return McpObservation(
                source=self.name,
                raw={
                    "entity": ioc.normalized,
                    "entity_type": ioc.type,
                    "mock": False,
                    "breach_count": 0,
                },
                reputation={"score": 0, "verdict": "clean", "tags": ["hibp:no-breaches"]},
            )

        score = self._score(breaches)
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": breach.get("Name"),
                        "domain": breach.get("Domain"),
                        "breach_date": breach.get("BreachDate"),
                        "pwn_count": breach.get("PwnCount"),
                        "data_classes": breach.get("DataClasses", []),
                    }
                    for breach in breaches
                ],
            },
            reputation={
                "score": score,
                "verdict": "malicious" if score >= 70 else "suspicious",
                "tags": [f"hibp:{breach.get('Name', 'breach')}" for breach in breaches[:8]],
            },
            community_reports=self._community_reports(breaches),
        )

    def _score(self, breaches: list[dict[str, Any]]) -> int:
        sensitive = sum(
            1
            for breach in breaches
            if breach.get("IsSensitive") or set(breach.get("DataClasses") or []) & SENSITIVE_CLASSES
        )
        spam = sum(1 for breach in breaches if breach.get("IsSpamList"))
        return min(100, len(breaches) * 20 + sensitive * 15 + spam * 10)

    def _community_reports(self, breaches: list[dict[str, Any]]) -> list[dict[str, str]]:
        reports = []
        for breach in breaches[:3]:
            classes = ", ".join(breach.get("DataClasses") or []) or "unknown data"
            reports.append(
                {
                    "title": f"Breach: {breach.get('Name', 'unknown')}",
                    "confidence": "high" if breach.get("IsVerified") else "medium",
                    "summary": (
                        f"{breach.get('PwnCount', 0):,} accounts exposed on "
                        f"{breach.get('BreachDate', 'unknown')} ({classes})."
                    ),
                }
            )
        return reports

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
