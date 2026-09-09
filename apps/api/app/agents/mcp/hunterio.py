"""Hunter.io adapter — email deliverability scoring.

Verifies whether an email address is deliverable, risky or disposable using
Hunter's email verifier API. Only meaningful for EMAIL IOCs.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.hunter.io/v2"


class HunterioMcpClient:
    """Real Hunter.io adapter (email verification)."""

    name = "mcp-hunterio"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("HUNTERIO_API_KEY is required to use the real adapter")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=10.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.EMAIL:
            return self._error_observation("hunterio_unsupported_ioc")
        try:
            response = await self._client.get(
                "/email-verifier",
                params={"email": ioc.normalized, "api_key": self._api_key},
            )
            response.raise_for_status()
            data = response.json()
            if "data" not in data:
                return self._error_observation("hunterio_no_data")
            return self._observation(ioc, data["data"])
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"401": "unauthorized", "403": "forbidden", "429": "rate_limited"}.get(
                str(status), f"http_{status}"
            )
            return self._error_observation(f"hunterio_{reason}")
        except httpx.RequestError:
            return self._error_observation("hunterio_unreachable")

    def _observation(self, ioc: ParsedIoc, data: dict) -> McpObservation:
        result = str(data.get("result") or "unknown")
        score = 0
        verdict = "clean"
        if result == "risky":
            score, verdict = 55, "suspicious"
        elif result == "undeliverable":
            score, verdict = 15, "low"
        elif result == "unknown":
            score, verdict = 5, "clean"

        tags = [f"hunterio:{result}"]
        if data.get("disposable"):
            score = min(100, score + 30)
            verdict = "suspicious" if score >= 50 else verdict
            tags.append("hunterio:disposable")
        if data.get("smtp_check") is False:
            score = min(100, score + 15)
            tags.append("hunterio:smtp-check-failed")

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "score": data.get("score"),
                "smtp_check": data.get("smtp_check"),
                "mx_records": data.get("mx_records"),
                "disposable": data.get("disposable"),
            },
            reputation={"score": score, "verdict": verdict, "tags": tags},
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
