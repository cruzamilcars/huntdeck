"""ThreatFox adapter — malware family/confidence scoring.

abuse.ch ThreatFox search_ioc requires an API key (the endpoint answers
`Unauthorized` without one), so this adapter is keyed and falls back to the
mock client when no key is configured. Covers DOMAIN, URL and hash IOCs.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatfoxMcpClient:
    """Real ThreatFox adapter (malware threat-intel scoring)."""

    name = "mcp-threatfox"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("THREATFOX_API_KEY is required to use the real adapter")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if not self._supports(ioc.type):
            return self._error_observation("threatfox_unsupported_ioc")
        try:
            response = await self._client.post(
                "",
                json={"query": "search_ioc", "search_term": ioc.normalized},
                headers={"Auth-Key": self._api_key},
            )
            response.raise_for_status()
            data = response.json()
            status = str(data.get("query_status") or "")
            if status.lower() in {"no_result", "unknown"}:
                return self._observation(ioc, [])
            return self._observation(ioc, data.get("data") or [])
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"401": "unauthorized", "403": "forbidden", "429": "rate_limited"}.get(
                str(status), f"http_{status}"
            )
            return self._error_observation(f"threatfox_{reason}")
        except httpx.RequestError:
            return self._error_observation("threatfox_unreachable")

    def _supports(self, ioc_type: str) -> bool:
        return IocType(ioc_type) in {
            IocType.DOMAIN,
            IocType.URL,
            IocType.MD5,
            IocType.SHA1,
            IocType.SHA256,
        }

    def _observation(self, ioc: ParsedIoc, records: list[dict]) -> McpObservation:
        if not records:
            return McpObservation(
                source=self.name,
                raw={"entity": ioc.normalized, "entity_type": ioc.type, "mock": False},
                reputation={"score": 0, "verdict": "clean", "tags": ["threatfox:no_result"]},
            )

        confidence_levels = [int(r.get("confidence_level") or 0) for r in records]
        score = min(100, max(confidence_levels) if confidence_levels else 70)
        verdict = "malicious" if score >= 70 else "suspicious"
        families = sorted({str(r.get("malware_printable") or "unknown") for r in records})[:10]
        first_seen = min((str(r.get("first_seen") or "") for r in records), default="")

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "records": records[:10],
            },
            reputation={
                "score": score,
                "verdict": verdict,
                "tags": [
                    "threatfox:matched",
                    f"threatfox:confidence:{score}",
                    *[f"threatfox:malware:{f}" for f in families],
                ],
            },
            community_reports=[
                {
                    "title": "ThreatFox malware association",
                    "confidence": "high",
                    "summary": (
                        f"This IOC is tied to {len(records)} ThreatFox record(s) — "
                        f"families: {', '.join(families)} — first seen {first_seen}."
                    ),
                }
            ],
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
