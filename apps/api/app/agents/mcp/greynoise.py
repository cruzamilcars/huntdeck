"""GreyNoise adapter (internet background-noise intelligence).

Real adapter implementing the McpClient contract for IPv4 via the GreyNoise
Community API. Distinguishes internet-wide scanners classified as benign
(RIOT: known business services like Cloudflare or Google) from malicious
noise, which raw reputation feeds often conflate. The key is sent in the
``key`` header and never logged.
"""

from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.greynoise.io"


class GreynoiseMcpClient:
    """Real GreyNoise Community adapter (IPv4 only)."""

    name = "mcp-greynoise"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("GREYNOISE_API_KEY is required to use the real adapter")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=10.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"403": "forbidden", "429": "rate_limited"}.get(str(status), f"http_{status}")
            return self._error_observation(f"greynoise_{reason}")
        except httpx.RequestError:
            return self._error_observation("greynoise_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.IPV4:
            return self._error_observation("greynoise_unsupported_ioc")

        response = await self._client.get(
            f"/v3/community/{ioc.normalized}",
            headers={"key": self._api_key, "Accept": "application/json"},
        )
        if response.status_code == 404:
            return self._observation(None, ioc)
        response.raise_for_status()
        return self._observation(response.json(), ioc)

    def _observation(self, data: dict[str, Any] | None, ioc: ParsedIoc) -> McpObservation:
        if not data:
            return McpObservation(
                source=self.name,
                raw={
                    "entity": ioc.normalized,
                    "entity_type": ioc.type,
                    "mock": False,
                    "observed": False,
                },
                reputation={"score": 0, "verdict": "clean", "tags": ["greynoise:not-observed"]},
            )

        name = str(data.get("name") or "").strip()
        is_noise = bool(data.get("noise"))
        is_riot = bool(data.get("riot"))
        classification = str(data.get("classification") or "unknown")

        score, verdict, tags = self._classify(classification, is_noise, is_riot, name)
        observation = McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "observed": True,
                "name": name or None,
                "noise": is_noise,
                "riot": is_riot,
                "classification": classification,
                "last_seen": data.get("last_seen"),
                "message": data.get("message"),
            },
            reputation={"score": score, "verdict": verdict, "tags": tags},
        )

        if name and (is_noise or is_riot):
            observation.community_reports = [
                {
                    "title": f"GreyNoise: {name}",
                    "confidence": "high" if classification != "unknown" else "medium",
                    "summary": (
                        f"Classified {classification}; "
                        f"{'common internet scanner' if is_noise else 'known benign service'}"
                        f"{', last seen ' + str(data.get('last_seen')) if data.get('last_seen') else ''}."
                    ),
                }
            ]
        if is_riot and name:
            observation.relationships = [{"kind": "known_service", "target": name}]
        return observation

    def _classify(
        self, classification: str, is_noise: bool, is_riot: bool, name: str
    ) -> tuple[int, str, list[str]]:
        tags = []
        if is_riot:
            tags.append("greynoise:riot")
            tags.extend([f"greynoise:{name}"] if name else [])
            return 0, "clean", tags
        if classification == "malicious":
            tags.append("greynoise:malicious-noise")
            tags.extend([f"greynoise:{name}"] if name else [])
            return 85, "malicious", tags
        if is_noise:
            tags.append("greynoise:noisy")
            return 45, "suspicious", tags
        tags.append("greynoise:unknown-classification")
        return 0, "unknown", tags

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
