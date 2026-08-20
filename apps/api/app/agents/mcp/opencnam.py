"""OpenCNAM adapter (phone carrier lookup).

Real adapter implementing the McpClient contract. The key is sent as a
Bearer token in the ``Authorization`` header (never in the URL, never
logged). Failures become structured observations with an empty reputation.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.opencnam.com/v3"


class OpenCnamMcpClient:
    """Real OpenCNAM adapter (phone numbers, E.164)."""

    name = "mcp-opencnam"

    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("OPENCNAM_API_KEY is required to use the real adapter")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=10.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"403": "forbidden", "422": "invalid_number", "429": "rate_limited"}.get(
                str(status), f"http_{status}"
            )
            return self._error_observation(f"opencnam_{reason}")
        except httpx.RequestError:
            return self._error_observation("opencnam_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.PHONE:
            return self._error_observation("opencnam_unsupported_ioc")

        response = await self._client.get(
            f"phone/{ioc.normalized}",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
            },
        )
        response.raise_for_status()
        return self._observation(response.json(), ioc)

    def _observation(self, data: dict, ioc: ParsedIoc) -> McpObservation:
        name = data.get("name")
        if not name:
            return McpObservation(
                source=self.name,
                raw={"entity": ioc.normalized, "entity_type": ioc.type, "mock": False},
                reputation={"score": 0, "verdict": "unknown", "tags": ["opencnam:no-owner"]},
            )

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "cnam_name": str(name),
                "carrier": data.get("carrier"),
                "number_type": data.get("type"),
            },
            reputation={
                "score": 0,
                "verdict": "clean",
                "tags": ["opencnam:attributed", f"opencnam:type:{data.get('type', 'unknown')}"],
            },
            relationships=self._relationships(data),
        )

    def _relationships(self, data: dict) -> list[dict[str, str]]:
        relationships = []
        carrier = data.get("carrier")
        if carrier:
            relationships.append({"kind": "served_by", "target": str(carrier)})
        if data.get("type"):
            relationships.append({"kind": "number_type", "target": str(data["type"])})
        return relationships

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
