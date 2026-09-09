"""Solana public RPC adapter — wallet balance & activity.

Keyless JSON-RPC over the public mainnet-beta endpoint. Balances and
signature counts give a first look at a Solana address with zero
configuration.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.mainnet-beta.solana.com"


class SolanaMcpClient:
    """Real Solana RPC adapter (keyless)."""

    name = "mcp-solana"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.SOLANA_ADDRESS:
            return self._error_observation("solana_unsupported_ioc")
        try:
            balance = await self._rpc("getBalance", [ioc.normalized])
            lamports = (balance.get("result") or {}).get("value") if balance else None
            signatures = await self._rpc("getSignaturesForAddress", [ioc.normalized, {"limit": 1}])
            tx_count = len(signatures.get("result") or []) if signatures else 0
            return self._observation(ioc, lamports, tx_count)
        except httpx.HTTPStatusError as exc:
            reason = {
                "403": "blocked",
                "429": "rate_limited",
            }.get(str(exc.response.status_code), f"http_{exc.response.status_code}")
            return self._error_observation(f"solana_{reason}")
        except (httpx.RequestError, KeyError, TypeError, ValueError):
            return self._error_observation("solana_unreachable")

    async def _rpc(self, method: str, params: list) -> dict:
        response = await self._client.post(
            "",
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        )
        response.raise_for_status()
        return response.json()

    def _observation(self, ioc: ParsedIoc, lamports: int | None, tx_count: int) -> McpObservation:
        if lamports is None:
            return self._error_observation("solana_account_not_found")
        tags = [f"solana:lamports:{lamports}", f"solana:sol:{lamports / 1e9:.6f}"]
        if tx_count:
            tags.append("solana:has-transactions")
        else:
            tags.append("solana:no-transactions")

        reports: list[dict[str, str]] = []
        if tx_count == 0 and lamports > 0:
            reports = [
                {
                    "title": "Solana funded but inactive wallet",
                    "confidence": "medium",
                    "summary": "The address holds SOL but has no confirmed transactions.",
                }
            ]

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "lamports": lamports,
                "signatures_scan_limit": tx_count,
            },
            reputation={
                "score": 20 if (tx_count == 0 and lamports > 0) else 0,
                "verdict": "low" if (tx_count == 0 and lamports > 0) else "clean",
                "tags": tags,
            },
            community_reports=reports,
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
