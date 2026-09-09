"""mempool.space adapter — Bitcoin on-chain activity enrichment.

Keyless Bitcoin explorer wrapping the mempool.space REST API. Successful
chains for an address (funded/spent counts and sums) are enrichment signals;
heavy accumulation with little spending is flagged as a possible holding/scam
wallet pattern.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://mempool.space/api"


class MempoolspaceMcpClient:
    """Real mempool.space adapter (BTC chain explorer)."""

    name = "mcp-mempoolspace"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.BITCOIN_ADDRESS:
            return self._error_observation("mempoolspace_unsupported_ioc")
        try:
            response = await self._client.get(f"/address/{ioc.normalized}")
            response.raise_for_status()
            data = response.json()
            return self._observation(ioc, data)
        except httpx.HTTPStatusError as exc:
            reason = {
                "404": "not_found",
                "403": "blocked",
                "429": "rate_limited",
            }.get(str(exc.response.status_code), f"http_{exc.response.status_code}")
            return self._error_observation(f"mempoolspace_{reason}")
        except (httpx.RequestError, ValueError):
            return self._error_observation("mempoolspace_unreachable")

    def _observation(self, ioc: ParsedIoc, data: dict) -> McpObservation:
        chain = data.get("chain_stats") or {}
        received_sats = int(chain.get("funded_txo_sum") or 0)
        spent_sats = int(chain.get("spent_txo_sum") or 0)
        tx_count = int(chain.get("tx_count") or 0)

        score = 0
        verdict = "clean"
        reports: list[dict[str, str]] = []
        if received_sats > 0 and spent_sats == 0:
            score, verdict = 35, "low"
        elif received_sats > 0 and tx_count > 0 and spent_sats / received_sats < 0.1:
            score, verdict = 25, "low"

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "tx_count": tx_count,
                "received_sats": received_sats,
                "spent_sats": spent_sats,
                "confirmed_utxos": chain.get("funded_txo_count"),
                "mempool_pending": (data.get("mempool_stats") or {}),
            },
            reputation={
                "score": score,
                "verdict": verdict,
                "tags": [
                    f"mempoolspace:tx_count:{tx_count}",
                    f"mempoolspace:received_btc:{received_sats / 1e8:.6f}",
                    f"mempoolspace:spent_btc:{spent_sats / 1e8:.6f}",
                ],
            },
            community_reports=reports
            if verdict == "clean"
            else [
                {
                    "title": "Bitcoin accumulation wallet pattern",
                    "confidence": "low",
                    "summary": (
                        f"This address received {received_sats / 1e8:.4f} BTC "
                        f"across {tx_count} transactions and has spent almost nothing — "
                        "consistent with a holding wallet or fund accumulator."
                    ),
                }
            ],
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
