"""Dexscreener adapter — liquidity & trading signals for tokens.

Keyless listing of active DEX pairs for an ERC-20 token. Thin liquidity,
extreme 24h price moves and micro-valuations are the risk signals that
typical scam tokens share.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.dexscreener.com/latest/dex"


class DexscreenerMcpClient:
    """Real Dexscreener adapter (token liquidity/trading)."""

    name = "mcp-dexscreener"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.ETHEREUM_ADDRESS:
            return self._error_observation("dexscreener_unsupported_ioc")
        try:
            response = await self._client.get(f"/tokens/{ioc.normalized}")
            response.raise_for_status()
            data = response.json()
            return self._observation(ioc, data.get("pairs") or [])
        except httpx.HTTPStatusError as exc:
            reason = {
                "404": "not_found",
                "403": "blocked",
                "429": "rate_limited",
            }.get(str(exc.response.status_code), f"http_{exc.response.status_code}")
            return self._error_observation(f"dexscreener_{reason}")
        except (httpx.RequestError, ValueError):
            return self._error_observation("dexscreener_unreachable")

    def _observation(self, ioc: ParsedIoc, pairs: list[dict]) -> McpObservation:
        if not pairs:
            return McpObservation(
                source=self.name,
                raw={"entity": ioc.normalized, "entity_type": ioc.type, "mock": False},
                reputation={
                    "score": 0,
                    "verdict": "clean",
                    "tags": ["dexscreener:not-listed"],
                },
            )

        def liquidity(pair: dict) -> float:
            return float((pair.get("liquidity") or {}).get("usd") or 0)

        best_pair = max(pairs, key=liquidity)
        best_liquidity = liquidity(best_pair)
        price_change = float((best_pair.get("priceChange") or {}).get("h24") or 0)
        fdv = float(best_pair.get("fdv") or (best_pair.get("marketCap") or 0) or 0)
        txns = (best_pair.get("txns") or {}).get("h24") or {}
        chain = str(best_pair.get("chainId") or "?")

        score = 0
        signals: list[str] = []
        if best_liquidity < 1000:
            score = max(score, 40)
            signals.append("thin-liquidity")
        if abs(price_change) >= 50:
            score = max(score, 35)
            signals.append("extreme-24h-move")
        if best_pair.get("priceUsd") and fdv < 10000:
            score = max(score, 30)
            signals.append("micro-valuation")

        verdict = "suspicious" if score >= 40 else "low" if score else "clean"
        reports: list[dict[str, str]] = []
        if score:
            reports = [
                {
                    "title": "DEX trading risk signals",
                    "confidence": "medium",
                    "summary": (
                        f"Liquidity ${best_liquidity:,.0f}, 24h change {price_change:+.1f}% — "
                        f"{', '.join(signals)}. Review before interacting."
                    ),
                }
            ]

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "chain": chain,
                "best_pair": str(best_pair.get("pairAddress") or best_pair.get("dexId")),
                "liquidity_usd": best_liquidity,
                "price_usd": best_pair.get("priceUsd"),
                "price_change_24h": price_change,
                "fdv": fdv,
                "txns_24h": {"buys": txns.get("buys"), "sells": txns.get("sells")},
                "pair_count": len(pairs),
            },
            reputation={
                "score": score,
                "verdict": verdict,
                "tags": [
                    f"dexscreener:{chain}",
                    f"dexscreener:liq-usd:{best_liquidity:.0f}",
                    *[f"dexscreener:{signal}" for signal in signals],
                ],
            },
            community_reports=reports,
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
