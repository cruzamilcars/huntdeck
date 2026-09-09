"""GoPlus adapter — token & wallet security flags.

Keyless detection of honeypots, blacklisted deployers, gas traps and
privilege abuse on EVM chains. Queries both `token_security` and
`address_security` for an ETH address and merges the risk signals.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.gopluslabs.io/api/v1"


class GoplusMcpClient:
    """Real GoPlus adapter (EVM token/wallet security)."""

    name = "mcp-goplus"

    def __init__(
        self,
        chain_id: str = "1",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._chain_id = chain_id
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.ETHEREUM_ADDRESS:
            return self._error_observation("goplus_unsupported_ioc")
        try:
            security = await self._fetch(
                f"/token_security/{self._chain_id}",
                {"contract_addresses": ioc.normalized},
            )
            address = await self._fetch(
                f"/address_security/{self._chain_id}",
                {"addresses": ioc.normalized},
            )
            return self._observation(ioc, security, address)
        except httpx.HTTPStatusError as exc:
            reason = {
                "404": "not_found",
                "403": "blocked",
                "429": "rate_limited",
            }.get(str(exc.response.status_code), f"http_{exc.response.status_code}")
            return self._error_observation(f"goplus_{reason}")
        except (httpx.RequestError, ValueError):
            return self._error_observation("goplus_unreachable")

    async def _fetch(self, path: str, params: dict[str, str]) -> dict:
        response = await self._client.get(path, params=params)
        response.raise_for_status()
        payload = response.json()
        result = payload.get("result") or {}
        return _entry(result)

    def _observation(self, ioc: ParsedIoc, security: dict, address: dict) -> McpObservation:
        flags: list[tuple[str, int, str]] = [
            ("is_honeypot", 92, "honeypot"),
            ("cannot_sell_all", 88, "sell-blocked"),
            ("cannot_buy", 80, "buy-blocked"),
            ("is_blacklisted", 85, "blacklisted"),
            ("can_take_back_ownership", 65, "ownership-withdrawable"),
            ("is_owner_change_balance", 55, "balance-tamperable"),
        ]
        score = 0
        hit_flags: list[str] = []
        for field, weight, label in flags:
            if str(security.get(field) or "") == "1":
                score = max(score, weight)
                hit_flags.append(f"goplus:{label}")

        buy_tax = int(security.get("buy_tax") or 0)
        sell_tax = int(security.get("sell_tax") or 0)
        if buy_tax >= 10 or sell_tax >= 10:
            score = max(score, 45)
            hit_flags.append(f"goplus:high-tax({buy_tax}/{sell_tax})")
        if str(security.get("is_mintable") or "") == "1":
            score = max(score, 40)
            hit_flags.append("goplus:mintable")
        if str(security.get("creator_in_top_holders") or "") == "1":
            score = max(score, 30)
            hit_flags.append("goplus:creator-in-top-holders")

        dexs = security.get("dex") or []
        liquidity = float(dexs[0].get("liquidity") or 0) if dexs else 0.0
        if liquidity and liquidity < 1000:
            score = max(score, 40)
            hit_flags.append("goplus:thin-liquidity")

        if score == 0:
            verdict = "clean"
            tags = ["goplus:no-risk-flags"]
        elif score >= 70:
            verdict = "malicious"
            tags = ["goplus:high-risk"] + hit_flags
        else:
            verdict = "suspicious"
            tags = ["goplus:flagged"] + hit_flags

        risk_lines = address.get("risk_lines") or []
        if isinstance(risk_lines, list) and risk_lines:
            score = max(score, 50)
            tags.append("goplus:address-risk")
            hit_flags.extend("goplus:address-risk")
        elif str(address.get("is_contract") or "0") == "1":
            tags.append("goplus:is-contract")

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "token_security": _compact(security),
                "address_security": _compact(address),
            },
            reputation={"score": score, "verdict": verdict, "tags": sorted(set(tags))},
            community_reports=(
                [
                    {
                        "title": "GoPlus token security alarm",
                        "confidence": "high",
                        "summary": (
                            f"Detected: {', '.join(dict.fromkeys(hit_flags))}."
                            " Interacting with this token may be unsafe."
                        ),
                    }
                ]
                if score
                else []
            ),
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})


def _entry(result: dict) -> dict:
    for value in result.values():
        if isinstance(value, dict):
            return value
    return {}


def _compact(data: dict) -> dict:
    keys = (
        "is_contract",
        "is_honeypot",
        "is_blacklisted",
        "is_mintable",
        "buy_tax",
        "sell_tax",
        "cannot_buy",
        "cannot_sell_all",
        "can_take_back_ownership",
        "creator_in_top_holders",
        "top_10_holder_rate",
        "holder_count",
        "dex",
        "tags",
        "risk_lines",
        "danger_address",
    )
    return {key: data.get(key) for key in keys if data.get(key) is not None}
