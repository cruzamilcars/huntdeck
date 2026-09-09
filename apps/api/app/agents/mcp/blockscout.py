"""Blockscout adapter — Ethereum on-chain activity & scam signals.

Keyless Ethereum explorer covering wallet addresses, transactions and ENS
names. The `is_scam` flag and the reputation field are first-class risk
signals; ENS names resolve to their controlling address via the search API.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://eth.blockscout.com/api/v2"


class BlockscoutMcpClient:
    """Real Blockscout adapter (ETH chain explorer)."""

    name = "mcp-blockscout"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            reason = {
                "404": "not_found",
                "403": "blocked",
                "429": "rate_limited",
            }.get(str(exc.response.status_code), f"http_{exc.response.status_code}")
            return self._error_observation(f"blockscout_{reason}")
        except (httpx.RequestError, ValueError):
            return self._error_observation("blockscout_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        match IocType(ioc.type):
            case IocType.ETHEREUM_ADDRESS:
                return await self._address(ioc)
            case IocType.TX_HASH:
                return await self._transaction(ioc)
            case IocType.ENS_NAME:
                return await self._ens(ioc)
            case _:
                return self._error_observation("blockscout_unsupported_ioc")

    async def _address(self, ioc: ParsedIoc) -> McpObservation:
        response = await self._client.get(f"/addresses/{ioc.normalized}")
        response.raise_for_status()
        data = response.json()

        score, verdict = 0, "clean"
        tags: list[str] = []
        if str(data.get("is_scam", "false")).lower() == "true":
            score, verdict, tags = 90, "malicious", ["blockscout:flagged-scam"]
        elif str(data.get("reputation") or "ok") == "suspicious":
            score, verdict = 60, "suspicious"
        if str(data.get("is_contract", "false")).lower() == "true":
            tags.append("blockscout:is-contract")
        if str(data.get("is_verified", "false")).lower() == "true":
            tags.append("blockscout:verified")
        tags.append("blockscout:reputation:" + str(data.get("reputation") or "ok"))

        relationships: list[dict[str, str]] = []
        ens_name = data.get("ens_domain_name")
        if ens_name:
            relationships.append({"kind": "has_ens", "target": str(ens_name)})
        creator = data.get("creator_address_hash")
        if creator:
            relationships.append({"kind": "deployed_by", "target": str(creator)})

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "coin_balance_wei": data.get("coin_balance"),
                "is_contract": data.get("is_contract"),
                "is_scam": data.get("is_scam"),
                "reputation": data.get("reputation"),
                "ens_domain_name": ens_name,
                "creation_transaction_hash": data.get("creation_transaction_hash"),
            },
            reputation={"score": score, "verdict": verdict, "tags": tags},
            relationships=relationships,
            community_reports=(
                [
                    {
                        "title": "Blockchain explorer scam flag",
                        "confidence": "high",
                        "summary": "Blockscout flags this address as a known scam on Ethereum mainnet.",
                    }
                ]
                if score >= 90
                else []
            ),
        )

    async def _transaction(self, ioc: ParsedIoc) -> McpObservation:
        response = await self._client.get(f"/transactions/{ioc.normalized}")
        response.raise_for_status()
        data = response.json()

        sender = (data.get("from") or {}).get("hash")
        recipient = (data.get("to") or {}).get("hash")
        relationships = []
        if sender:
            relationships.append({"kind": "sent_from", "target": str(sender)})
        if recipient:
            relationships.append({"kind": "received_by", "target": str(recipient)})

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "status": data.get("status"),
                "method": data.get("method"),
                "value_wei": data.get("value"),
                "block_number": data.get("block_number"),
                "timestamp": data.get("timestamp"),
                "fee_wei": data.get("fee"),
                "from": data.get("from"),
                "to": data.get("to"),
            },
            reputation={
                "score": 0,
                "verdict": "clean",
                "tags": [
                    "blockscout:transaction",
                    "blockscout:status:" + str(data.get("status") or "unknown"),
                ],
            },
            relationships=relationships,
        )

    async def _ens(self, ioc: ParsedIoc) -> McpObservation:
        response = await self._client.get("/search", params={"q": ioc.normalized})
        response.raise_for_status()
        items = response.json().get("items") or []
        ens_item = next((item for item in items if item.get("type") == "ens_domain"), None)
        address = None
        if ens_item:
            address = (
                (ens_item.get("ens_info") or {}).get("address_hash")
                or ens_item.get("address_hash")
                or _address_from_path(ens_item.get("url"))
            )

        if not address:
            return McpObservation(
                source=self.name,
                raw={"entity": ioc.normalized, "entity_type": ioc.type, "mock": False},
                reputation={"score": 0, "verdict": "clean", "tags": ["blockscout:ens-not-found"]},
            )

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "resolved_address": address,
            },
            reputation={"score": 0, "verdict": "clean", "tags": ["blockscout:ens-resolved"]},
            relationships=[{"kind": "resolves_to", "target": str(address)}],
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})


def _address_from_path(url: str | None) -> str | None:
    if not url:
        return None
    segments = [segment for segment in url.split("/") if segment.startswith("0x")]
    return segments[-1] if segments else None
