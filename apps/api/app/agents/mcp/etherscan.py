"""Etherscan (v2) adapter — Ethereum balance & transaction enrichment.

Keyed adapter hitting api.etherscan.io/v2. Etherscan is the canonical
explorer for wallet balances and transaction payloads; combined with the
keyless Blockscout adapter it provides source redundancy on-chain.
"""

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://api.etherscan.io/v2/api"


class EtherscanMcpClient:
    """Real Etherscan v2 adapter (ETH balance/tx)."""

    name = "mcp-etherscan"

    def __init__(
        self,
        api_key: str,
        chain_id: str = "1",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY is required to use the real adapter")
        self._chain_id = chain_id
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            match IocType(ioc.type):
                case IocType.ETHEREUM_ADDRESS:
                    return await self._address(ioc)
                case IocType.TX_HASH:
                    return await self._transaction(ioc)
                case _:
                    return self._error_observation("etherscan_unsupported_ioc")
        except httpx.HTTPStatusError as exc:
            reason = {
                "401": "unauthorized",
                "403": "forbidden",
                "429": "rate_limited",
            }.get(str(exc.response.status_code), f"http_{exc.response.status_code}")
            return self._error_observation(f"etherscan_{reason}")
        except (httpx.RequestError, ValueError):
            return self._error_observation("etherscan_unreachable")

    async def _call(self, params: dict[str, str]) -> dict:
        response = await self._client.get(
            "",
            params={**params, "chainid": self._chain_id, "apikey": self._api_key},
        )
        response.raise_for_status()
        return response.json()

    def _balance_wei(self, result: str) -> float:
        try:
            return float(int(str(result), 16))
        except ValueError:
            return 0.0

    async def _address(self, ioc: ParsedIoc) -> McpObservation:
        balance = await self._call(
            {"module": "account", "action": "balance", "address": ioc.normalized, "tag": "latest"}
        )
        latest = await self._call(
            {
                "module": "account",
                "action": "txlist",
                "address": ioc.normalized,
                "startblock": "0",
                "endblock": "99999999",
                "page": "1",
                "offset": "1",
                "sort": "desc",
            }
        )
        latest_txs = latest.get("result") if isinstance(latest.get("result"), list) else []
        has_txs = bool(latest_txs)

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "balance_wei": balance.get("result"),
                "latest_tx_hash": latest_txs[0].get("hash") if has_txs else None,
            },
            reputation={
                "score": 0,
                "verdict": "clean",
                "tags": [
                    f"etherscan:balance_wei:{balance.get('result')}",
                    "etherscan:has-transactions" if has_txs else "etherscan:no-transactions",
                ],
            },
        )

    async def _transaction(self, ioc: ParsedIoc) -> McpObservation:
        response = await self._call(
            {
                "module": "proxy",
                "action": "eth_getTransactionByHash",
                "txhash": ioc.normalized,
            }
        )
        tx = response.get("result") if isinstance(response.get("result"), dict) else None
        if tx is None:
            return McpObservation(
                source=self.name,
                raw={
                    "entity": ioc.normalized,
                    "entity_type": ioc.type,
                    "mock": False,
                    "found": False,
                },
                reputation={"score": 0, "verdict": "clean", "tags": ["etherscan:tx-not-found"]},
            )

        relationships = []
        for field, kind in (("from", "sent_from"), ("to", "received_by")):
            address = tx.get(field)
            if address:
                relationships.append({"kind": kind, "target": str(address)})

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "found": True,
                "from": tx.get("from"),
                "to": tx.get("to"),
                "value_wei": tx.get("value"),
                "block_number": tx.get("blockNumber"),
                "gas_used": tx.get("gas"),
                "transaction_index": tx.get("transactionIndex"),
            },
            reputation={
                "score": 0,
                "verdict": "clean",
                "tags": ["etherscan:transaction", "etherscan:confirmed"],
            },
            relationships=relationships,
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
