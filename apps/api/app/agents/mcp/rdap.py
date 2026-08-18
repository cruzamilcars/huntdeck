"""Real RDAP/WHOIS adapter (no API key required).

RDAP (RFC 7480-7484) is the modern successor to WHOIS. The bootstrap registry
at rdap.org redirects to the authoritative registry server for each domain/IP,
so this adapter needs zero configuration and works for every TLD and IP range
that publishes RDAP data. Returns registration metadata: registrar, dates,
nameservers, status codes and contact entities (with country when available).
"""

from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BOOTSTRAP_URL = "https://rdap.org"


class RdapMcpClient:
    """RDAP/WHOIS adapter implementing the McpClient contract.

    Always available (no API key). Domain and IP lookups are supported;
    other IOC types return a structured "unsupported" observation. Network
    failures become observations, never exceptions.
    """

    name = "mcp-rdap"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=10.0, base_url=BOOTSTRAP_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"404": "not_found", "429": "rate_limited"}.get(str(status), f"http_{status}")
            return self._error_observation(reason)
        except httpx.RequestError:
            return self._error_observation("rdap_unreachable")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type in {IocType.DOMAIN, IocType.URL}:
            target = (
                ioc.normalized
                if ioc.type == IocType.DOMAIN
                else ioc.normalized.split("://")[1].split("/")[0]
            )
            path = f"/domain/{target}"
        elif ioc.type in {IocType.IPV4, IocType.IPV6}:
            path = f"/ip/{ioc.normalized}"
        else:
            return self._error_observation("unsupported_ioc")

        response = await self._client.get(path)
        response.raise_for_status()
        return self._observation(response.json(), ioc)

    def _observation(self, data: dict[str, Any], ioc: ParsedIoc) -> McpObservation:
        registrar = self._registrar(data)
        contacts = self._contacts(data)
        nameservers = [
            str(nameserver.get("ldhName", ""))
            for nameserver in data.get("nameservers", [])
            if nameserver.get("ldhName")
        ]
        dates = {
            key: data.get(key)
            for key in ("registrationDate", "expirationDate", "lastChangedDate")
            if data.get(key)
        }

        reputation: dict[str, Any] = {
            "score": 0,
            "verdict": "unknown",
            "tags": [],
        }
        if registrar:
            reputation["registrar"] = registrar
        if nameservers:
            reputation["nameservers"] = nameservers
        if dates:
            reputation["dates"] = dates
        if not reputation["tags"]:
            reputation["tags"] = ["rdap:registered"]

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
            },
            reputation=reputation,
            geolocation=contacts,
        )

    def _registrar(self, data: dict[str, Any]) -> str | None:
        for entity in data.get("entities", []):
            if "registrar" in (entity.get("roles") or []):
                return self._entity_name(entity)
        return None

    def _contacts(self, data: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for entity in data.get("entities", []):
            country = self._entity_country(entity)
            if country:
                result["country"] = country
                break
        return result

    def _entity_name(self, entity: dict[str, Any]) -> str | None:
        vcard = entity.get("vcardArray", [None, []])[1]
        for item in vcard:
            if item and item[0] == "fn":
                return str(item[3])
        return None

    def _entity_country(self, entity: dict[str, Any]) -> str | None:
        vcard = entity.get("vcardArray", [None, []])[1]
        for item in vcard:
            if item and item[0] == "adr":
                components = item[3].get("value") if isinstance(item[3], dict) else item[3]
                if isinstance(components, list) and components and components[-1]:
                    return str(components[-1])
        return None

    def _error_observation(self, tag: str) -> McpObservation:
        return McpObservation(
            source=self.name,
            raw={"mock": False},
            reputation={"score": 0, "verdict": "unknown", "tags": [f"rdap:{tag}"]},
        )
