"""crt.sh certificate transparency adapter.

Keyless and always-on. Enumerates certificates issued for a domain and the
observable subdomains hidden in certificate name fields — a passive
subdomain discovery source for DOMAIN IOCs.
"""

import json
from collections import Counter

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

BASE_URL = "https://crt.sh"


class CrtshMcpClient:
    """Real certificate-transparency adapter (keyless, best effort)."""

    name = "mcp-crtsh"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=15.0, base_url=BASE_URL)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.DOMAIN:
            return self._error_observation("crtsh_unsupported_ioc")
        try:
            response = await self._client.get(
                "/", params={"q": f"%25.{ioc.normalized}", "output": "json"}
            )
            response.raise_for_status()
            data = response.json()
            return self._observation(ioc, data)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"429": "rate_limited", "403": "blocked"}.get(str(status), f"http_{status}")
            return self._error_observation(f"crtsh_{reason}")
        except (httpx.RequestError, json.JSONDecodeError, ValueError):
            return self._error_observation("crtsh_unreachable")

    def _observation(self, ioc: ParsedIoc, data: list) -> McpObservation:
        certificates = data if isinstance(data, list) else []
        subjects = set()
        issuers = Counter()
        for certificate in certificates:
            for name in str(certificate.get("name_value", "")).split("\n"):
                name = name.strip().strip("*.")
                if name and name.endswith(ioc.normalized):
                    subjects.add(name)
            issuer = str(certificate.get("issuer_name", "") or "unknown")
            issuers[issuer] += 1

        relationships = [
            {"kind": "certificate_subject", "target": subject} for subject in sorted(subjects)
        ]
        score = 0 if subjects else -10 if not certificates else 0
        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "certificates_found": len(certificates),
                "subdomains_found": sorted(subjects)[:25],
            },
            reputation={
                "score": max(0, score),
                "verdict": "clean",
                "tags": [
                    f"crtsh:certificates:{len(certificates)}",
                    f"crtsh:subdomains:{len(subjects)}",
                    f"crtsh:issuers:{len(issuers)}",
                ],
            },
            relationships=relationships,
        )

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
