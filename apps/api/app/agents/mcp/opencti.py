"""OpenCTI adapter (org-internal threat intelligence platform).

Real adapter implementing the McpClient contract. Queries your OpenCTI
instance's GraphQL ``stixCyberObservables`` endpoint for the IOC and
surfaces the linked entities (reports, indicators, labels) that reported
it. Requires both ``OPENCTI_URL`` and ``OPENCTI_API_KEY``; the key is sent
only in the Authorization Bearer header. Failures become structured
observations with an empty reputation.

Scoring follows OpenCTI semantics: ``x_opencti_score`` on the observable
(0-100, attacker-controlled) wins when present; otherwise sightings with
linked entities default to 50 (suspicious).
"""

import json
import logging
from typing import Any

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

logger = logging.getLogger(__name__)

SUPPORTED_TYPES = {
    IocType.IPV4,
    IocType.IPV6,
    IocType.DOMAIN,
    IocType.URL,
    IocType.MD5,
    IocType.SHA1,
    IocType.SHA256,
    IocType.EMAIL,
}

# IocType -> OpenCTI StixCyberObservable type (PascalCase, schema-stable).
_OBSERVABLE_TYPES = {
    IocType.IPV4: "IPv4-Addr",
    IocType.IPV6: "IPv6-Addr",
    IocType.DOMAIN: "Domain-Name",
    IocType.URL: "Url",
    IocType.MD5: "StixFile",
    IocType.SHA1: "StixFile",
    IocType.SHA256: "StixFile",
    IocType.EMAIL: "Email-Addr",
}

_QUERY = """
query HuntDeck($types: [String], $filters: FilterGroup, $first: Int) {
  stixCyberObservables(types: $types, filters: $filters, first: $first) {
    edges {
      node {
        id
        entity_type
        observable_value
        x_opencti_description
        x_opencti_score
        created_at
        objectLabel {
          id
          value
        }
        indicators(first: 3) {
          edges {
            node {
              id
              name
              pattern
            }
          }
        }
      }
    }
    pageInfo {
      globalCount
    }
  }
}
"""


class OpenCtiMcpClient:
    """Real OpenCTI adapter for org-internal observable lookups."""

    name = "mcp-opencti"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        verify_ssl: bool = True,
    ) -> None:
        if not base_url or not api_key:
            raise ValueError("OPENCTI_URL and OPENCTI_API_KEY are required")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(
            timeout=10.0,
            base_url=base_url.rstrip("/"),
            verify=verify_ssl,
        )

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        try:
            return await self._query_ioc(ioc)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {"401": "unauthorized", "403": "forbidden", "404": "endpoint_not_found"}.get(
                str(status), f"http_{status}"
            )
            return self._error_observation(f"opencti_{reason}")
        except httpx.RequestError:
            return self._error_observation("opencti_unreachable")
        except ValueError as exc:
            # GraphQL 200-with-errors payloads raise ValueError in this adapter
            # (mirrors pycti behavior) - degrade to a structured observation.
            logger.warning("opencti.graphql.error", extra={"error": str(exc)[:200]})
            return self._error_observation("opencti_graphql_error")

    async def _query_ioc(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type not in SUPPORTED_TYPES:
            return self._error_observation("opencti_unsupported_ioc")

        # OpenCTI stores Domain-Name and Email-Addr observables lowercased;
        # the parser already normalizes both, but a BTC-style raw passthrough
        # would break eq-matching, so lowercase defensively for those types.
        value = ioc.normalized
        if ioc.type in {IocType.DOMAIN, IocType.EMAIL}:
            value = value.lower()

        response = await self._client.post(
            "/graphql",
            json={
                "query": _QUERY,
                "variables": {
                    "types": [_OBSERVABLE_TYPES[ioc.type]],
                    "filters": {
                        "mode": "and",
                        "filters": [{"key": "value", "values": [value], "operator": "eq"}],
                        "filterGroups": [],
                    },
                    "first": 5,
                },
            },
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("errors"):
            # Mirrors pycti: an errors array is a failed query, not empty data.
            raise ValueError(json.dumps(payload["errors"])[:200])

        edges = ((payload.get("data") or {}).get("stixCyberObservables") or {}).get("edges") or []
        return self._observation(edges, ioc)

    def _observation(self, edges: list[dict[str, Any]], ioc: ParsedIoc) -> McpObservation:
        raw = {
            "entity": ioc.normalized,
            "entity_type": ioc.type,
            "mock": False,
            "observable_count": len(edges),
        }
        if not edges:
            return McpObservation(
                source=self.name,
                raw=raw,
                reputation={"score": 0, "verdict": "clean", "tags": ["opencti:no-reports"]},
            )

        observables = [edge.get("node") or {} for edge in edges]
        score = self._score(observables)
        return McpObservation(
            source=self.name,
            raw={
                **raw,
                "observables": [
                    {
                        "id": obs.get("id"),
                        "entity_type": obs.get("entity_type"),
                        "value": obs.get("observable_value"),
                        "description": obs.get("x_opencti_description"),
                        "score": obs.get("x_opencti_score"),
                        "labels": [label.get("value") for label in obs.get("objectLabel") or []],
                        "indicators": [
                            (indicator.get("node") or {}).get("name")
                            for indicator in (obs.get("indicators") or {}).get("edges") or []
                            if (indicator.get("node") or {}).get("name")
                        ],
                    }
                    for obs in observables
                ],
            },
            reputation={
                "score": score,
                "verdict": "malicious" if score >= 60 else "suspicious",
                "tags": self._tags(observables),
            },
            relationships=self._relationships(observables),
            community_reports=self._reports(observables),
        )

    def _score(self, observables: list[dict[str, Any]]) -> int:
        # x_opencti_score is the platform's own 0-100 risk score; use the max.
        for obs in observables:
            score = obs.get("x_opencti_score")
            if isinstance(score, (int, float)) and score > 0:
                return int(score)
        # Known observable with linked context but no platform score: suspicious.
        return 50

    def _tags(self, observables: list[dict[str, Any]]) -> list[str]:
        tags = ["opencti:sighted"]
        labels = sorted(
            {
                label
                for obs in observables
                for label in [item.get("value") for item in obs.get("objectLabel") or []]
                if label
            }
        )
        tags.extend(f"opencti:label:{label}" for label in labels[:5])
        return tags[:8]

    def _relationships(self, observables: list[dict[str, Any]]) -> list[dict[str, str]]:
        relationships: list[dict[str, str]] = []
        for obs in observables[:5]:
            entity_type = str(obs.get("entity_type") or "observable")
            value = str(obs.get("observable_value") or "")[:60]
            relationships.append(
                {"kind": "reported_in", "target": f"OpenCTI {entity_type}: {value}"}
            )
        return relationships

    def _reports(self, observables: list[dict[str, Any]]) -> list[dict[str, str]]:
        reports = []
        for obs in observables[:3]:
            description = str(obs.get("x_opencti_description") or "").strip()
            entity_type = str(obs.get("entity_type") or "observable")
            summary = f"OpenCTI {entity_type} sighting" + (
                f" — {description[:120]}" if description else ""
            )
            reports.append(
                {
                    "title": f"OpenCTI sighting: {entity_type}",
                    "confidence": "medium",
                    "summary": summary,
                }
            )
        return reports

    def _error_observation(self, reason: str) -> McpObservation:
        return McpObservation(source=self.name, raw={"error": reason, "mock": False})
