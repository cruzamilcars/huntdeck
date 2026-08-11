"""Supabase (PostgREST + service-role) store.

Drop-in replacement for :class:`~app.infrastructure.store.SqliteStore`
implementing the same three-method interface, so the quota service and the
investigations route work unchanged against a live Supabase project.

Selected by the factory when SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are
set; otherwise the app falls back to the local SQLite store (no credentials
required). Quota reservation is delegated to the atomic SQL function
``public.reserve_daily_usage`` (supabase/migrations/002_quota_reserve_rpc.sql)
which rows locks the daily_usage row, so concurrent requests cannot
double-spend the free quota.

Note: org/user identifiers must be legal UUIDs when talking to Supabase
(the local dev-mode fallback uses free-form strings like "dev-org").
"""

import json
from datetime import date
from typing import Any

import httpx

from app.core.security import CurrentUser
from app.schemas.investigation import InvestigationResponse

HISTORY_SELECT = ",".join(
    [
        "raw_ioc",
        "normalized_ioc",
        "ioc_type",
        "risk_score",
        "severity",
        "sources",
        "used_byok",
        "created_at",
    ]
)


class SupabaseStore:
    def __init__(
        self,
        *,
        url: str,
        service_role_key: str,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base = url.rstrip("/") + "/rest/v1"
        self._client = httpx.Client(
            base_url=self._base,
            headers={
                "apikey": service_role_key,
                "Authorization": f"Bearer {service_role_key}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    # --- quota ---------------------------------------------------------------

    def reserve_usage(
        self,
        user: CurrentUser,
        usage_date: date,
        daily_free_quota: int,
        byok_providers: set[str],
    ) -> tuple[bool, bool, int, int, str]:
        payload = {
            "p_org_id": user.org_id,
            "p_user_id": user.user_id,
            "p_usage_date": usage_date.isoformat(),
            "p_daily_free_quota": daily_free_quota,
            "p_byok_providers": sorted(byok_providers),
        }
        response = self._client.post("/rpc/reserve_daily_usage", json=payload)
        response.raise_for_status()
        row = response.json()
        return (
            bool(row["allowed"]),
            bool(row["used_byok"]),
            int(row["free_queries_used"]),
            int(row["byok_queries_used"]),
            str(row["reason"]),
        )

    # --- investigations ------------------------------------------------------

    def save_investigation(self, user: CurrentUser, result: InvestigationResponse) -> None:
        row = {
            "org_id": user.org_id,
            "user_id": user.user_id,
            "raw_ioc": result.ioc.raw,
            "normalized_ioc": result.ioc.normalized,
            "ioc_type": str(result.ioc.type),
            "risk_score": result.risk.score,
            "severity": result.risk.severity,
            "sources": result.sources,
            "mcp_servers_queried": result.mcp_servers_queried,
            "used_byok": result.used_byok,
            "result_json": json.loads(result.model_dump_json()),
        }
        response = self._client.post("/investigations", json=row)
        response.raise_for_status()

    def list_investigations(self, user: CurrentUser, limit: int = 50) -> list[dict[str, Any]]:
        params: dict[str, str] = {
            "select": HISTORY_SELECT,
            "org_id": f"eq.{user.org_id}",
            "user_id": f"eq.{user.user_id}",
            "order": "created_at.desc",
            "limit": str(limit),
        }
        response = self._client.get("/investigations", params=params)
        response.raise_for_status()
        rows: list[dict[str, Any]] = response.json()

        def _flatten(row: dict[str, Any]) -> dict[str, Any]:
            flat = dict(row)
            flat["sources"] = json.dumps(row.get("sources") or [])
            return flat

        return [_flatten(row) for row in rows]


__all__ = ["SupabaseStore"]
