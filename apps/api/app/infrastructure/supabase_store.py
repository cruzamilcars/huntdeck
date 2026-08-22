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
from app.domain.ioc.types import ParsedIoc
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

    def list_investigations(
        self, user: CurrentUser, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        params: dict[str, str] = {
            "select": HISTORY_SELECT,
            "org_id": f"eq.{user.org_id}",
            "user_id": f"eq.{user.user_id}",
            "order": "created_at.desc",
            "limit": str(limit),
            "offset": str(offset),
        }
        response = self._client.get("/investigations", params=params)
        response.raise_for_status()
        rows: list[dict[str, Any]] = response.json()

        def _flatten(row: dict[str, Any]) -> dict[str, Any]:
            flat = dict(row)
            flat["sources"] = json.dumps(row.get("sources") or [])
            return flat

        return [_flatten(row) for row in rows]

    def stats(self, user: CurrentUser, days: int = 14) -> dict[str, Any]:
        """Aggregate metrics over the user's investigations.

        PostgREST has no GROUP BY aggregation for arbitrary expressions, so we
        fetch the scoped rows and aggregate in Python. Fine for analytics
        volumes; move to a SQL view if it ever becomes hot.
        """
        rows = self.list_investigations(user, limit=1000)
        by_severity: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_day: dict[str, int] = {}
        ioc_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        scores: list[int] = []
        byok_count = 0

        for row in rows:
            severity = str(row.get("severity") or "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
            ioc_type = str(row.get("ioc_type") or "unknown")
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            day = str(row.get("created_at") or "")[:10]
            if day:
                by_day[day] = by_day.get(day, 0) + 1
            ioc = str(row.get("normalized_ioc") or "unknown")
            ioc_counts[ioc] = ioc_counts.get(ioc, 0) + 1
            for source in json.loads(row.get("sources") or "[]"):
                source_counts[str(source)] = source_counts.get(str(source), 0) + 1
            score = row.get("risk_score")
            if isinstance(score, (int, float)):
                scores.append(int(score))
            if row.get("used_byok"):
                byok_count += 1

        daily_dates = sorted(by_day.keys())[-days:]
        return {
            "total": len(rows),
            "avg_risk_score": round(sum(scores) / len(scores), 1) if scores else None,
            "byok_count": byok_count,
            "by_severity": by_severity,
            "by_type": by_type,
            "top_iocs": [
                {"ioc": ioc, "count": count}
                for ioc, count in sorted(
                    ioc_counts.items(), key=lambda item: item[1], reverse=True
                )[:5]
            ],
            "daily": [{"date": day, "count": by_day[day]} for day in daily_dates],
            "sources_used": [
                {"source": source, "count": count}
                for source, count in sorted(
                    source_counts.items(), key=lambda item: item[1], reverse=True
                )
            ],
        }

    # --- watchlist -----------------------------------------------------------

    def add_watch_item(
        self,
        user: CurrentUser,
        parsed_ioc: ParsedIoc,
        note: str | None = None,
    ) -> dict:
        row = {
            "org_id": user.org_id,
            "user_id": user.user_id,
            "raw_ioc": parsed_ioc.raw,
            "normalized_ioc": parsed_ioc.normalized,
            "ioc_type": str(parsed_ioc.type),
            "note": note or None,
        }
        response = self._client.post(
            "/watchlist",
            params={"on_conflict": "org_id,user_id,normalized_ioc"},
            headers={"Prefer": "resolution=merge-duplicates,return=representation"},
            json=row,
        )
        response.raise_for_status()
        created = response.json()
        if isinstance(created, list) and created:
            return created[0]
        raise RuntimeError("Supabase did not return the created watchlist row")

    def list_watch_items(self, user: CurrentUser) -> list[dict]:
        params: dict[str, str] = {
            "org_id": f"eq.{user.org_id}",
            "user_id": f"eq.{user.user_id}",
            "order": "created_at.desc",
        }
        response = self._client.get("/watchlist", params=params)
        response.raise_for_status()
        return response.json()

    def remove_watch_item(self, user: CurrentUser, normalized_ioc: str) -> bool:
        response = self._client.delete(
            "/watchlist",
            params={
                "normalized_ioc": f"eq.{normalized_ioc}",
                "org_id": f"eq.{user.org_id}",
                "user_id": f"eq.{user.user_id}",
            },
        )
        response.raise_for_status()
        return True

    def touch_watch_item(
        self,
        user: CurrentUser,
        normalized_ioc: str,
        risk_score: int | None,
        severity: str | None,
    ) -> None:
        from datetime import UTC, datetime

        response = self._client.patch(
            "/watchlist",
            params={
                "normalized_ioc": f"eq.{normalized_ioc}",
                "org_id": f"eq.{user.org_id}",
                "user_id": f"eq.{user.user_id}",
            },
            json={
                "last_checked_at": datetime.now(UTC).isoformat(),
                "last_risk_score": risk_score,
                "last_severity": severity,
            },
        )
        response.raise_for_status()


__all__ = ["SupabaseStore"]
