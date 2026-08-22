import json
import sqlite3
from datetime import UTC, date, datetime
from pathlib import Path
from threading import Lock

from app.core.security import CurrentUser
from app.domain.ioc.types import ParsedIoc
from app.schemas.investigation import InvestigationResponse

SCHEMA = """
CREATE TABLE IF NOT EXISTS daily_usage (
  org_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  usage_date TEXT NOT NULL,
  free_queries_used INTEGER NOT NULL DEFAULT 0,
  byok_queries_used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (org_id, user_id, usage_date)
);

CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  raw_ioc TEXT NOT NULL,
  normalized_ioc TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  risk_score INTEGER,
  severity TEXT,
  sources TEXT NOT NULL,
  result_json TEXT NOT NULL,
  used_byok INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS investigations_scope_created
  ON investigations (org_id, user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  raw_ioc TEXT NOT NULL,
  normalized_ioc TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  last_checked_at TEXT,
  last_risk_score INTEGER,
  last_severity TEXT
);

CREATE INDEX IF NOT EXISTS watchlist_scope
  ON watchlist (org_id, user_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS watchlist_scope_unique
  ON watchlist (org_id, user_id, normalized_ioc);

CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  org_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
);
"""


class SqliteStore:
    """Durable local storage for quota usage and investigation history.

    Purpose-built mirror of the Supabase tables (daily_usage, investigations)
    so the app is fully functional without external credentials. Supabase
    remains the production target; the schema in supabase/migrations/ is
    already compatible with this row shape.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._lock = Lock()
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)
        self._connection = self._connect(check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

    def _connect(self, *, check_same_thread: bool = True) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path, check_same_thread=check_same_thread)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    # --- quota ---------------------------------------------------------------

    def reserve_usage(
        self,
        user: CurrentUser,
        usage_date: date,
        daily_free_quota: int,
        byok_providers: set[str],
    ) -> tuple[bool, bool, int, int, str]:
        row_key = (user.org_id, user.user_id, usage_date.isoformat())
        with self._lock:
            free, byok = self._get_usage(row_key)
            if free < daily_free_quota:
                free += 1
                self._set_usage(row_key, free, byok)
                return True, False, free, byok, "platform_quota"
            if byok_providers:
                byok += 1
                self._set_usage(row_key, free, byok)
                return True, True, free, byok, "byok"
            return False, False, free, byok, "quota_exhausted"

    def _get_usage(self, row_key: tuple[str, str, str]) -> tuple[int, int]:
        row = self._connection.execute(
            "SELECT free_queries_used, byok_queries_used FROM daily_usage "
            "WHERE org_id = ? AND user_id = ? AND usage_date = ?",
            row_key,
        ).fetchone()
        if row is None:
            return 0, 0
        return int(row[0]), int(row[1])

    def _set_usage(self, row_key: tuple[str, str, str], free: int, byok: int) -> None:
        self._connection.execute(
            "INSERT INTO daily_usage (org_id, user_id, usage_date, free_queries_used, byok_queries_used) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (org_id, user_id, usage_date) DO UPDATE SET "
            "free_queries_used = excluded.free_queries_used, "
            "byok_queries_used = excluded.byok_queries_used",
            (*row_key, free, byok),
        )
        self._connection.commit()

    # --- investigations ------------------------------------------------------

    def save_investigation(self, user: CurrentUser, result: InvestigationResponse) -> None:
        with self._lock:
            self._connection.execute(
                "INSERT INTO investigations "
                "(org_id, user_id, raw_ioc, normalized_ioc, ioc_type, risk_score, "
                " severity, sources, result_json, used_byok, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    user.org_id,
                    user.user_id,
                    result.ioc.raw,
                    result.ioc.normalized,
                    str(result.ioc.type),
                    result.risk.score,
                    result.risk.severity,
                    json.dumps(result.sources),
                    result.model_dump_json(),
                    int(result.used_byok),
                    datetime.now(UTC).isoformat(),
                ),
            )
            self._connection.commit()

    def list_investigations(
        self,
        user: CurrentUser,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT raw_ioc, normalized_ioc, ioc_type, risk_score, severity, "
                "       sources, used_byok, created_at "
                "FROM investigations "
                "WHERE org_id = ? AND user_id = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (user.org_id, user.user_id, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self, user: CurrentUser, days: int = 14) -> dict:
        with self._lock:
            total = self._connection.execute(
                "SELECT COUNT(*) FROM investigations WHERE org_id = ? AND user_id = ?",
                (user.org_id, user.user_id),
            ).fetchone()[0]
            avg_score = self._connection.execute(
                "SELECT AVG(risk_score) FROM investigations "
                "WHERE org_id = ? AND user_id = ? AND risk_score IS NOT NULL",
                (user.org_id, user.user_id),
            ).fetchone()[0]
            byok_count = self._connection.execute(
                "SELECT COUNT(*) FROM investigations "
                "WHERE org_id = ? AND user_id = ? AND used_byok = 1",
                (user.org_id, user.user_id),
            ).fetchone()[0]
            by_severity = {
                str(row[0]): int(row[1])
                for row in self._connection.execute(
                    "SELECT severity, COUNT(*) FROM investigations "
                    "WHERE org_id = ? AND user_id = ? GROUP BY severity",
                    (user.org_id, user.user_id),
                ).fetchall()
            }
            by_type = {
                str(row[0]): int(row[1])
                for row in self._connection.execute(
                    "SELECT ioc_type, COUNT(*) FROM investigations "
                    "WHERE org_id = ? AND user_id = ? GROUP BY ioc_type",
                    (user.org_id, user.user_id),
                ).fetchall()
            }
            top_iocs = [
                {"ioc": str(row[0]), "count": int(row[1])}
                for row in self._connection.execute(
                    "SELECT normalized_ioc, COUNT(*) FROM investigations "
                    "WHERE org_id = ? AND user_id = ? "
                    "GROUP BY normalized_ioc ORDER BY COUNT(*) DESC LIMIT 5",
                    (user.org_id, user.user_id),
                ).fetchall()
            ]
            daily = [
                {"date": str(row[0]), "count": int(row[1])}
                for row in self._connection.execute(
                    "SELECT substr(created_at, 1, 10), COUNT(*) FROM investigations "
                    "WHERE org_id = ? AND user_id = ? "
                    "GROUP BY substr(created_at, 1, 10) ORDER BY 1 DESC LIMIT ?",
                    (user.org_id, user.user_id, days),
                ).fetchall()
            ]
            daily.reverse()
            sources_used = [
                {"source": str(row[0]), "count": int(row[1])}
                for row in self._connection.execute(
                    "SELECT json_each.value, COUNT(*) FROM investigations, "
                    "json_each(investigations.sources) "
                    "WHERE org_id = ? AND user_id = ? "
                    "GROUP BY json_each.value ORDER BY COUNT(*) DESC",
                    (user.org_id, user.user_id),
                ).fetchall()
            ]
        return {
            "total": int(total),
            "avg_risk_score": round(float(avg_score), 1) if avg_score is not None else None,
            "byok_count": int(byok_count),
            "by_severity": by_severity,
            "by_type": by_type,
            "top_iocs": top_iocs,
            "daily": daily,
            "sources_used": sources_used,
        }

    # --- watchlist -----------------------------------------------------------

    def add_watch_item(
        self,
        user: CurrentUser,
        parsed_ioc: ParsedIoc,
        note: str | None = None,
    ) -> dict:
        with self._lock:
            cursor = self._connection.execute(
                "INSERT INTO watchlist "
                "(org_id, user_id, raw_ioc, normalized_ioc, ioc_type, note, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (org_id, user_id, normalized_ioc) DO UPDATE SET raw_ioc = excluded.raw_ioc",
                (
                    user.org_id,
                    user.user_id,
                    parsed_ioc.raw,
                    parsed_ioc.normalized,
                    str(parsed_ioc.type),
                    note or None,
                    datetime.now(UTC).isoformat(),
                ),
            )
            self._connection.commit()
            row = self._connection.execute(
                "SELECT id, raw_ioc, normalized_ioc, ioc_type, note, created_at, "
                "       last_checked_at, last_risk_score, last_severity "
                "FROM watchlist WHERE id = ? AND org_id = ? AND user_id = ?",
                (cursor.lastrowid, user.org_id, user.user_id),
            ).fetchone()
        if row is None:
            raise KeyError(f"Watch item {cursor.lastrowid} not found")
        return dict(row)

    def list_watch_items(self, user: CurrentUser) -> list[dict]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, raw_ioc, normalized_ioc, ioc_type, note, created_at, "
                "       last_checked_at, last_risk_score, last_severity "
                "FROM watchlist "
                "WHERE org_id = ? AND user_id = ? "
                "ORDER BY created_at DESC",
                (user.org_id, user.user_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def remove_watch_item(self, user: CurrentUser, normalized_ioc: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM watchlist WHERE normalized_ioc = ? AND org_id = ? AND user_id = ?",
                (normalized_ioc, user.org_id, user.user_id),
            )
            self._connection.commit()
            return cursor.rowcount > 0

    def touch_watch_item(
        self,
        user: CurrentUser,
        normalized_ioc: str,
        risk_score: int | None,
        severity: str | None,
    ) -> None:
        with self._lock:
            self._connection.execute(
                "UPDATE watchlist SET last_checked_at = ?, last_risk_score = ?, last_severity = ? "
                "WHERE normalized_ioc = ? AND org_id = ? AND user_id = ?",
                (
                    datetime.now(UTC).isoformat(),
                    risk_score,
                    severity,
                    normalized_ioc,
                    user.org_id,
                    user.user_id,
                ),
            )
            self._connection.commit()

    # --- service API keys ----------------------------------------------------

    def create_api_key(self, name: str, org_id: str, key_hash: str) -> int:
        with self._lock:
            cursor = self._connection.execute(
                "INSERT INTO api_keys (name, key_hash, org_id, created_at) VALUES (?, ?, ?, ?)",
                (name, key_hash, org_id, datetime.now(UTC).isoformat()),
            )
            self._connection.commit()
            return int(cursor.lastrowid)

    def list_api_keys(self) -> list[dict]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, name, org_id, created_at, last_used_at, enabled FROM api_keys "
                "ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_api_key(self, key_id: int) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE api_keys SET enabled = 0 WHERE id = ? AND enabled = 1", (key_id,)
            )
            self._connection.commit()
            return cursor.rowcount > 0

    def verify_api_key(self, key_hash: str) -> str | None:
        """Return the org_id bound to the key, or None when invalid."""
        with self._lock:
            row = self._connection.execute(
                "SELECT org_id FROM api_keys WHERE key_hash = ? AND enabled = 1", (key_hash,)
            ).fetchone()
            if row is None:
                return None
            self._connection.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?",
                (datetime.now(UTC).isoformat(), key_hash),
            )
            self._connection.commit()
            return str(row[0])
