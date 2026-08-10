import json
import sqlite3
from datetime import UTC, date, datetime
from pathlib import Path
from threading import Lock

from app.core.security import CurrentUser
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
    ) -> list[dict]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT raw_ioc, normalized_ioc, ioc_type, risk_score, severity, "
                "       sources, used_byok, created_at "
                "FROM investigations "
                "WHERE org_id = ? AND user_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (user.org_id, user.user_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]
