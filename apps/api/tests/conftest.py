import os
import pytest
import httpx

from app.core.config import get_settings
from app.domain.quota import service as quota_module


def _supabase_dev_org_reset():
    """Reset daily_usage for dev org in Supabase (used by integration tests)."""
    settings = get_settings()
    if not (settings.supabase_url and settings.supabase_secret_key):
        return  # using SQLite, no need to reset
    key = settings.supabase_secret_key
    url = settings.supabase_url.rstrip("/") + "/rest/v1"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Prefer": "return=minimal",
    }
    dev_org = "00000000-0000-0000-0000-000000000001"
    dev_user = "00000000-0000-0000-0000-000000000002"
    from datetime import date
    today = date.today().isoformat()

    try:
        httpx.delete(
            f"{url}/daily_usage?org_id=eq.{dev_org}",
            headers=headers,
            timeout=10,
        )
        httpx.post(
            f"{url}/daily_usage",
            headers={**headers, "Prefer": "resolution=merge-duplicates"},
            json={"org_id": dev_org, "user_id": dev_user, "usage_date": today, "free_queries_used": 0, "byok_queries_used": 0},
            timeout=10,
        )
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_supabase_daily_usage(request):
    """Reset Supabase dev org quota before integration tests if markers/environment allow."""
    is_integration = any(
        "integration" in getattr(mark, "name", "")
        for mark in getattr(request.node, "marks", [])
    )
    if is_integration:
        _supabase_dev_org_reset()
    yield
    if is_integration:
        _supabase_dev_org_reset()
