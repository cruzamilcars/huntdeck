import pytest

from app.core.config import get_settings
from app.domain.quota import service as quota_module


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    from app.infrastructure.store import SqliteStore

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(get_settings(), "database_path", db_path)

    store = SqliteStore(db_path)
    monkeypatch.setattr(quota_module, "_quota_service", None)
    monkeypatch.setattr(quota_module, "_quota_store", store)
    yield store
    store.close()
