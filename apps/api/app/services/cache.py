"""Investigation cache backends.

The default is an in-process dict bounded by TTL and entry count. When
``REDIS_URL`` is set (and the optional ``redis`` package is installed), a
shared Redis backend is used so cache hits survive across uvicorn workers or
replicas. Without the ``redis`` package the config degrades gracefully back to
the in-memory backend with a logged warning.
"""

from __future__ import annotations

import json
import logging
from time import time
from typing import Any

logger = logging.getLogger(__name__)

_TTL_SECONDS = 5 * 60
_MAX_ENTRIES = 256


class MemoryCache:
    def __init__(self, ttl: float = _TTL_SECONDS, max_entries: int = _MAX_ENTRIES) -> None:
        self._ttl = ttl
        self._max_entries = max_entries
        self._store: dict[str, tuple[float, Any]] = {}

    async def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, value = entry
        if time() - ts > self._ttl:
            self._store.pop(key, None)
            return None
        return value

    async def put(self, key: str, value: Any) -> None:
        if len(self._store) >= self._max_entries:
            self._store.pop(next(iter(self._store)), None)
        self._store[key] = (time(), value)


class RedisCache:
    def __init__(self, url: str, ttl: float = _TTL_SECONDS) -> None:
        try:
            import redis.asyncio as redis  # noqa: PLC0415
        except ImportError:
            raise RuntimeError(
                "redis package not installed; set REDIS_URL only after `pip install redis`"
            )
        self._redis = redis.from_url(url)
        self._ttl = int(ttl)
        self._prefix = "huntdeck:cache:"

    async def get(self, key: str) -> Any | None:
        raw = await self._redis.get(self._prefix + key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None

    async def put(self, key: str, value: Any) -> None:
        await self._redis.set(self._prefix + key, json.dumps(value), ex=self._ttl)


_backend: Any | None = None


async def get_cache_backend() -> Any:
    """Return the configured cache backend, built once per process."""
    global _backend
    if _backend is None:
        from app.core.config import get_settings  # noqa: PLC0415

        settings = get_settings()
        if settings.redis_url:
            try:
                _backend = RedisCache(settings.redis_url)
                logger.info("orchestrator.cache.backend", extra={"backend": "redis"})
            except RuntimeError as exc:
                logger.warning(
                    "orchestrator.cache.backend.fallback",
                    extra={"error": str(exc), "backend": "memory"},
                )
        if _backend is None:
            _backend = MemoryCache()
    return _backend
