from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Callable

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import Settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings
        self._lock = Lock()
        self._hits: dict[str, deque[datetime]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path == "/health":
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=1)

        with self._lock:
            hits = self._hits[client]
            while hits and hits[0] < window_start:
                hits.popleft()
            if len(hits) >= self.settings.rate_limit_per_minute:
                return Response(
                    content='{"detail":"Rate limit exceeded."}',
                    media_type="application/json",
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            hits.append(now)

        return await call_next(request)
