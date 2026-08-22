from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from hashlib import sha256
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
    """Per-identity sliding-window rate limiter.

    Anonymous traffic is bucketed per client IP. Requests carrying an
    ``X-API-Key`` service credential get their own, much larger bucket (the
    key itself is validated downstream; here only its fingerprint shapes the
    identity) so SIEM/CI integrations do not compete with browser traffic.
    """

    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings
        self._lock = Lock()
        self._hits: dict[str, deque[datetime]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path == "/health":
            return await call_next(request)

        identity, limit = self._identity_and_limit(request)
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=1)

        with self._lock:
            hits = self._hits[identity]
            while hits and hits[0] < window_start:
                hits.popleft()
            if len(hits) >= limit:
                return Response(
                    content='{"detail":"Rate limit exceeded."}',
                    media_type="application/json",
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            hits.append(now)

        return await call_next(request)

    def _identity_and_limit(self, request: Request) -> tuple[str, int]:
        api_key = request.headers.get("x-api-key")
        if api_key:
            fingerprint = sha256(api_key.encode()).hexdigest()[:12]
            return f"key:{fingerprint}", self.settings.service_rate_limit_per_minute
        client = request.client.host if request.client else "unknown"
        return client, self.settings.rate_limit_per_minute
