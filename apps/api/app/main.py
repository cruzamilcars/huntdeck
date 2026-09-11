import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.v1.api import api_router
from app.core.config import get_settings
from app.core.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from app.mcp import McpAuthMiddleware, get_mcp_http_app, mount_mcp

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_settings()
    mcp_app = get_mcp_http_app()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _purge_expired_history(settings.investigation_retention_days)
        # Delegate startup/shutdown to the mounted MCP session manager.
        async with mcp_app.lifespan(app):
            yield

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )
    # Innermost first: /mcp requests still pass through CORS/security/rate-limit.
    app.add_middleware(McpAuthMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin).rstrip("/") for origin in settings.api_cors_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, settings=settings)
    app.include_router(api_router)
    mount_mcp(app, http_app=mcp_app)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def _purge_expired_history(retention_days: int) -> None:
    """Apply INVESTIGATION_RETENTION_DAYS once at startup (best-effort).

    Failures never block startup: an unreachable Supabase project or a
    locked SQLite file is logged and skipped so the API still serves.
    """
    if retention_days <= 0:
        return
    try:
        from app.domain.quota.service import get_quota_store

        store = get_quota_store()
        removed = store.prune_investigations(retention_days)
        logger.info(
            "Retention purge: removed %d investigations older than %d days",
            removed,
            retention_days,
        )
    except Exception:  # noqa: BLE001 - retention must never block startup
        logger.exception("Retention purge failed; continuing without it")


app = create_app()
