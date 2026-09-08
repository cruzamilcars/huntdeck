from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.v1.api import api_router
from app.core.config import get_settings
from app.core.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from app.mcp import McpAuthMiddleware, get_mcp_http_app, mount_mcp


def create_app() -> FastAPI:
    settings = get_settings()
    mcp_app = get_mcp_http_app()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=mcp_app.lifespan,
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


app = create_app()
