"""MCP server exposing HuntDeck's investigation engine as an MCP tool.

Any MCP-capable agent or console (Claude, Codex, random MCP clients) can
point at ``/mcp`` on the API and call ``investigate`` to get the same
tactical report the web console renders.

Transport is Streamable HTTP (the current MCP standard). ``json_response``
mode returns plain JSON to ``Accept: application/json`` clients and falls
back to SSE for stream-aware ones, so plain HTTP probes work too.
"""

from functools import lru_cache

from fastapi import FastAPI, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings
from app.services.orchestrator import InvestigationOrchestrator, get_orchestrator

MCP_SERVER_NAME = "huntdeck"
MCP_SERVER_VERSION = "0.1.0"
MCP_MOUNT_PATH = "/mcp"

MCP_INSTRUCTIONS = (
    "HuntDeck investigates indicators of compromise (IPs, domains, URLs, hashes, "
    "emails, phone numbers, social handles) by fanning out to up to 12 OSINT "
    "providers and returns a tactical report: risk score/severity, reputation, "
    "geolocation, relationship graph, community reports, MITRE/NIST/ISO mappings "
    "and playbooks."
)


def create_mcp_server(orchestrator: InvestigationOrchestrator | None = None):
    from fastmcp import FastMCP

    mcp = FastMCP(
        MCP_SERVER_NAME,
        instructions=MCP_INSTRUCTIONS,
        version=MCP_SERVER_VERSION,
    )

    @mcp.tool(
        name="investigate",
        description=(
            "Investigate an IOC and return the tactical report (risk, reputation, "
            "geolocation, relationships, mappings, playbooks)."
        ),
    )
    async def investigate(ioc: str) -> dict:
        """Run an IOC investigation against the configured OSINT providers."""
        engine = orchestrator or get_orchestrator()
        # Match the HTTP route: reject strings that are not a recognizable IOC
        # instead of silently returning an UNKNOWN-type report.
        from app.domain.ioc.parser import parse_ioc
        from app.domain.ioc.types import IocType

        if parse_ioc(ioc).type == IocType.UNKNOWN:
            raise ValueError(f"{ioc!r} is not a recognizable IOC.")
        # MCP is the programmatic/service surface: no platform quota is burned
        # here (the HTTP route enforces the anonymous/free quota). Caching and
        # BYOK semantics still apply inside the orchestrator.
        result = await engine.investigate(ioc)
        return result.model_dump()

    return mcp


@lru_cache
def get_mcp_server():
    return create_mcp_server()


@lru_cache
def get_mcp_http_app():
    """The Starlette app serving /mcp.

    Reused across ``create_app`` so that the SAME app instance provides both
    the lifespan (its ``session_manager.run()``) and the mounted handler.
    """
    return get_mcp_server().http_app(path="/", transport="streamable-http", json_response=True)


def mount_mcp(app: FastAPI, *, http_app=None) -> None:
    """Mount the MCP endpoint on the FastAPI app.

    App-level middleware (CORS, security headers, rate limit, MCP auth) still
    applies. IMPORTANT: pass ``lifespan=http_app.lifespan`` to the parent
    FastAPI constructor so the session manager's task group actually starts —
    Starlette mounts do not run the mounted app's lifespan on their own.
    """
    app.mount(MCP_MOUNT_PATH, http_app or get_mcp_http_app(), name="mcp")


class McpAuthMiddleware(BaseHTTPMiddleware):
    """Guard /mcp with service credentials once real auth is configured.

    Matches the rest of the API: while ``supabase_jwt_secret`` is unset the
    API runs in anonymous dev mode, so /mcp is open too. When auth is on,
    callers must present a valid service ``X-API-Key`` (verified against the
    same store the REST routes use). Interactive MCP clients typically proxy
    through this as ``Authorization: Bearer <service-key>``.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path.startswith(MCP_MOUNT_PATH):
            settings = get_settings()
            if settings.supabase_jwt_secret:
                api_key = request.headers.get("x-api-key") or _bearer_key(
                    request.headers.get("authorization")
                )
                if api_key is None or not _valid_service_key(api_key):
                    return Response(
                        content='{"detail":"A valid X-API-Key service credential is required."}',
                        media_type="application/json",
                        status_code=status.HTTP_401_UNAUTHORIZED,
                    )
        return await call_next(request)


def _bearer_key(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, credential = authorization.partition(" ")
    return credential if scheme.lower() == "bearer" and credential else None


def _valid_service_key(api_key: str) -> bool:
    from app.core.security import hash_api_key
    from app.domain.quota.service import get_quota_store

    store = get_quota_store()
    return store.verify_api_key(hash_api_key(api_key)) is not None


__all__ = [
    "MCP_INSTRUCTIONS",
    "MCP_MOUNT_PATH",
    "MCP_SERVER_NAME",
    "MCP_SERVER_VERSION",
    "McpAuthMiddleware",
    "get_mcp_http_app",
    "get_mcp_server",
    "mount_mcp",
]
