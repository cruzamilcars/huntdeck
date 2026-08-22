"""System routes: provider status transparency.

Exposes which MCP providers are live (real adapters) versus mocked because
their API key is not configured, so operators and the dashboard can show
exactly what evidence is real. Never exposes key values.
"""

from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.core.security import CurrentUser, get_current_user
from app.services.orchestrator import get_orchestrator

router = APIRouter(prefix="/system", tags=["system"])

KEY_ENV_VARS = {
    "mcp-virustotal": "VIRUSTOTAL_API_KEY",
    "mcp-shodan": "SHODAN_API_KEY",
    "mcp-abuseipdb": "ABUSEIPDB_API_KEY",
    "mcp-hibp": "HIBP_API_KEY",
    "mcp-opencnam": "OPENCNAM_API_KEY",
    "mcp-otx": "OTX_API_KEY",
    "mcp-urlscan": "URLSCAN_API_KEY",
}

# Adapters that operate fully (or with graceful degradation) without a key.
ALWAYS_LIVE = {"mcp-rdap", "mcp-urlscan", "mcp-social"}


@router.get("/providers", response_model=list[dict])
async def system_providers(
    user: CurrentUser = Depends(get_current_user),
    orchestrator=Depends(get_orchestrator),
) -> list[dict]:
    settings = get_settings()
    coverage = orchestrator.provider_coverage()
    modes = orchestrator.provider_modes()
    return [
        {
            "name": name,
            "mode": modes.get(name, "mock"),
            "ioc_types": coverage.get(name, []),
            "key_env_var": KEY_ENV_VARS.get(name),
            "configured": _is_configured(name, settings),
        }
        for name in sorted(coverage)
    ]


def _is_configured(name: str, settings) -> bool:
    if name in ALWAYS_LIVE:
        return True
    env_var = KEY_ENV_VARS.get(name)
    if env_var is None:
        return True
    return bool(getattr(settings, env_var.lower(), None))
