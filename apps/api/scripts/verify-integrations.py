"""Verify live third-party integrations.

Probes every real adapter against its live API using the credentials
configured in the environment (apps/api/.env). Never prints keys. Exits
non-zero when a configured integration fails to respond.

Usage (from apps/api):
    python scripts/verify-integrations.py
"""

import asyncio
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.mcp.abuseipdb import AbuseIpdbMcpClient
from app.agents.mcp.greynoise import GreynoiseMcpClient
from app.agents.mcp.hibp import HibpMcpClient
from app.agents.mcp.misp import MispMcpClient
from app.agents.mcp.opencnam import OpenCnamMcpClient
from app.agents.mcp.otx import OtxMcpClient
from app.agents.mcp.rdap import RdapMcpClient
from app.agents.mcp.shodan import ShodanMcpClient
from app.agents.mcp.social import SocialPresenceMcpClient
from app.agents.mcp.urlscan import UrlScanMcpClient
from app.agents.mcp.virustotal import VirusTotalMcpClient
from app.core.config import Settings, get_settings
from app.domain.ioc.parser import parse_ioc


def _keyed(cls, attr: str) -> Callable[[Settings], object | None]:
    return lambda settings: (
        cls(api_key=getattr(settings, attr)) if getattr(settings, attr) else None
    )


def _misp(settings: Settings) -> object | None:
    if settings.misp_url and settings.misp_api_key:
        return MispMcpClient(base_url=settings.misp_url, api_key=settings.misp_api_key)
    return None


PROBES = [
    ("mcp-virustotal", _keyed(VirusTotalMcpClient, "virustotal_api_key"), "8.8.8.8"),
    ("mcp-abuseipdb", _keyed(AbuseIpdbMcpClient, "abuseipdb_api_key"), "8.8.8.8"),
    ("mcp-shodan", _keyed(ShodanMcpClient, "shodan_api_key"), "8.8.8.8"),
    (
        "mcp-urlscan",
        lambda s: (
            UrlScanMcpClient(api_key=s.urlscan_api_key) if s.urlscan_api_key else UrlScanMcpClient()
        ),
        "example.com",
    ),
    ("mcp-rdap", lambda _s: RdapMcpClient(), "example.com"),
    ("mcp-hibp", _keyed(HibpMcpClient, "hibp_api_key"), "test@example.com"),
    ("mcp-opencnam", _keyed(OpenCnamMcpClient, "opencnam_api_key"), "+15555550101"),
    ("mcp-otx", _keyed(OtxMcpClient, "otx_api_key"), "8.8.8.8"),
    ("mcp-greynoise", _keyed(GreynoiseMcpClient, "greynoise_api_key"), "8.8.8.8"),
    ("mcp-social", lambda _s: SocialPresenceMcpClient(), "@octocat"),
    ("mcp-misp", _misp, "example.com"),
]


async def _probe(name: str, client: object, sample: str) -> dict:
    observation = await client.query(parse_ioc(sample))  # type: ignore[attr-defined]
    raw = observation.raw or {}
    if raw.get("error"):
        return {"name": name, "status": "error", "detail": raw["error"]}
    verdict = (observation.reputation or {}).get("verdict", "unknown")
    score = (observation.reputation or {}).get("score", 0)
    return {"name": name, "status": "ok", "detail": f"verdict={verdict} score={score}"}


async def main() -> int:
    settings = get_settings()
    checks: list[dict] = []
    for name, factory, sample in PROBES:
        client = factory(settings)
        if client is None:
            checks.append(
                {"name": name, "status": "skipped", "detail": "credentials not configured"}
            )
            continue
        try:
            checks.append(await _probe(name, client, sample))
        except Exception as exc:  # noqa: BLE001 - report and continue
            checks.append({"name": name, "status": "error", "detail": type(exc).__name__})

    width = max(len(check["name"]) for check in checks) + 2
    failures = 0
    for check in checks:
        print(f"{check['name'].ljust(width)} {check['status'].ljust(9)} {check['detail']}")
        if check["status"] == "error":
            failures += 1
    print(f"\n{len(checks) - failures}/{len(checks)} integrations responding")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
