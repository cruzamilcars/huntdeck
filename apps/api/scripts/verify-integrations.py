"""Verify live third-party integrations.

Probes every real adapter against its live API using the keys configured in
the environment (apps/api/.env). Never prints keys. Exits non-zero when a
configured integration fails to respond.

Usage (from apps/api):
    python scripts/verify-integrations.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.mcp.abuseipdb import AbuseIpdbMcpClient
from app.agents.mcp.hibp import HibpMcpClient
from app.agents.mcp.opencnam import OpenCnamMcpClient
from app.agents.mcp.rdap import RdapMcpClient
from app.agents.mcp.shodan import ShodanMcpClient
from app.agents.mcp.urlscan import UrlScanMcpClient
from app.agents.mcp.virustotal import VirusTotalMcpClient
from app.core.config import get_settings
from app.domain.ioc.parser import parse_ioc

PROBES = [
    ("mcp-virustotal", VirusTotalMcpClient, "virustotal_api_key", "8.8.8.8", False),
    ("mcp-abuseipdb", AbuseIpdbMcpClient, "abuseipdb_api_key", "8.8.8.8", False),
    ("mcp-shodan", ShodanMcpClient, "shodan_api_key", "8.8.8.8", False),
    ("mcp-urlscan", UrlScanMcpClient, "urlscan_api_key", "example.com", True),
    ("mcp-rdap", RdapMcpClient, None, "example.com", True),
    ("mcp-hibp", HibpMcpClient, "hibp_api_key", "test@example.com", False),
    ("mcp-opencnam", OpenCnamMcpClient, "opencnam_api_key", "+15555550101", False),
]


async def _probe(name: str, client_cls: type, key: str | None, sample: str) -> dict:
    client = client_cls(api_key=key) if key else client_cls()
    observation = await client.query(parse_ioc(sample))
    raw = observation.raw or {}
    if raw.get("error"):
        return {"name": name, "status": "error", "detail": raw["error"]}
    if observation.reputation and observation.reputation.get("score", 0) is not None:
        verdict = observation.reputation.get("verdict", "unknown")
        return {
            "name": name,
            "status": "ok",
            "detail": f"verdict={verdict} score={observation.reputation.get('score', 0)}",
        }
    return {"name": name, "status": "ok", "detail": "responded"}


async def main() -> int:
    settings = get_settings()
    checks: list[dict] = []
    for name, client_cls, setting_name, sample, always in PROBES:
        key = getattr(settings, setting_name) if setting_name else None
        if not key and not always:
            checks.append({"name": name, "status": "skipped", "detail": "no API key configured"})
            continue
        try:
            checks.append(await _probe(name, client_cls, key, sample))
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
