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
from app.agents.mcp.blockscout import BlockscoutMcpClient
from app.agents.mcp.crtsh import CrtshMcpClient
from app.agents.mcp.dexscreener import DexscreenerMcpClient
from app.agents.mcp.etherscan import EtherscanMcpClient
from app.agents.mcp.goplus import GoplusMcpClient
from app.agents.mcp.greynoise import GreynoiseMcpClient
from app.agents.mcp.hibp import HibpMcpClient
from app.agents.mcp.hunterio import HunterioMcpClient
from app.agents.mcp.intelx import IntelxMcpClient
from app.agents.mcp.mempool import MempoolspaceMcpClient
from app.agents.mcp.misp import MispMcpClient
from app.agents.mcp.opencnam import OpenCnamMcpClient
from app.agents.mcp.opencti import OpenCtiMcpClient
from app.agents.mcp.otx import OtxMcpClient
from app.agents.mcp.rdap import RdapMcpClient
from app.agents.mcp.shodan import ShodanMcpClient
from app.agents.mcp.social import SocialPresenceMcpClient
from app.agents.mcp.solana import SolanaMcpClient
from app.agents.mcp.threatfox import ThreatfoxMcpClient
from app.agents.mcp.urlhaus import UrlHausMcpClient
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


def _opencti(settings: Settings) -> object | None:
    if settings.opencti_url and settings.opencti_api_key:
        return OpenCtiMcpClient(base_url=settings.opencti_url, api_key=settings.opencti_api_key)
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
    ("mcp-opencti", _opencti, "example.com"),
    ("mcp-urlhaus", _keyed(UrlHausMcpClient, "urlhaus_api_key"), "http://w-diarium.pw/malware.exe"),
    ("mcp-intelx", _keyed(IntelxMcpClient, "intelx_api_key"), "8.8.8.8"),
    ("mcp-hunterio", _keyed(HunterioMcpClient, "hunterio_api_key"), "test@example.com"),
    ("mcp-crtsh", lambda _s: CrtshMcpClient(), "example.com"),
    (
        "mcp-threatfox",
        _keyed(ThreatfoxMcpClient, "threatfox_api_key"),
        "http://w-diarium.pw/malware.exe",
    ),
    (
        "mcp-blockscout",
        lambda _s: BlockscoutMcpClient(),
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    ),
    (
        "mcp-mempoolspace",
        lambda _s: MempoolspaceMcpClient(),
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    ),
    ("mcp-goplus", lambda _s: GoplusMcpClient(), "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"),
    (
        "mcp-dexscreener",
        lambda _s: DexscreenerMcpClient(),
        "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",
    ),
    ("mcp-solana", lambda _s: SolanaMcpClient(), "So11111111111111111111111111111111111111112"),
    (
        "mcp-etherscan",
        _keyed(EtherscanMcpClient, "etherscan_api_key"),
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    ),
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
