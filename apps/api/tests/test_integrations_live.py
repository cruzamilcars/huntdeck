"""Live contract tests for real adapters.

Skipped unless the matching API key is configured, so the default suite stays
offline and deterministic. Run explicitly with:

    python -m pytest -m integration -v

Each test asserts the real API accepts the adapter's request shape and that
the adapter produces a structured observation (no exception, error field set
on failure).
"""

import pytest

from app.agents.mcp.abuseipdb import AbuseIpdbMcpClient
from app.agents.mcp.hibp import HibpMcpClient
from app.agents.mcp.opencnam import OpenCnamMcpClient
from app.agents.mcp.rdap import RdapMcpClient
from app.agents.mcp.shodan import ShodanMcpClient
from app.agents.mcp.urlscan import UrlScanMcpClient
from app.agents.mcp.virustotal import VirusTotalMcpClient
from app.core.config import get_settings
from app.domain.ioc.parser import parse_ioc

pytestmark = pytest.mark.integration


def _requires(settings_name: str):
    key = getattr(get_settings(), settings_name)
    return pytest.mark.skipif(not key, reason=f"{settings_name.upper()} not configured")


async def _assert_responds(client, raw_ioc: str) -> None:
    observation = await client.query(parse_ioc(raw_ioc))
    assert observation.source
    if observation.raw and observation.raw.get("error"):
        # Structured failure is acceptable (rate limit, unknown IOC) — but
        # the raw payload must still mark the adapter as real.
        assert observation.raw.get("mock") is False
    else:
        assert observation.reputation is not None
        assert observation.reputation.get("score", 0) >= 0


@_requires("virustotal_api_key")
async def test_virustotal_ip_live() -> None:
    settings = get_settings()
    await _assert_responds(VirusTotalMcpClient(api_key=settings.virustotal_api_key), "8.8.8.8")


@_requires("virustotal_api_key")
async def test_virustotal_hash_live() -> None:
    settings = get_settings()
    await _assert_responds(
        VirusTotalMcpClient(api_key=settings.virustotal_api_key),
        "44d88612fea8a8f36de82e1278abb02f",
    )


@_requires("abuseipdb_api_key")
async def test_abuseipdb_ip_live() -> None:
    settings = get_settings()
    await _assert_responds(AbuseIpdbMcpClient(api_key=settings.abuseipdb_api_key), "8.8.8.8")


@_requires("shodan_api_key")
async def test_shodan_ip_live() -> None:
    settings = get_settings()
    await _assert_responds(ShodanMcpClient(api_key=settings.shodan_api_key), "8.8.8.8")


@_requires("urlscan_api_key")
async def test_urlscan_domain_live() -> None:
    settings = get_settings()
    await _assert_responds(UrlScanMcpClient(api_key=settings.urlscan_api_key), "example.com")


async def test_urlscan_anonymous_live() -> None:
    await _assert_responds(UrlScanMcpClient(), "example.com")


async def test_rdap_domain_live() -> None:
    await _assert_responds(RdapMcpClient(), "example.com")


@_requires("hibp_api_key")
async def test_hibp_email_live() -> None:
    settings = get_settings()
    await _assert_responds(HibpMcpClient(api_key=settings.hibp_api_key), "test@example.com")


@_requires("opencnam_api_key")
async def test_opencnam_phone_live() -> None:
    settings = get_settings()
    await _assert_responds(OpenCnamMcpClient(api_key=settings.opencnam_api_key), "+15555550101")
