from fastapi.testclient import TestClient

from app.main import create_app


def test_providers_reports_modes_and_coverage() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/system/providers")

    assert response.status_code == 200
    providers = {provider["name"]: provider for provider in response.json()}

    # Always-live adapters report real without any key configured.
    for name in ("mcp-rdap", "mcp-urlscan", "mcp-social"):
        assert providers[name]["mode"] == "real", name
        assert providers[name]["configured"] is True
        assert providers[name]["key_env_var"] is None or name == "mcp-urlscan"

    # Key-gated adapters default to mock with a hint of which env var to set.
    vt = providers["mcp-virustotal"]
    assert vt["mode"] == "mock"
    assert vt["key_env_var"] == "VIRUSTOTAL_API_KEY"
    assert vt["configured"] is False

    # Coverage is derived from actual routing, never drifts.
    assert set(vt["ioc_types"]) == {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    assert set(providers["mcp-hibp"]["ioc_types"]) == {"email"}
    assert set(providers["mcp-opencnam"]["ioc_types"]) == {"phone"}
    assert set(providers["mcp-social"]["ioc_types"]) == {"social_handle"}


def test_providers_urlscan_configured_without_key() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/system/providers")
    urlscan = next(p for p in response.json() if p["name"] == "mcp-urlscan")

    assert urlscan["mode"] == "real"
    assert urlscan["configured"] is True
    assert urlscan["key_env_var"] == "URLSCAN_API_KEY"
