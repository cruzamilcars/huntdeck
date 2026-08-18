import httpx

from app.agents.mcp.rdap import RdapMcpClient
from app.domain.ioc.parser import parse_ioc


def _sample_rdap() -> dict:
    return {
        "rdapConformance": ["rdap_level_0"],
        "registrationDate": "2010-01-01T00:00:00Z",
        "expirationDate": "2027-01-01T00:00:00Z",
        "nameservers": [{"ldhName": "ns1.example.com"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]],
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["adr", {}, "text", {"value": ["", "", "", "", "", "US"]}],
                    ],
                ],
            },
        ],
    }


def test_rdap_domain_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/domain/example.com"
        return httpx.Response(200, json=_sample_rdap())

    transport = httpx.MockTransport(handler)
    client = RdapMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url="https://rdap.org")
    )

    import asyncio

    observation = asyncio.run(client.query(parse_ioc("example.com")))

    assert observation.source == "mcp-rdap"
    assert observation.reputation["registrar"] == "Example Registrar"
    assert observation.reputation["nameservers"] == ["ns1.example.com"]
    assert observation.reputation["dates"]["expirationDate"] == "2027-01-01T00:00:00Z"
    assert observation.geolocation == {"country": "US"}


def test_rdap_ip_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/ip/8.8.8.8"
        return httpx.Response(200, json={"entities": [], "nameservers": []})

    transport = httpx.MockTransport(handler)
    client = RdapMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url="https://rdap.org")
    )

    import asyncio

    observation = asyncio.run(client.query(parse_ioc("8.8.8.8")))

    assert observation.reputation["tags"] == ["rdap:registered"]


def test_rdap_not_found_is_structured_observation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errorCode": 404, "title": "Not found"})

    transport = httpx.MockTransport(handler)
    client = RdapMcpClient(
        client=httpx.AsyncClient(transport=transport, base_url="https://rdap.org")
    )

    import asyncio

    observation = asyncio.run(client.query(parse_ioc("notregistered.example")))

    assert observation.reputation["tags"] == ["rdap:not_found"]
    assert observation.reputation["score"] == 0


def test_rdap_unsupported_ioc_type() -> None:
    import asyncio

    client = RdapMcpClient()
    observation = asyncio.run(client.query(parse_ioc("44d88612fea8a8f36de82e1278abb02f")))

    assert observation.reputation["tags"] == ["rdap:unsupported_ioc"]
