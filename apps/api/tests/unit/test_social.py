import httpx

from app.agents.mcp.social import SocialPresenceMcpClient
from app.domain.ioc.parser import parse_ioc


def build_client(handler) -> SocialPresenceMcpClient:
    return SocialPresenceMcpClient(client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def github_found() -> httpx.Response:
    return httpx.Response(
        200,
        json={"login": "octocat", "name": "The Octocat", "followers": 100, "public_repos": 8},
    )


async def test_handle_found_on_github_and_telegram() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        if request.url.host == "api.github.com":
            assert request.url.path == "/users/octocat"
            return github_found()
        if request.url.host == "t.me":
            assert request.url.path == "/octocat"
            return httpx.Response(
                200,
                text='<div class="tgme_page_title" dir="auto"><span>Octo Cat</span></div>',
            )
        if request.url.host == "www.reddit.com":
            return httpx.Response(404)
        raise AssertionError(f"unexpected host {request.url.host}")

    observation = await build_client(handler).query(parse_ioc("@octocat"))

    assert observation.source == "mcp-social"
    assert observation.raw["mock"] is False
    assert observation.raw["handle"] == "octocat"
    assert observation.raw["platforms"]["github"]["exists"] is True
    assert observation.raw["platforms"]["github"]["name"] == "The Octocat"
    assert observation.raw["platforms"]["telegram"]["title"] == "Octo Cat"
    assert observation.raw["platforms"]["reddit"] == {"exists": False}
    assert set(calls) == {"api.github.com", "t.me", "www.reddit.com"}
    assert observation.reputation["verdict"] == "unknown"
    assert sorted(observation.reputation["tags"]) == [
        "social:found:github",
        "social:found:telegram",
    ]
    assert {"kind": "presence", "target": "github.com/octocat"} in observation.relationships


async def test_profile_url_extracts_username() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            assert request.url.path == "/users/torvalds"
            return github_found()
        return httpx.Response(404)

    observation = await build_client(handler).query(parse_ioc("https://github.com/torvalds"))

    assert observation.raw["handle"] == "torvalds"
    assert "social:found:github" in observation.reputation["tags"]


async def test_not_found_anywhere_is_structured() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    observation = await build_client(handler).query(parse_ioc("@ghost-handle-xyz"))

    assert observation.reputation["tags"] == ["social:not-found"]
    assert observation.relationships == []
    assert all(p == {"exists": False} for p in observation.raw["platforms"].values())


async def test_platform_error_does_not_break_others() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.reddit.com":
            return httpx.Response(403)
        if request.url.host == "api.github.com":
            return github_found()
        return httpx.Response(404)

    observation = await build_client(handler).query(parse_ioc("@octocat"))

    assert observation.raw["platforms"]["reddit"] == {"exists": False, "error": "reddit_blocked"}
    assert "social:found:github" in observation.reputation["tags"]


async def test_unsupported_ioc_type_is_structured_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    observation = await build_client(handler).query(parse_ioc("8.8.8.8"))

    assert observation.raw["error"] == "social_unsupported_ioc"
    assert observation.reputation == {}
