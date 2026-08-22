"""Social presence adapter (GitHub / Reddit / Telegram).

Real adapter implementing the McpClient contract without any API key: it
checks whether a handle exists on public platforms. Presence alone is an
attribution signal, not a maliciousness verdict, so the reputation score
stays at 0 and per-platform results land in ``raw`` and ``relationships``.
Failures on one platform never break the others.
"""

import asyncio
import re

import httpx

from app.domain.ioc.types import IocType, ParsedIoc
from app.schemas.investigation import McpObservation

USER_AGENT = "huntdeck-osint-hub"
TELEGRAM_TITLE_RE = re.compile(r'class="tgme_page_title[^"]*"[^>]*>(.*?)</div>', re.DOTALL)


class SocialPresenceMcpClient:
    """Real social presence adapter (no API key required)."""

    name = "mcp-social"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=8.0)

    async def query(self, ioc: ParsedIoc) -> McpObservation:
        if ioc.type != IocType.SOCIAL_HANDLE:
            return McpObservation(
                source=self.name,
                raw={"error": "social_unsupported_ioc", "mock": False},
            )

        username = ioc.normalized.split("/")[-1].lstrip("@")
        github, reddit, telegram = await asyncio.gather(
            self._check_github(username),
            self._check_reddit(username),
            self._check_telegram(username),
        )
        platforms = {"github": github, "reddit": reddit, "telegram": telegram}
        found = [name for name, result in platforms.items() if result.get("exists")]

        return McpObservation(
            source=self.name,
            raw={
                "entity": ioc.normalized,
                "entity_type": ioc.type,
                "mock": False,
                "handle": username,
                "platforms": platforms,
            },
            reputation={
                "score": 0,
                "verdict": "unknown",
                "tags": [f"social:found:{name}" for name in found] or ["social:not-found"],
            },
            relationships=[
                {"kind": "presence", "target": f"{name}.com/{username}"} for name in found
            ],
        )

    async def _check_github(self, username: str) -> dict:
        try:
            response = await self._client.get(
                f"https://api.github.com/users/{username}",
                headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
            )
            if response.status_code == 404:
                return {"exists": False}
            response.raise_for_status()
            data = response.json()
            return {
                "exists": True,
                "name": data.get("name"),
                "followers": data.get("followers"),
                "public_repos": data.get("public_repos"),
            }
        except httpx.HTTPStatusError as exc:
            return {"exists": False, "error": f"github_http_{exc.response.status_code}"}
        except httpx.RequestError:
            return {"exists": False, "error": "github_unreachable"}

    async def _check_reddit(self, username: str) -> dict:
        try:
            response = await self._client.get(
                f"https://www.reddit.com/user/{username}/about.json",
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            if response.status_code == 404:
                return {"exists": False}
            response.raise_for_status()
            data = response.json().get("data") or {}
            return {
                "exists": bool(data.get("name")),
                "karma": (data.get("total_karma") or data.get("link_karma")),
            }
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            reason = {403: "blocked", 429: "rate_limited"}.get(status, f"http_{status}")
            return {"exists": False, "error": f"reddit_{reason}"}
        except httpx.RequestError:
            return {"exists": False, "error": "reddit_unreachable"}

    async def _check_telegram(self, username: str) -> dict:
        try:
            response = await self._client.get(
                f"https://t.me/{username}",
                headers={"User-Agent": USER_AGENT},
            )
            if response.status_code == 404:
                return {"exists": False}
            response.raise_for_status()
            match = TELEGRAM_TITLE_RE.search(response.text)
            if not match:
                return {"exists": False}
            title = re.sub(r"<[^>]+>", "", match.group(1)).strip()
            return {"exists": True, "title": title}
        except httpx.HTTPStatusError as exc:
            return {"exists": False, "error": f"telegram_http_{exc.response.status_code}"}
        except httpx.RequestError:
            return {"exists": False, "error": "telegram_unreachable"}
