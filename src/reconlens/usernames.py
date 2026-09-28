"""Checks whether a username is registered on public platforms.

Only endpoints that are public, need no login and have a clear "not found"
signal are used. Platforms that require authentication or actively block
automated requests (Instagram, X, VK, ...) are deliberately left out.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from reconlens.errors import InvalidTargetError
from reconlens.models import LookupReport, LookupSection
from reconlens.scanner import DEFAULT_HEADERS

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,39}$")

Rule = Callable[[httpx.Response], bool | None]


_CHALLENGE_RE = re.compile(
    r"<title>\s*(?:client challenge|just a moment|attention required|ddos-guard)", re.I
)


def is_bot_challenge(resp: httpx.Response) -> bool:
    """Anti-bot interstitials often answer 200 and must not be read as 'profile exists'."""
    if "text/html" not in resp.headers.get("content-type", ""):
        return False
    return bool(_CHALLENGE_RE.search(resp.text[:5000]))


def by_status(resp: httpx.Response) -> bool | None:
    if resp.status_code == 200:
        return True
    if resp.status_code in (404, 410):
        return False
    return None


def json_not_null(resp: httpx.Response) -> bool | None:
    if resp.status_code != 200:
        return None
    return resp.json() is not None


def json_nonempty_list(resp: httpx.Response) -> bool | None:
    if resp.status_code != 200:
        return None
    return bool(resp.json())


def codeforces(resp: httpx.Response) -> bool | None:
    try:
        return resp.json().get("status") == "OK"
    except ValueError:
        return None


def keybase(resp: httpx.Response) -> bool | None:
    if resp.status_code != 200:
        return None
    them = resp.json().get("them") or [None]
    return them[0] is not None


def text_absent(marker: str) -> Rule:
    """Found when ``marker`` (a 'not found' phrase) is absent from a 200 response."""

    def rule(resp: httpx.Response) -> bool | None:
        if resp.status_code != 200:
            return by_status(resp)
        return marker not in resp.text

    return rule


def text_present(marker: str) -> Rule:
    """Found when ``marker`` (a 'profile exists' token) is present in a 200 response."""

    def rule(resp: httpx.Response) -> bool | None:
        if resp.status_code != 200:
            return by_status(resp)
        return marker in resp.text

    return rule


@dataclass(frozen=True)
class Site:
    name: str
    check_url: str
    profile_url: str
    rule: Rule = by_status
    category: str = "Other"


SITES: tuple[Site, ...] = (
    # --- Development ----------------------------------------------------------
    Site("GitHub", "https://api.github.com/users/{}", "https://github.com/{}", category="Dev"),
    Site(
        "GitLab",
        "https://gitlab.com/api/v4/users?username={}",
        "https://gitlab.com/{}",
        json_nonempty_list,
        category="Dev",
    ),
    Site(
        "Codeberg",
        "https://codeberg.org/api/v1/users/{}",
        "https://codeberg.org/{}",
        category="Dev",
    ),
    Site(
        "Docker Hub",
        "https://hub.docker.com/v2/users/{}/",
        "https://hub.docker.com/u/{}",
        category="Dev",
    ),
    Site("PyPI", "https://pypi.org/user/{}/", "https://pypi.org/user/{}/", category="Dev"),
    Site(
        "Replit",
        "https://replit.com/@{}",
        "https://replit.com/@{}",
        text_absent("404"),
        category="Dev",
    ),
    Site(
        "DEV Community",
        "https://dev.to/api/users/by_username?url={}",
        "https://dev.to/{}",
        category="Dev",
    ),
    # --- Competitive programming ---------------------------------------------
    Site(
        "Codeforces",
        "https://codeforces.com/api/user.info?handles={}",
        "https://codeforces.com/profile/{}",
        codeforces,
        category="CP",
    ),
    Site(
        "Codewars",
        "https://www.codewars.com/api/v1/users/{}",
        "https://www.codewars.com/users/{}",
        category="CP",
    ),
    Site(
        "AtCoder",
        "https://atcoder.jp/users/{}",
        "https://atcoder.jp/users/{}",
        category="CP",
    ),
    Site(
        "LeetCode",
        "https://leetcode.com/{}/",
        "https://leetcode.com/{}/",
        text_absent("Page Not Found"),
        category="CP",
    ),
    # --- Community / social (public, no login) --------------------------------
    Site(
        "Habr",
        "https://habr.com/ru/users/{}/",
        "https://habr.com/ru/users/{}/",
        category="Community",
    ),
    Site(
        "Pikabu",
        "https://pikabu.ru/@{}",
        "https://pikabu.ru/@{}",
        text_absent("Такая страница не найдена"),
        category="Community",
    ),
    Site(
        "Reddit",
        "https://www.reddit.com/user/{}/about.json",
        "https://www.reddit.com/user/{}",
        json_not_null,
        category="Community",
    ),
    Site(
        "Hacker News",
        "https://hacker-news.firebaseio.com/v0/user/{}.json",
        "https://news.ycombinator.com/user?id={}",
        json_not_null,
        category="Community",
    ),
    Site(
        "Keybase",
        "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}",
        "https://keybase.io/{}",
        keybase,
        category="Community",
    ),
    Site(
        "Telegram",
        "https://t.me/{}",
        "https://t.me/{}",
        text_present("tgme_page_title"),  # public channel/user preview only
        category="Community",
    ),
    Site(
        "Last.fm",
        "https://www.last.fm/user/{}",
        "https://www.last.fm/user/{}",
        category="Community",
    ),
    # --- Media / creative -----------------------------------------------------
    Site(
        "Gravatar",
        "https://gravatar.com/{}.json",
        "https://gravatar.com/{}",
        by_status,
        category="Media",
    ),
    Site(
        "SoundCloud",
        "https://soundcloud.com/{}",
        "https://soundcloud.com/{}",
        category="Media",
    ),
    Site(
        "Behance",
        "https://www.behance.net/{}",
        "https://www.behance.net/{}",
        category="Media",
    ),
    # --- Gaming ---------------------------------------------------------------
    Site(
        "Chess.com",
        "https://api.chess.com/pub/player/{}",
        "https://www.chess.com/member/{}",
        category="Gaming",
    ),
    Site(
        "Lichess", "https://lichess.org/api/user/{}", "https://lichess.org/@/{}", category="Gaming"
    ),
    Site(
        "Steam",
        "https://steamcommunity.com/id/{}",
        "https://steamcommunity.com/id/{}",
        text_absent("The specified profile could not be found"),
        category="Gaming",
    ),
)


@dataclass(frozen=True)
class UsernameResult:
    site: str
    url: str
    status: str  # "found" | "not found" | "unknown"
    detail: str = ""
    category: str = "Other"


def validate_username(username: str) -> str:
    username = username.strip().lstrip("@")
    if not USERNAME_RE.match(username):
        raise InvalidTargetError(
            f"'{username}' is not a valid username (letters, digits, '_', '.', '-'; up to 39)"
        )
    return username


async def _check(
    client: httpx.AsyncClient, site: Site, username: str, semaphore: asyncio.Semaphore
) -> UsernameResult:
    profile = site.profile_url.format(username)
    try:
        async with semaphore:
            resp = await client.get(site.check_url.format(username))
        if is_bot_challenge(resp):
            return UsernameResult(site.name, profile, "unknown", "bot challenge", site.category)
        verdict = site.rule(resp)
    except (httpx.HTTPError, ValueError) as exc:
        return UsernameResult(site.name, profile, "unknown", type(exc).__name__, site.category)
    if verdict is None:
        return UsernameResult(
            site.name, profile, "unknown", f"HTTP {resp.status_code}", site.category
        )
    status = "found" if verdict else "not found"
    return UsernameResult(site.name, profile, status, "", site.category)


async def check_username(
    username: str, *, timeout: float = 10.0, concurrency: int = 15
) -> list[UsernameResult]:
    username = validate_username(username)
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, headers=DEFAULT_HEADERS
    ) as client:
        return list(await asyncio.gather(*(_check(client, s, username, semaphore) for s in SITES)))


def username_report(username: str, results: list[UsernameResult]) -> LookupReport:
    """Turn raw username results into a shareable report object."""
    found = [r for r in results if r.status == "found"]
    rows = [
        {"site": r.site, "category": r.category, "status": r.status, "profile": r.url}
        for r in sorted(results, key=lambda r: (r.status != "found", r.category, r.site.lower()))
    ]
    return LookupReport(
        kind="username",
        target=username,
        summary={
            "Found on": f"{len(found)} of {len(results)} sites",
            "Platforms checked": len(results),
        },
        sections=[LookupSection("Platforms", rows=rows)],
        notes=[
            "A 'found' result means a public page exists at that URL for this name. It does NOT "
            "prove the same person owns every account — names collide across sites."
        ],
        disclaimer=(
            "Only public profile pages are checked, the same way a browser would open them. "
            "Use for a lawful purpose such as auditing your own digital footprint."
        ),
    )
