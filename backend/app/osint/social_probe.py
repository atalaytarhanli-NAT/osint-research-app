"""Sherlock-style username probe — kullanıcı adı popüler platformlarda var mı?

Tüm istekler HEAD/GET ile yalnızca kamuya açık profil URL'lerini sorgular. Hiçbir
şifre/oturum bilgisi gerekmez."""

from __future__ import annotations

import asyncio
import logging
import re

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.social")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,40}$")

# (platform, url_template, expected_status, false_positive_marker)
PLATFORMS: list[tuple[str, str, int, str | None]] = [
    ("github", "https://github.com/{u}", 200, "Not Found"),
    ("twitter", "https://x.com/{u}", 200, "This account doesn’t exist"),
    ("instagram", "https://www.instagram.com/{u}/", 200, "Sorry, this page isn"),
    ("reddit", "https://www.reddit.com/user/{u}/about.json", 200, None),
    ("medium", "https://medium.com/@{u}", 200, "PAGE NOT FOUND"),
    ("dev_to", "https://dev.to/{u}", 200, "404"),
    ("gitlab", "https://gitlab.com/{u}", 200, "Page Not Found"),
    ("hackernews", "https://news.ycombinator.com/user?id={u}", 200, "No such user"),
    ("stackoverflow", "https://stackoverflow.com/users/filter?search={u}", 200, None),
    ("youtube", "https://www.youtube.com/@{u}", 200, "This page isn't available"),
    ("tiktok", "https://www.tiktok.com/@{u}", 200, "Couldn't find this account"),
    ("linkedin", "https://www.linkedin.com/in/{u}", 200, None),
    ("pinterest", "https://www.pinterest.com/{u}/", 200, "Sorry, we couldn"),
    ("vimeo", "https://vimeo.com/{u}", 200, "Page not found"),
    ("dribbble", "https://dribbble.com/{u}", 200, "Whoops, that page is gone"),
    ("behance", "https://www.behance.net/{u}", 200, "Oops! We can't find"),
    ("soundcloud", "https://soundcloud.com/{u}", 200, "We can’t find that user"),
    ("twitch", "https://www.twitch.tv/{u}", 200, "Sorry. Unless you"),
    ("keybase", "https://keybase.io/{u}", 200, "Sorry, no users by that name"),
    ("hashnode", "https://hashnode.com/@{u}", 200, "404"),
]


def _looks_like_username(target: str) -> bool:
    candidate = target.strip().lstrip("@")
    return bool(USERNAME_RE.match(candidate))


async def _probe_one(
    client: httpx.AsyncClient, platform: str, tpl: str, expected: int, fp: str | None, username: str
) -> SourceResult | None:
    url = tpl.format(u=username)
    try:
        r = await client.get(url, follow_redirects=True, timeout=8.0)
    except Exception as exc:
        log.debug("probe %s failed: %s", platform, exc)
        return None
    body = r.text[:8000] if r.headers.get("content-type", "").startswith(("text/", "application/json")) else ""
    if r.status_code != expected:
        return None
    if fp and fp.lower() in body.lower():
        return None
    return SourceResult(
        source=f"social:{platform}",
        url=url,
        title=f"@{username} on {platform}",
        snippet=safe_truncate(f"Profile candidate found on {platform}", 200),
        kind="profile",
        confidence=0.55,
        raw={"platform": platform, "status": r.status_code},
    )


async def probe_username(target: str) -> list[SourceResult]:
    candidate = target.strip().lstrip("@")
    if not _looks_like_username(candidate):
        return []
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    }
    async with httpx.AsyncClient(headers=headers, timeout=8.0) as c:
        coros = [_probe_one(c, p, t, s, fp, candidate) for p, t, s, fp in PLATFORMS]
        out = await asyncio.gather(*coros, return_exceptions=False)
    return [r for r in out if r is not None]
