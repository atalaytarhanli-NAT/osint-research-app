"""GitHub açık search API — anahtarsız 60 req/saat."""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.github")


async def search_github(query: str, max_users: int = 8, max_repos: int = 12) -> list[SourceResult]:
    out: list[SourceResult] = []
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "OsintResearchApp/1.0"}
    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as c:
            # Users
            ur = await c.get(
                "https://api.github.com/search/users",
                params={"q": query, "per_page": max_users},
            )
            if ur.status_code == 200:
                for it in ur.json().get("items", []):
                    out.append(
                        SourceResult(
                            source="github_user",
                            url=it.get("html_url", ""),
                            title=it.get("login", ""),
                            snippet=f"GitHub user: {it.get('login','')} (id {it.get('id')})",
                            kind="profile",
                            confidence=0.55,
                        )
                    )
            # Repos
            rr = await c.get(
                "https://api.github.com/search/repositories",
                params={"q": query, "per_page": max_repos, "sort": "stars"},
            )
            if rr.status_code == 200:
                for it in rr.json().get("items", []):
                    out.append(
                        SourceResult(
                            source="github_repo",
                            url=it.get("html_url", ""),
                            title=it.get("full_name", ""),
                            snippet=safe_truncate(it.get("description") or "", 240),
                            published_at=(it.get("created_at") or "")[:10] or None,
                            kind="code",
                            confidence=0.6,
                            raw={"stars": it.get("stargazers_count", 0)},
                        )
                    )
    except Exception as exc:
        log.warning("GitHub search failed: %s", exc)
    return out
