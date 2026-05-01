"""DuckDuckGo HTML search — açık endpoint, anahtar gerektirmez."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.web")

DDG_URL = "https://html.duckduckgo.com/html/"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


async def search_web(query: str, max_results: int = 18) -> list[SourceResult]:
    params = {"q": query, "kl": "wt-wt"}
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}

    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.post(DDG_URL, data=params, headers=headers)
            resp.raise_for_status()
            html = resp.text
    except Exception as exc:
        log.warning("DDG search failed: %s", exc)
        return []

    soup = BeautifulSoup(html, "lxml")
    results: list[SourceResult] = []
    for block in soup.select("div.result")[:max_results]:
        a = block.select_one("a.result__a")
        snippet_el = block.select_one("a.result__snippet, div.result__snippet")
        if not a:
            continue
        href = a.get("href") or ""
        title = a.get_text(strip=True)
        snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""

        # DDG often wraps URLs in /l/?uddg=... — extract the real URL
        if "/l/?" in href:
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(href).query)
            href = qs.get("uddg", [href])[0]

        if not href.startswith("http"):
            continue

        results.append(
            SourceResult(
                source="duckduckgo",
                url=href,
                title=safe_truncate(title, 240),
                snippet=safe_truncate(snippet, 320),
                kind="web",
                confidence=0.55,
            )
        )

    return results


async def search_news(query: str, max_results: int = 12) -> list[SourceResult]:
    """News-flavored search by appending site filters."""
    news_query = (
        f'{query} (site:reuters.com OR site:apnews.com OR site:bbc.com OR site:nytimes.com '
        f'OR site:bloomberg.com OR site:wsj.com OR site:ft.com OR site:guardian.co.uk '
        f'OR site:hurriyetdailynews.com OR site:dailysabah.com OR site:trtworld.com '
        f'OR site:aljazeera.com OR site:dw.com OR site:lemonde.fr)'
    )
    items = await search_web(news_query, max_results=max_results)
    for item in items:
        item.source = "news"
        item.kind = "news"
        item.confidence = 0.7
    return items
