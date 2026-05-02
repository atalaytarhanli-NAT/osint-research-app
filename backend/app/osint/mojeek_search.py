"""Mojeek arama — bağımsız crawler, kendi index'i, anti-bot toleransı yüksek."""

from __future__ import annotations

import logging
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.mojeek")


async def search_mojeek(query: str, max_results: int = 12) -> list[SourceResult]:
    url = f"https://www.mojeek.com/search?q={quote_plus(query)}&fmt=html"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            html = r.text
    except Exception as exc:
        log.warning("Mojeek search failed: %s", exc)
        return []

    soup = BeautifulSoup(html, "lxml")
    results: list[SourceResult] = []

    for li in soup.select("ul.results-standard li, ul li.result, div.result")[:max_results]:
        a = li.select_one("h2 a, a.title, a.ob")
        snippet_el = li.select_one("p.s, p.snippet, div.snippet")
        if not a or not a.get("href"):
            continue
        href = a["href"]
        if not href.startswith("http"):
            continue
        title = a.get_text(" ", strip=True)
        snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
        results.append(
            SourceResult(
                source="mojeek",
                url=href,
                title=safe_truncate(title, 240),
                snippet=safe_truncate(snippet, 320),
                kind="web",
                confidence=0.5,
            )
        )

    return results
