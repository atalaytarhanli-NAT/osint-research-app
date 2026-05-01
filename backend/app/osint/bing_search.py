"""Bing arama — HTML scrape, anahtar gerektirmez."""

from __future__ import annotations

import logging
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.bing")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


async def search_bing(query: str, max_results: int = 12) -> list[SourceResult]:
    url = f"https://www.bing.com/search?q={quote_plus(query)}&count={max_results}&form=QBLH"
    headers = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            html = r.text
    except Exception as exc:
        log.warning("Bing search failed: %s", exc)
        return []

    soup = BeautifulSoup(html, "lxml")
    results: list[SourceResult] = []
    for li in soup.select("li.b_algo")[:max_results]:
        a = li.select_one("h2 a")
        snippet_el = li.select_one("div.b_caption p, p.b_lineclamp2, p.b_lineclamp3, p.b_lineclamp4")
        if not a or not a.get("href"):
            continue
        href = a["href"]
        if not href.startswith("http"):
            continue
        results.append(
            SourceResult(
                source="bing",
                url=href,
                title=safe_truncate(a.get_text(strip=True), 240),
                snippet=safe_truncate(snippet_el.get_text(" ", strip=True) if snippet_el else "", 320),
                kind="web",
                confidence=0.55,
            )
        )
    return results
