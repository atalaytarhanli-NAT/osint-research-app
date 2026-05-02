"""Yandex arama — HTML scrape, anahtar gerektirmez.

Bot-friendly olduğu için DDG/Bing block ettiğinde fallback olarak iyi.
Türkçe ve Rusça sorgularda ayrıca güçlü."""

from __future__ import annotations

import logging
from urllib.parse import quote_plus, parse_qs, urlparse

import httpx
from bs4 import BeautifulSoup

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.yandex")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


async def search_yandex(query: str, max_results: int = 12) -> list[SourceResult]:
    url = f"https://yandex.com/search/?text={quote_plus(query)}"
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,tr;q=0.8",
    }
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            html = r.text
    except Exception as exc:
        log.warning("Yandex search failed: %s", exc)
        return []

    soup = BeautifulSoup(html, "lxml")
    results: list[SourceResult] = []

    # Yandex SERP modern: li.serp-item with .organic, span.organic__url, h2/a, div.text-container
    for li in soup.select("li.serp-item, .organic")[:max_results]:
        a = li.select_one("h2 a, a.organic__url, a.OrganicTitle-Link")
        snippet_el = li.select_one(".text-container, .organic__content-wrapper, .organic__text")
        if not a or not a.get("href"):
            continue
        href = a["href"]
        # Yandex sometimes wraps in /clck/redir/... — extract the real URL from query string
        if "/clck/" in href or "yabs.yandex" in href:
            qs = parse_qs(urlparse(href).query)
            if "url" in qs:
                href = qs["url"][0]
            elif "uri" in qs:
                href = qs["uri"][0]
        if not href.startswith("http"):
            continue

        title = a.get_text(" ", strip=True)
        snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
        results.append(
            SourceResult(
                source="yandex",
                url=href,
                title=safe_truncate(title, 240),
                snippet=safe_truncate(snippet, 320),
                kind="web",
                confidence=0.5,
            )
        )

    return results
