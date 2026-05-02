"""Yandex arama — HTML scrape, anahtar gerektirmez.

Bot-friendly olduğu için DDG/Bing block ettiğinde fallback olarak iyi.
Türkçe ve Rusça sorgularda ayrıca güçlü. UA rotation + 3 endpoint fallback
(yandex.com → yandex.com.tr → yandex.ru)."""

from __future__ import annotations

import logging
import random
from urllib.parse import quote_plus, parse_qs, urlparse

import httpx
from bs4 import BeautifulSoup

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.yandex")


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
]


def _parse_yandex(html: str, max_results: int) -> list[SourceResult]:
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


async def _try_endpoint(endpoint: str, query: str, ua: str, accept_lang: str) -> str:
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": accept_lang,
        "DNT": "1",
    }
    url = f"{endpoint}?text={quote_plus(query)}"
    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as c:
        r = await c.get(url)
        if r.status_code != 200:
            log.info("yandex %s status=%s", endpoint, r.status_code)
            return ""
        return r.text


async def search_yandex(query: str, max_results: int = 12) -> list[SourceResult]:
    # 3 endpoint dene: yandex.com.tr (TR locale), yandex.com, yandex.ru
    endpoints = [
        ("https://yandex.com.tr/search/", "tr-TR,tr;q=0.9,en;q=0.7"),
        ("https://yandex.com/search/", "en-US,en;q=0.9,tr;q=0.8"),
        ("https://www.yandex.ru/search/", "ru-RU,ru;q=0.9,en;q=0.7,tr;q=0.5"),
    ]
    for endpoint, lang in endpoints:
        try:
            html = await _try_endpoint(endpoint, query, random.choice(UA_POOL), lang)
            if html:
                results = _parse_yandex(html, max_results)
                if results:
                    return results
                log.info("yandex %s parsed 0 results, trying next", endpoint)
        except Exception as exc:
            log.warning("yandex %s failed: %s", endpoint, exc)
    return []
