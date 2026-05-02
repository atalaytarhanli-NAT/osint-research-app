"""DuckDuckGo HTML search — açık endpoint, anahtar gerektirmez.

DDG arka planda Bing index'i kullanır. Render IP'lerinde captcha yiyince
TR locale (kl=tr-tr) + UA rotation + lite endpoint fallback denenir."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.web")

DDG_URL = "https://html.duckduckgo.com/html/"
DDG_LITE_URL = "https://lite.duckduckgo.com/lite/"
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
]


def _parse_ddg_html(html: str, max_results: int) -> list[SourceResult]:
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


def _parse_ddg_lite(html: str, max_results: int) -> list[SourceResult]:
    """DDG lite endpoint farklı HTML yapısı kullanır (eski tablo bazlı)."""
    soup = BeautifulSoup(html, "lxml")
    results: list[SourceResult] = []
    # Lite version: <a class="result-link"> içinde href, snippet alt satırda
    for a in soup.select("a.result-link, a[class*=result]")[:max_results]:
        href = a.get("href") or ""
        if "/l/?" in href:
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(href).query)
            href = qs.get("uddg", [href])[0]
        if not href.startswith("http"):
            continue
        title = a.get_text(strip=True)
        if not title:
            continue
        # Snippet — sonraki kardeş <td class="result-snippet">
        snippet_td = a.find_next("td", class_="result-snippet")
        snippet = snippet_td.get_text(" ", strip=True) if snippet_td else ""
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


async def search_web(query: str, max_results: int = 18) -> list[SourceResult]:
    ua = random.choice(UA_POOL)
    headers_base = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
    }

    # Pass 1: TR locale
    params = {"q": query, "kl": "tr-tr"}
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.post(
                DDG_URL, data=params,
                headers={**headers_base, "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7"},
            )
            if resp.status_code == 200:
                results = _parse_ddg_html(resp.text, max_results)
                if results:
                    return results
                log.info("DDG pass1 (tr-tr) parsed 0, trying wt-wt")
            else:
                log.info("DDG pass1 status=%s", resp.status_code)
    except Exception as exc:
        log.warning("DDG pass1 failed: %s", exc)

    # Pass 2: wt-wt locale (worldwide)
    params2 = {"q": query, "kl": "wt-wt"}
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.post(
                DDG_URL, data=params2,
                headers={**headers_base, "User-Agent": random.choice(UA_POOL),
                         "Accept-Language": "en-US,en;q=0.9"},
            )
            if resp.status_code == 200:
                results = _parse_ddg_html(resp.text, max_results)
                if results:
                    return results
                log.info("DDG pass2 (wt-wt) parsed 0, trying lite endpoint")
    except Exception as exc:
        log.warning("DDG pass2 failed: %s", exc)

    # Pass 3: lite.duckduckgo.com — minimal HTML, captcha yedek
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.post(
                DDG_LITE_URL,
                data={"q": query, "kl": "tr-tr"},
                headers={**headers_base, "User-Agent": random.choice(UA_POOL),
                         "Accept-Language": "tr-TR,en;q=0.7"},
            )
            if resp.status_code == 200:
                return _parse_ddg_lite(resp.text, max_results)
    except Exception as exc:
        log.warning("DDG lite failed: %s", exc)

    return []


async def search_news(query: str, max_results: int = 12) -> list[SourceResult]:
    """News-flavored search — TR + EN siteler paralel.

    DDG'nin OR-list'i çok uzun olunca tek sorgu olarak kabul etmiyor; bu yüzden
    TR ve EN için iki ayrı arama yapıp birleştiriyoruz."""
    tr_query = (
        f'{query} (site:hurriyet.com.tr OR site:milliyet.com.tr OR site:sabah.com.tr '
        f'OR site:haberturk.com OR site:sozcu.com.tr OR site:cumhuriyet.com.tr '
        f'OR site:ntv.com.tr OR site:cnnturk.com OR site:t24.com.tr '
        f'OR site:gazeteduvar.com.tr OR site:bbc.com/turkce OR site:dw.com/tr '
        f'OR site:bianet.org OR site:posta.com.tr OR site:karar.com)'
    )
    en_query = (
        f'{query} (site:reuters.com OR site:apnews.com OR site:bbc.com OR site:nytimes.com '
        f'OR site:bloomberg.com OR site:wsj.com OR site:ft.com OR site:guardian.co.uk '
        f'OR site:hurriyetdailynews.com OR site:dailysabah.com OR site:trtworld.com '
        f'OR site:aljazeera.com OR site:dw.com OR site:politico.eu)'
    )
    tr_items, en_items = await asyncio.gather(
        search_web(tr_query, max_results=max_results // 2 + 2),
        search_web(en_query, max_results=max_results // 2 + 2),
    )
    items = (tr_items or []) + (en_items or [])
    for item in items:
        item.source = "news"
        item.kind = "news"
        item.confidence = 0.7
    return items[:max_results + 4]
