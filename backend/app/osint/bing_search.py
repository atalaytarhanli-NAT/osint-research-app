"""Bing arama — HTML scrape (Microsoft Bing Web Search API Aug 2025'te kapatıldı).

Render datacenter IP'lerinde Bing bazen captcha gönderir. Bu modül:
- TR/EN locale negotiation (mkt=tr-TR, sonra fallback en-US)
- UA pool (3 farklı, random) → bot fingerprint azaltma
- Çoklu selector fallback (b_algo → b_resultsParser → h2)
- Boş sonuç durumunda mobile.bing.com retry

Anahtar gerekmez. Render'da fail olursa Tavily/Serper/Google CSE öneri.
"""

from __future__ import annotations

import logging
import random
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.bing")


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
]


def _parse_bing_html(html: str, max_results: int) -> list[SourceResult]:
    soup = BeautifulSoup(html, "lxml")
    results: list[SourceResult] = []

    # Primary: li.b_algo (desktop standard)
    items = soup.select("li.b_algo")
    if not items:
        # Fallback: b_resultsParser veya genel li (HTML değişikliği için)
        items = soup.select("li.b_ans, ol#b_results > li")

    for li in items[:max_results]:
        # Title link: h2 > a, h3 > a, fallback any a in heading
        a = (li.select_one("h2 a")
             or li.select_one("h3 a")
             or li.select_one(".b_title a, .b_topTitle a"))
        snippet_el = li.select_one(
            "div.b_caption p, p.b_lineclamp1, p.b_lineclamp2, p.b_lineclamp3, p.b_lineclamp4, .b_snippet"
        )
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


async def _fetch(url: str, ua: str, lang: str) -> str:
    headers = {
        "User-Agent": ua,
        "Accept-Language": lang,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "DNT": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }
    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as c:
        r = await c.get(url)
        if r.status_code != 200:
            log.info("bing status=%s for %s", r.status_code, url[:80])
            return ""
        return r.text


async def search_bing(query: str, max_results: int = 12) -> list[SourceResult]:
    q = quote_plus(query)
    ua = random.choice(UA_POOL)

    # Pass 1: Türkçe locale + setmkt
    primary_url = (
        f"https://www.bing.com/search?q={q}&count={max_results}"
        f"&setmkt=tr-TR&setlang=tr&form=QBLH&cc=TR"
    )
    try:
        html = await _fetch(primary_url, ua, "tr-TR,tr;q=0.9,en;q=0.7")
        if html:
            results = _parse_bing_html(html, max_results)
            if results:
                return results
            log.info("bing pass1 (tr-TR) parsed 0 results, trying en-US fallback")
    except Exception as exc:
        log.warning("bing primary failed: %s", exc)

    # Pass 2: en-US fallback
    fallback_url = f"https://www.bing.com/search?q={q}&count={max_results}&form=QBLH"
    try:
        html = await _fetch(fallback_url, random.choice(UA_POOL), "en-US,en;q=0.9")
        if html:
            results = _parse_bing_html(html, max_results)
            if results:
                return results
            log.info("bing pass2 (en-US) parsed 0 results, trying mobile fallback")
    except Exception as exc:
        log.warning("bing fallback failed: %s", exc)

    # Pass 3: cn.bing.com mobile (daha hafif HTML, captcha riski az)
    mobile_url = f"https://cn.bing.com/search?q={q}&count={max_results}&FORM=BEHPTB"
    try:
        html = await _fetch(mobile_url, random.choice(UA_POOL), "tr-TR,en-US;q=0.9")
        if html:
            return _parse_bing_html(html, max_results)
    except Exception as exc:
        log.warning("bing mobile failed: %s", exc)

    return []
