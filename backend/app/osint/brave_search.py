"""Brave Search API — anahtar gerektirir ama IP-block olmaz, Render'da güvenli.

Anahtar ücretsiz: https://api.search.brave.com/app/keys (free tier 2000/ay).
Çevre değişkeni `APP_BRAVE_API_KEY` veya admin `/api/admin/search-keys` ile saklanır.

Bu, scraping-tabanlı motorlar (DDG, Bing, Yandex) Render datacenter IP'lerinden
captcha/block alırken bile çalışan tek güvenilir SERP kaynağıdır."""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.brave")


async def search_brave(query: str, api_key: str, max_results: int = 15) -> list[SourceResult]:
    if not api_key:
        return []
    url = "https://api.search.brave.com/res/v1/web/search"
    headers = {
        "X-Subscription-Token": api_key,
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
    }
    params = {"q": query, "count": min(max_results, 20)}
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as c:
            r = await c.get(url, params=params)
            if r.status_code != 200:
                log.warning("Brave search HTTP %s: %s", r.status_code, r.text[:200])
                return []
            data = r.json()
    except Exception as exc:
        log.warning("Brave search failed: %s", exc)
        return []

    for item in data.get("web", {}).get("results", []):
        out.append(
            SourceResult(
                source="brave",
                url=item.get("url", ""),
                title=safe_truncate(item.get("title", ""), 240),
                snippet=safe_truncate(item.get("description", ""), 320),
                published_at=(item.get("page_age") or "")[:10] or None,
                kind="web",
                confidence=0.7,  # API-grade > scrape, daha güvenilir
            )
        )
    # Brave news bloğunu da çek (varsa)
    for item in data.get("news", {}).get("results", []):
        out.append(
            SourceResult(
                source="brave_news",
                url=item.get("url", ""),
                title=safe_truncate(item.get("title", ""), 240),
                snippet=safe_truncate(item.get("description", ""), 320),
                published_at=(item.get("page_age") or "")[:10] or None,
                kind="news",
                confidence=0.75,
            )
        )
    return out
