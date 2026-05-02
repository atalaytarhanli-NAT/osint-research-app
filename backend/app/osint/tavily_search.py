"""Tavily Search API — anahtar gerektirir, IP-block olmaz, Render'da güvenli.

Ücretsiz tier 1000 sorgu/ay. Kayıt: https://app.tavily.com/
"""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.tavily")


async def search_tavily(query: str, api_key: str, max_results: int = 12) -> list[SourceResult]:
    if not api_key:
        return []
    url = "https://api.tavily.com/search"
    body = {
        "api_key": api_key,
        "query": query,
        "max_results": min(max_results, 20),
        "search_depth": "advanced",
        "include_answer": False,
    }
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            r = await c.post(url, json=body)
            if r.status_code != 200:
                log.warning("Tavily search HTTP %s: %s", r.status_code, r.text[:200])
                return []
            data = r.json()
    except Exception as exc:
        log.warning("Tavily search failed: %s", exc)
        return []

    for item in data.get("results", []):
        out.append(
            SourceResult(
                source="tavily",
                url=item.get("url", ""),
                title=safe_truncate(item.get("title", ""), 240),
                snippet=safe_truncate(item.get("content", ""), 360),
                published_at=(item.get("published_date") or "")[:10] or None,
                kind="web",
                confidence=0.7,
                raw={"score": item.get("score")},
            )
        )
    return out
