"""Serper.dev — Google sonuçlarına API üzerinden erişim. 2500 ücretsiz sorgu, sonra paid.

Kayıt: https://serper.dev/  (key dashboard)
"""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.serper")


async def search_serper(query: str, api_key: str, max_results: int = 12) -> list[SourceResult]:
    if not api_key:
        return []
    url = "https://google.serper.dev/search"
    headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
    body = {"q": query, "num": min(max_results, 20)}
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as c:
            r = await c.post(url, json=body)
            if r.status_code != 200:
                log.warning("Serper search HTTP %s: %s", r.status_code, r.text[:200])
                return []
            data = r.json()
    except Exception as exc:
        log.warning("Serper search failed: %s", exc)
        return []

    for item in data.get("organic", []):
        out.append(
            SourceResult(
                source="serper",
                url=item.get("link", ""),
                title=safe_truncate(item.get("title", ""), 240),
                snippet=safe_truncate(item.get("snippet", ""), 320),
                published_at=(item.get("date") or "")[:10] or None,
                kind="web",
                confidence=0.75,  # Google-quality
            )
        )
    for item in data.get("topStories", []):
        out.append(
            SourceResult(
                source="serper_news",
                url=item.get("link", ""),
                title=safe_truncate(item.get("title", ""), 240),
                snippet=safe_truncate(item.get("source", ""), 320),
                published_at=(item.get("date") or "")[:10] or None,
                kind="news",
                confidence=0.8,
            )
        )
    return out
