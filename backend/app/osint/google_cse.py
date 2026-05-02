"""Google Programmable Search Engine (CSE) — Google sonuçları için.

Google'ın "doğru" arama sonuçlarına erişim için public API. Anahtar formatı:
"<API_KEY>:<CX_ID>" (Settings'te tek field).

Ücretsiz tier: 100 sorgu/gün. https://developers.google.com/custom-search/v1/overview

Render IP'sinde DDG/Bing/Yandex bot tespiti yiyince Google CSE devreye girer
ve "kullanıcının kendi browser'ında gördüğü" sonuçları dödndürür.
"""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.google_cse")


SEARCH_URL = "https://www.googleapis.com/customsearch/v1"


async def search_google_cse(query: str, key_pair: str, max_results: int = 10) -> list[SourceResult]:
    """Google CSE arama. key_pair format: '<API_KEY>:<CX_ID>'."""
    if not key_pair or ":" not in key_pair:
        return []
    parts = key_pair.split(":", 1)
    api_key, cx = parts[0].strip(), parts[1].strip()
    if not api_key or not cx:
        return []

    out: list[SourceResult] = []
    # CSE 1 sayfada max 10 sonuç döner; gerekirse 2 sayfa
    pages = 1 if max_results <= 10 else 2
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            for page in range(pages):
                start = page * 10 + 1
                params = {
                    "key": api_key, "cx": cx, "q": query,
                    "num": min(10, max_results - len(out)),
                    "start": start,
                }
                r = await c.get(SEARCH_URL, params=params)
                if r.status_code != 200:
                    log.info("google_cse status=%s body=%s", r.status_code, r.text[:200])
                    break
                data = r.json()
                items = data.get("items") or []
                for item in items:
                    title = item.get("title") or ""
                    snippet = item.get("snippet") or ""
                    link = item.get("link") or ""
                    if not link:
                        continue
                    pagemap = item.get("pagemap") or {}
                    metatags = (pagemap.get("metatags") or [{}])[0]
                    date = metatags.get("article:published_time") or metatags.get("og:updated_time")
                    out.append(
                        SourceResult(
                            source="google_cse",
                            url=link,
                            title=title[:200],
                            snippet=safe_truncate(snippet, 280),
                            published_at=(date or "")[:10] or None,
                            kind="web",
                            confidence=0.85,  # Google sonuçları genelde yüksek doğrulukta
                            raw={"display_link": item.get("displayLink", "")},
                        )
                    )
                if not items or len(out) >= max_results:
                    break
    except Exception as exc:
        log.warning("google_cse failed: %s", exc)
        return out
    return out[:max_results]
