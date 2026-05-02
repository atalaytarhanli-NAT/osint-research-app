"""SearXNG meta-search — public instance üzerinden Yandex/Google/Bing/DDG aggregate.

SearXNG, kullanıcının IP'sinden gizli olarak birden fazla arama motorunu sorgulayan
açık kaynak meta-search engine. Render datacenter IP'sinden direkt
DDG/Bing/Yandex 429 alırken, SearXNG public instance'ları residential IP'lerden
çalıştığı için bot tespitine yakalanmaz.

JSON API'si ile kullanılır. Ücretsiz, key gerekmez.

Public instance listesi: https://searx.space/
Bu modül 3 instance dener (rotation), birinde başarısız olursa diğerine geçer.
"""

from __future__ import annotations

import logging
import random
from urllib.parse import quote_plus

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.searxng")


# Public SearXNG instances (JSON API destekli, stabil olanlar — searx.space'ten seçildi)
INSTANCES = [
    "https://searx.be",
    "https://search.disroot.org",
    "https://baresearch.org",
    "https://searx.tiekoetter.com",
    "https://search.bus-hit.me",
    "https://priv.au",
    "https://opnxng.com",
]


async def _try_instance(client: httpx.AsyncClient, base: str, query: str, max_results: int) -> list[dict]:
    url = f"{base}/search"
    params = {
        "q": query,
        "format": "json",
        "safesearch": "0",
        "language": "tr",
        "categories": "general",
    }
    try:
        r = await client.get(url, params=params, timeout=12.0)
        if r.status_code != 200:
            log.info("searxng %s status=%s", base, r.status_code)
            return []
        try:
            data = r.json()
        except Exception:
            return []
        return data.get("results", []) or []
    except Exception as exc:
        log.warning("searxng %s failed: %s", base, exc)
        return []


async def search_searxng(query: str, max_results: int = 15) -> list[SourceResult]:
    """3 random instance dene; biri sonuç döndürürse onu kullan."""
    instances = random.sample(INSTANCES, k=min(3, len(INSTANCES)))

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; OsintResearchApp/1.0)",
        "Accept": "application/json,*/*;q=0.8",
    }
    out: list[SourceResult] = []
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as c:
        for base in instances:
            results = await _try_instance(c, base, query, max_results)
            if not results:
                continue
            for r in results[:max_results]:
                title = r.get("title") or ""
                content = r.get("content") or ""
                link = r.get("url") or ""
                engine = r.get("engine") or "?"
                if not link or not link.startswith("http"):
                    continue
                # Engine ipucu: Yandex/Google/Bing/DDG hangisinden geldi
                src_label = f"searxng:{engine}"
                out.append(
                    SourceResult(
                        source=src_label,
                        url=link,
                        title=safe_truncate(title, 240),
                        snippet=safe_truncate(content, 320),
                        kind="web",
                        confidence=0.65,
                        raw={"searxng_instance": base, "underlying_engine": engine},
                    )
                )
            if out:
                log.info("searxng %s: %d results (engine=%s)", base, len(out), engine)
                break
    return out
