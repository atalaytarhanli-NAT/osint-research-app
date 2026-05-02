"""Wikipedia ve Wikidata kontrolü — açık REST API."""

from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.wiki")


async def lookup_wikipedia(query: str, lang: str = "en") -> list[SourceResult]:
    """Search Wikipedia for the term and return the top summary if found."""
    results: list[SourceResult] = []
    # Wikipedia API requires a contact / descriptive User-Agent per their UA policy.
    # Without this they 403 some IPs.
    headers = {
        "User-Agent": "OsintResearchApp/1.0 (https://osint-research-app.onrender.com; contact: atalay.tarhanli@gmail.com) httpx/0.28",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, headers=headers) as c:
            # 1. Search
            search_url = f"https://{lang}.wikipedia.org/w/api.php"
            search_params = {
                "action": "opensearch",
                "search": query,
                "limit": 4,
                "format": "json",
            }
            r = await c.get(search_url, params=search_params)
            r.raise_for_status()
            data = r.json()
            titles = data[1] if len(data) > 1 else []
            urls = data[3] if len(data) > 3 else []

            # 2. For each title, fetch summary
            for title, url in zip(titles, urls):
                try:
                    summary_url = (
                        f"https://{lang}.wikipedia.org/api/rest_v1/page/summary/{quote(title)}"
                    )
                    sr = await c.get(summary_url)
                    if sr.status_code != 200:
                        continue
                    s = sr.json()
                    extract = s.get("extract") or ""
                    description = s.get("description") or ""
                    page_url = s.get("content_urls", {}).get("desktop", {}).get("page") or url
                    results.append(
                        SourceResult(
                            source="wikipedia",
                            url=page_url,
                            title=title,
                            snippet=safe_truncate(f"{description}. {extract}".strip(". "), 380),
                            kind="wiki",
                            confidence=0.85,
                            raw={"description": description, "lang": lang},
                        )
                    )
                except Exception as exc:
                    log.debug("Wikipedia summary fetch failed for %s: %s", title, exc)
    except Exception as exc:
        log.warning("Wikipedia search failed: %s", exc)

    return results
