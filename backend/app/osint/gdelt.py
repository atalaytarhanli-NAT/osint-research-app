"""GDELT 2.0 DOC API — küresel haber/olay veritabanı (100+ dil), açık & ücretsiz."""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.gdelt")


async def search_gdelt(query: str, max_records: int = 15) -> list[SourceResult]:
    url = "https://api.gdeltproject.org/api/v2/doc/doc"
    params = {
        "query": query,
        "mode": "ArtList",
        "maxrecords": max_records,
        "format": "json",
        "sort": "HybridRel",
        "timespan": "12months",
    }
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url, params=params)
            if r.status_code != 200 or not r.text.strip():
                return []
            data = r.json()
            for art in data.get("articles", []):
                date = (art.get("seendate") or "")[:8]
                iso = f"{date[:4]}-{date[4:6]}-{date[6:8]}" if len(date) == 8 else None
                out.append(
                    SourceResult(
                        source="gdelt",
                        url=art.get("url", ""),
                        title=safe_truncate(art.get("title", ""), 240),
                        snippet=safe_truncate(art.get("seendate", ""), 320),
                        published_at=iso,
                        kind="news",
                        confidence=0.7,
                        raw={
                            "domain": art.get("domain"),
                            "language": art.get("language"),
                            "country": art.get("sourcecountry"),
                        },
                    )
                )
    except Exception as exc:
        log.warning("GDELT search failed: %s", exc)
    return out
