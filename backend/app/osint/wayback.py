"""Wayback Machine — Web archive check."""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.wayback")


async def wayback_lookup(query: str) -> list[SourceResult]:
    """Look up the target as a URL in Wayback Machine. If query is not a URL,
    we simply skip (the CDX API expects a URL/host)."""
    if not (query.startswith("http://") or query.startswith("https://") or "." in query):
        return []

    # Normalize: if user gave a bare domain, try http://domain
    target = query
    if not target.startswith("http"):
        target = f"http://{target}"

    results: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
            cdx_url = "https://web.archive.org/cdx/search/cdx"
            params = {
                "url": target,
                "limit": "5",
                "output": "json",
                "filter": "statuscode:200",
                "from": "2000",
            }
            r = await c.get(cdx_url, params=params)
            if r.status_code != 200:
                return []
            rows = r.json()
            if not rows or len(rows) <= 1:
                return []
            header, *snapshots = rows
            for snap in snapshots[:5]:
                try:
                    timestamp = snap[1]
                    original = snap[2]
                    archive_url = f"https://web.archive.org/web/{timestamp}/{original}"
                    iso = (
                        f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
                        if len(timestamp) >= 8
                        else None
                    )
                    results.append(
                        SourceResult(
                            source="wayback",
                            url=archive_url,
                            title=safe_truncate(f"Archive snapshot — {original}", 240),
                            snippet=f"Archived {iso}",
                            published_at=iso,
                            kind="archive",
                            confidence=0.9,
                            raw={"timestamp": timestamp, "original": original},
                        )
                    )
                except Exception as exc:
                    log.debug("snap parse failed: %s", exc)
    except Exception as exc:
        log.warning("Wayback fetch failed: %s", exc)

    return results
