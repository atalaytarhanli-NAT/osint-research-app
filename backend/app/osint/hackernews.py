"""HackerNews (Algolia API) — açık endpoint."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.hn")


async def search_hn(query: str, hits: int = 8) -> list[SourceResult]:
    url = "https://hn.algolia.com/api/v1/search"
    params = {"query": query, "hitsPerPage": hits, "tags": "(story,comment)"}
    results: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url, params=params)
            r.raise_for_status()
            data = r.json()
            for h in data.get("hits", []):
                title = h.get("title") or h.get("story_title") or ""
                story_url = h.get("url") or h.get("story_url") or (
                    f"https://news.ycombinator.com/item?id={h.get('objectID')}"
                )
                snippet = h.get("comment_text") or h.get("story_text") or ""
                created = h.get("created_at")
                iso = None
                if created:
                    try:
                        iso = (
                            datetime.fromisoformat(created.replace("Z", "+00:00"))
                            .astimezone(timezone.utc)
                            .date()
                            .isoformat()
                        )
                    except Exception:
                        pass
                results.append(
                    SourceResult(
                        source="hackernews",
                        url=story_url,
                        title=safe_truncate(title, 240),
                        snippet=safe_truncate(snippet, 320),
                        published_at=iso,
                        kind="news",
                        confidence=0.6,
                    )
                )
    except Exception as exc:
        log.warning("HN search failed: %s", exc)
    return results
