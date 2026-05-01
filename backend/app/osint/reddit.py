"""Reddit public JSON search — anahtar gerektirmez."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.reddit")

UA = "OsintResearchApp/1.0 (by /u/atalay-osint)"


async def search_reddit(query: str, limit: int = 10) -> list[SourceResult]:
    url = "https://www.reddit.com/search.json"
    params = {"q": query, "limit": limit, "sort": "relevance", "t": "all"}
    headers = {"User-Agent": UA}
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as c:
            r = await c.get(url, params=params)
            if r.status_code != 200:
                return []
            data = r.json()
            for child in data.get("data", {}).get("children", []):
                d = child.get("data", {})
                title = d.get("title") or ""
                permalink = d.get("permalink") or ""
                full_url = f"https://www.reddit.com{permalink}" if permalink else d.get("url", "")
                snippet = d.get("selftext") or ""
                created = d.get("created_utc")
                iso = None
                if created:
                    try:
                        iso = (
                            datetime.fromtimestamp(int(created), tz=timezone.utc).date().isoformat()
                        )
                    except Exception:
                        pass
                out.append(
                    SourceResult(
                        source="reddit",
                        url=full_url,
                        title=safe_truncate(title, 240),
                        snippet=safe_truncate(snippet, 320),
                        published_at=iso,
                        kind="social",
                        confidence=0.45,
                        raw={"subreddit": d.get("subreddit"), "score": d.get("score")},
                    )
                )
    except Exception as exc:
        log.warning("Reddit search failed: %s", exc)
    return out
