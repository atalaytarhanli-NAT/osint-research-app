"""arXiv arama — açık akademik preprint veritabanı."""

from __future__ import annotations

import logging
import re

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.arxiv")

NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "arxiv": "http://arxiv.org/schemas/atom",
}


async def search_arxiv(query: str, max_results: int = 8) -> list[SourceResult]:
    url = "http://export.arxiv.org/api/query"
    params = {
        "search_query": f"all:{query}",
        "start": 0,
        "max_results": max_results,
        "sortBy": "relevance",
    }
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=12.0) as c:
            r = await c.get(url, params=params)
            if r.status_code != 200:
                return []
            xml = r.text
    except Exception as exc:
        log.warning("arXiv search failed: %s", exc)
        return []

    # Lightweight parsing — avoid lxml.etree hassle, use regex
    entries = re.findall(r"<entry>(.*?)</entry>", xml, re.S)
    for ent in entries:
        title_m = re.search(r"<title>(.*?)</title>", ent, re.S)
        link_m = re.search(r'<id>(.*?)</id>', ent, re.S)
        summary_m = re.search(r"<summary>(.*?)</summary>", ent, re.S)
        published_m = re.search(r"<published>(\d{4}-\d{2}-\d{2})", ent)
        if not (title_m and link_m):
            continue
        title = re.sub(r"\s+", " ", title_m.group(1)).strip()
        link = link_m.group(1).strip()
        summary = re.sub(r"\s+", " ", summary_m.group(1)).strip() if summary_m else ""
        published = published_m.group(1) if published_m else None
        out.append(
            SourceResult(
                source="arxiv",
                url=link,
                title=safe_truncate(title, 240),
                snippet=safe_truncate(summary, 360),
                published_at=published,
                kind="wiki",  # academic ~ scholarly, group with wiki/factual
                confidence=0.75,
            )
        )
    return out
