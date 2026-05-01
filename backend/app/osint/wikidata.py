"""Wikidata entity search — yapılandırılmış varlık verisi, kim-kimdir, kurum-türü."""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.wikidata")


async def search_wikidata(query: str, limit: int = 6) -> list[SourceResult]:
    url = "https://www.wikidata.org/w/api.php"
    headers = {"User-Agent": "OsintResearchApp/1.0"}
    params_search = {
        "action": "wbsearchentities",
        "search": query,
        "language": "en",
        "format": "json",
        "limit": limit,
    }
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as c:
            r = await c.get(url, params=params_search)
            if r.status_code != 200:
                return []
            data = r.json()
            for it in data.get("search", []):
                qid = it.get("id", "")
                label = it.get("label", "")
                desc = it.get("description", "")
                concept_uri = it.get("concepturi") or f"https://www.wikidata.org/wiki/{qid}"
                out.append(
                    SourceResult(
                        source="wikidata",
                        url=concept_uri,
                        title=f"{label} ({qid})",
                        snippet=safe_truncate(desc, 320),
                        kind="wiki",
                        confidence=0.85,
                        raw={"qid": qid, "label": label},
                    )
                )
    except Exception as exc:
        log.warning("Wikidata search failed: %s", exc)
    return out
