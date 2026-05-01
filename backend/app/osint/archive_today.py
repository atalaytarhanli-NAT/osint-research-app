"""archive.today (archive.ph) — Wayback'e ek ikinci web arşivi.

Kamuya açık snapshot listesi sayfası HTML olarak parse edilir."""

from __future__ import annotations

import logging
import re
from urllib.parse import quote

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.archive_today")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/124.0"


async def archive_today_lookup(query: str) -> list[SourceResult]:
    if "." not in query and not query.startswith("http"):
        return []
    target = query if query.startswith("http") else f"http://{query}"
    url = f"https://archive.ph/newest/{quote(target, safe=':/')}"
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": UA}, follow_redirects=True) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            html = r.text
    except Exception as exc:
        log.warning("archive.today fetch failed: %s", exc)
        return []

    pattern = re.compile(r'href="(https://archive\.(?:ph|today|is)/\w{5,})"', re.I)
    seen: set[str] = set()
    for m in pattern.finditer(html):
        link = m.group(1)
        if link in seen:
            continue
        seen.add(link)
        out.append(
            SourceResult(
                source="archive_today",
                url=link,
                title=safe_truncate(f"archive.today snapshot — {target}", 240),
                snippet=safe_truncate("Cached snapshot via archive.ph", 200),
                kind="archive",
                confidence=0.85,
            )
        )
        if len(out) >= 8:
            break
    return out
