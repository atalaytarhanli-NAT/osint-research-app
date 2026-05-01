"""OSINT pipeline orchestrator — tüm kaynakları paralel çalıştırır."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from .base import SourceResult
from .github_oss import search_github
from .hackernews import search_hn
from .reddit import search_reddit
from .social_probe import probe_username
from .wayback import wayback_lookup
from .web_search import search_news, search_web
from .wikipedia import lookup_wikipedia


log = logging.getLogger("osint.pipeline")


URL_RE = re.compile(r"^(https?://|www\.)|\.[a-z]{2,}/?$", re.I)
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9_.-]{2,40}$")


def detect_kind(target: str, hint: str = "auto") -> str:
    if hint and hint != "auto":
        return hint
    t = target.strip()
    if URL_RE.search(t):
        return "url"
    if t.startswith("@") or (USERNAME_RE.match(t) and " " not in t):
        return "social"
    if " " in t and len(t.split()) <= 4:
        return "person"
    return "keyword"


async def _safe(name: str, coro):
    try:
        return await coro
    except Exception as exc:
        log.warning("%s failed: %s", name, exc)
        return []


async def run_pipeline(target: str, kind_hint: str = "auto") -> list[dict[str, Any]]:
    kind = detect_kind(target, kind_hint)

    tasks: list[asyncio.Task] = [
        asyncio.create_task(_safe("web", search_web(target))),
        asyncio.create_task(_safe("news", search_news(target))),
        asyncio.create_task(_safe("wiki_en", lookup_wikipedia(target, "en"))),
        asyncio.create_task(_safe("wiki_tr", lookup_wikipedia(target, "tr"))),
        asyncio.create_task(_safe("hn", search_hn(target))),
        asyncio.create_task(_safe("reddit", search_reddit(target))),
        asyncio.create_task(_safe("github", search_github(target))),
        asyncio.create_task(_safe("wayback", wayback_lookup(target))),
    ]
    if kind in ("social", "person"):
        tasks.append(asyncio.create_task(_safe("social", probe_username(target))))

    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    for chunk in chunks:
        flat.extend(chunk)

    seen: set[str] = set()
    deduped: list[dict] = []
    for r in flat:
        if r.url in seen:
            continue
        seen.add(r.url)
        deduped.append(r.to_dict())
    return deduped
