"""Kişi/kurum hedefler için varyasyon-bazlı enrichment.

Hedef "Atalay Tarhanlı" gibi bir isimse, ana sorgunun yanında "{name} LinkedIn",
"{name} biography", "{name} CV" vb. profil/biyografi kombinasyonlarıyla DDG/Bing/
Yandex/Mojeek üzerinden ek tarama yapar."""

from __future__ import annotations

import asyncio
import logging
import re

from .base import SourceResult
from .bing_search import search_bing
from .mojeek_search import search_mojeek
from .web_search import search_web
from .yandex_search import search_yandex


log = logging.getLogger("osint.person_enrich")


_PERSON_VARIATIONS = [
    "{q} LinkedIn",
    "{q} biography",
    "{q} CV resume",
    '"{q}" profile',
    "{q} interview",
]

_ORG_VARIATIONS = [
    "{q} headquarters",
    "{q} CEO founder",
    "{q} crunchbase",
    "{q} annual report",
    '"{q}" controversy',
]


def _is_likely_person(target: str) -> bool:
    t = target.strip()
    if " " not in t:
        return False
    parts = t.split()
    if not 2 <= len(parts) <= 4:
        return False
    # rough: most parts start with capital letter
    return sum(1 for p in parts if p[:1].isupper()) >= max(1, len(parts) - 1)


async def enrich_with_variations(target: str, kind: str, per_engine: int = 5) -> list[SourceResult]:
    if kind == "person" or (kind in ("auto", "") and _is_likely_person(target)):
        templates = _PERSON_VARIATIONS
    elif kind in ("organization", "auto") and not target.startswith("@") and "." not in target:
        templates = _ORG_VARIATIONS
    else:
        return []

    queries = [t.format(q=target) for t in templates]
    tasks = []
    # Spread across engines: rotate to avoid hitting one engine many times
    engines = [search_web, search_bing, search_yandex, search_mojeek]
    for i, q in enumerate(queries):
        engine = engines[i % len(engines)]
        tasks.append(_safe(engine.__name__, engine(q, per_engine)))

    chunks = await asyncio.gather(*tasks)
    out: list[SourceResult] = []
    for chunk in chunks:
        for s in chunk:
            s.source = f"enrich:{s.source}"
            s.confidence = max(0.3, s.confidence - 0.05)
            s.raw["enrichment"] = True
            out.append(s)
    return out


async def _safe(name: str, coro):
    try:
        return await coro
    except Exception as exc:
        log.warning("enrich %s failed: %s", name, exc)
        return []
