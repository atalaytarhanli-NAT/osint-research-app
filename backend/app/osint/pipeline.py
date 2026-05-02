"""OSINT pipeline orchestrator — 14 kaynak paralel + opsiyonel 2-pass deepening."""

from __future__ import annotations

import asyncio
import logging
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from .archive_today import archive_today_lookup
from .arxiv import search_arxiv
from .base import SourceResult
from .bing_search import search_bing
from .crtsh import search_crtsh
from .gdelt import search_gdelt
from .github_oss import search_github
from .hackernews import search_hn
from .mojeek_search import search_mojeek
from .person_enrich import enrich_with_variations
from .reddit import search_reddit
from .social_probe import probe_username
from .wayback import wayback_lookup
from .web_search import search_news, search_web
from .wikidata import search_wikidata
from .wikipedia import lookup_wikipedia
from .yandex_search import search_yandex


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


async def _first_pass(target: str, kind: str) -> list[SourceResult]:
    tasks: list = [
        _safe("ddg", search_web(target)),
        _safe("ddg_news", search_news(target)),
        _safe("bing", search_bing(target)),
        _safe("yandex", search_yandex(target)),
        _safe("mojeek", search_mojeek(target)),
        _safe("wiki_en", lookup_wikipedia(target, "en")),
        _safe("wiki_tr", lookup_wikipedia(target, "tr")),
        _safe("wikidata", search_wikidata(target)),
        _safe("hn", search_hn(target)),
        _safe("reddit", search_reddit(target)),
        _safe("github", search_github(target)),
        _safe("gdelt", search_gdelt(target)),
        _safe("arxiv", search_arxiv(target)),
        _safe("wayback", wayback_lookup(target)),
        _safe("archive_today", archive_today_lookup(target)),
    ]
    if kind == "url":
        tasks.append(_safe("crtsh", search_crtsh(target)))
    if kind in ("social", "person"):
        tasks.append(_safe("social_probe", probe_username(target)))
    if kind in ("person", "organization", "auto"):
        tasks.append(_safe("person_enrich", enrich_with_variations(target, kind)))

    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    for chunk in chunks:
        flat.extend(chunk)
    return flat


_STOPWORDS = {
    "the","a","an","of","and","or","to","in","on","is","are","was","were","be","by","for","with",
    "as","at","that","this","it","from","but","not","you","we","they","he","she","his","her","our",
    "their","its","have","has","had","will","would","can","could","should","than","into","about",
    "ile","ve","de","da","bir","bu","şu","o","mı","mi","mu","mü","için","gibi","ama","fakat","veya",
    "olarak","kadar","göre","sonra","önce","çok","var","yok","yıl","yılı","gün","ay",
}


def _refine_queries(target: str, sources: list[SourceResult], k: int = 3) -> list[str]:
    """Top tekrar eden anlamlı kelimelerden ek sorgular üret."""
    text_blob = " ".join((s.title or "") + " " + (s.snippet or "") for s in sources[:30])
    target_lower = target.lower()
    words = re.findall(r"[A-Za-zÇĞİÖŞÜçğıöşü0-9]{4,}", text_blob)
    counter: Counter[str] = Counter()
    for w in words:
        wl = w.lower()
        if wl in _STOPWORDS or wl in target_lower or target_lower in wl:
            continue
        counter[wl] += 1
    common = [w for w, _ in counter.most_common(8) if _ >= 2]
    queries: list[str] = []
    for term in common[:k]:
        queries.append(f'"{target}" {term}')
    return queries


async def _second_pass(target: str, refined_queries: list[str]) -> list[SourceResult]:
    if not refined_queries:
        return []
    tasks = []
    for q in refined_queries:
        tasks.append(_safe("ddg2", search_web(q, max_results=8)))
        tasks.append(_safe("bing2", search_bing(q, max_results=8)))
        tasks.append(_safe("yandex2", search_yandex(q, max_results=6)))
        tasks.append(_safe("gdelt2", search_gdelt(q, max_records=8)))
    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    for chunk in chunks:
        flat.extend(chunk)
    for s in flat:
        s.confidence = max(0.3, s.confidence - 0.1)  # 2nd pass biraz daha düşük güven
        s.raw["pass"] = 2
    return flat


def _dedupe(items: list[SourceResult]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict] = []
    for r in items:
        key = (r.url or "").rstrip("/")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(r.to_dict())
    return out


async def run_pipeline(
    target: str, kind_hint: str = "auto", intensity: str = "deep"
) -> list[dict[str, Any]]:
    """intensity: 'quick' (1 pass) | 'deep' (2 pass with refined queries)."""
    kind = detect_kind(target, kind_hint)

    first = await _first_pass(target, kind)
    log.info("OSINT first pass: %d sources for %r", len(first), target)

    if intensity == "deep":
        refined = _refine_queries(target, first, k=3)
        log.info("OSINT refined queries: %s", refined)
        second = await _second_pass(target, refined)
        log.info("OSINT second pass: %d sources", len(second))
        all_results = first + second
    else:
        all_results = first

    return _dedupe(all_results)
