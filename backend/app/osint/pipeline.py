"""OSINT pipeline orchestrator — paralel kaynaklar + 2-pass deepening + scope filter."""

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
from .brave_search import search_brave
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


def _quote_for_search(target: str, kind: str) -> str:
    """Person/organization hedeflerini SERP'lerde tırnağa al → exact match,
    eş isim çakışmasını azalt."""
    t = target.strip()
    if kind in ("person", "organization") and " " in t and not (t.startswith('"') and t.endswith('"')):
        return f'"{t}"'
    return t


async def _web_pass(query: str, raw_target: str, kind: str, brave_key: str = "") -> list[SourceResult]:
    tasks = [
        _safe("ddg", search_web(query)),
        _safe("ddg_news", search_news(query)),
        _safe("bing", search_bing(query)),
        _safe("yandex", search_yandex(query)),
        _safe("mojeek", search_mojeek(query)),
        _safe("wiki_en", lookup_wikipedia(raw_target, "en")),
        _safe("wiki_tr", lookup_wikipedia(raw_target, "tr")),
        _safe("wikidata", search_wikidata(raw_target)),
        _safe("github", search_github(query)),
        _safe("gdelt", search_gdelt(query)),
        _safe("arxiv", search_arxiv(query)),
        _safe("wayback", wayback_lookup(raw_target)),
        _safe("archive_today", archive_today_lookup(raw_target)),
    ]
    if brave_key:
        tasks.append(_safe("brave", search_brave(query, brave_key)))
    if kind == "url":
        tasks.append(_safe("crtsh", search_crtsh(raw_target)))
    if kind in ("person", "organization", "auto"):
        tasks.append(_safe("person_enrich", enrich_with_variations(raw_target, kind)))

    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    for chunk in chunks:
        flat.extend(chunk)
    return flat


async def _social_pass(query: str, raw_target: str, kind: str) -> list[SourceResult]:
    tasks = [
        _safe("hn", search_hn(query)),
        _safe("reddit", search_reddit(query)),
    ]
    if kind in ("social", "person"):
        tasks.append(_safe("social_probe", probe_username(raw_target)))
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


def _significant_words(text: str) -> list[str]:
    words = re.findall(r"[A-Za-zÇĞİÖŞÜçğıöşü]{3,}", text)
    return [w.lower() for w in words if w.lower() not in _STOPWORDS]


def _filter_relevance(target: str, kind: str, sources: list[SourceResult]) -> list[SourceResult]:
    """Çok kelimeli isim/kurum hedeflerinde, başlık+snippet+url'de hedefin
    anlamlı kelimelerinden hiçbiri geçmiyorsa o kaynağı düşür.

    Bu, Render IP'leriyle yapılan "Atalay Tarhanlı" araması gibi durumlarda
    SERP'lerin döndürdüğü ilgisiz sonuçları (haber, başka kişiler) eler."""
    if kind not in ("person", "organization"):
        return sources
    sig = _significant_words(target)
    if len(sig) < 2:
        return sources

    out: list[SourceResult] = []
    for s in sources:
        # Yetkili kaynaklar (wiki/wikidata/wayback/archive) her zaman geçer
        if s.kind in ("wiki", "archive"):
            out.append(s)
            continue
        # social_probe sonuçları zaten username'den geldi, ilgili
        if s.source.startswith("social:"):
            out.append(s)
            continue
        text = " ".join([s.title or "", s.snippet or "", s.url or ""]).lower()
        if any(w in text for w in sig):
            out.append(s)
        else:
            log.debug("dropped irrelevant: %s — %s", s.source, s.title[:80] if s.title else s.url)
    log.info("relevance filter: %d → %d (kind=%s, target=%r)", len(sources), len(out), kind, target)
    return out


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
    common = [w for w, c in counter.most_common(8) if c >= 2]
    queries: list[str] = []
    for term in common[:k]:
        queries.append(f'"{target}" {term}')
    return queries


async def _second_pass(query: str, refined_queries: list[str], brave_key: str = "") -> list[SourceResult]:
    if not refined_queries:
        return []
    tasks = []
    for q in refined_queries:
        tasks.append(_safe("ddg2", search_web(q, max_results=8)))
        tasks.append(_safe("bing2", search_bing(q, max_results=8)))
        tasks.append(_safe("yandex2", search_yandex(q, max_results=6)))
        tasks.append(_safe("gdelt2", search_gdelt(q, max_records=8)))
        if brave_key:
            tasks.append(_safe("brave2", search_brave(q, brave_key, max_results=8)))
    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    for chunk in chunks:
        flat.extend(chunk)
    for s in flat:
        s.confidence = max(0.3, s.confidence - 0.1)
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
    target: str,
    kind_hint: str = "auto",
    intensity: str = "deep",
    scope: str = "all",
    brave_key: str = "",
) -> list[dict[str, Any]]:
    """
    intensity: 'quick' (1 pass) | 'deep' (2 pass)
    scope:     'web' | 'social' | 'all'
    brave_key: opsiyonel Brave Search API anahtarı (Render IP'lerinden iyi sonuç verir)
    """
    kind = detect_kind(target, kind_hint)
    query = _quote_for_search(target, kind)

    first: list[SourceResult] = []
    if scope in ("web", "all"):
        first.extend(await _web_pass(query, target, kind, brave_key=brave_key))
    if scope in ("social", "all"):
        first.extend(await _social_pass(query, target, kind))

    log.info("OSINT first pass: %d sources for %r (scope=%s, brave=%s)",
             len(first), target, scope, "on" if brave_key else "off")

    if intensity == "deep" and scope in ("web", "all"):
        refined = _refine_queries(target, first, k=3)
        log.info("OSINT refined queries: %s", refined)
        second = await _second_pass(query, refined, brave_key=brave_key)
        log.info("OSINT second pass: %d sources", len(second))
        all_results = first + second
    else:
        all_results = first

    filtered = _filter_relevance(target, kind, all_results)
    return _dedupe(filtered)
