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
from .companies_house import search_companies_house
from .crtsh import search_crtsh
from .dns_records import lookup_dns
from .dnstwist_check import check_typosquats
from .gdelt import search_gdelt
from .geolocation import extract_geopoints
from .github_oss import search_github
from .google_cse import search_google_cse
from .hackernews import search_hn
from .mojeek_search import search_mojeek
from .person_enrich import enrich_with_variations
from .ransomwatch import check_ransomwatch
from .reddit import search_reddit
from .sanctions import search_sanctions
from .searxng import search_searxng
from .sec_edgar import search_sec_edgar
from .serper_search import search_serper
from .social_probe import probe_username
from .tavily_search import search_tavily
from .tracking_ids import extract_tracking_ids
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


async def _safe(name: str, coro) -> tuple[str, list, str | None]:
    """(engine_name, results, error|None) döndürür — diagnostics için."""
    try:
        results = await coro
        return name, results or [], None
    except Exception as exc:
        log.warning("%s failed: %s", name, exc)
        return name, [], str(exc)[:200]


def _quote_for_search(target: str, kind: str) -> str:
    """Person/organization hedeflerini SERP'lerde tırnağa al → exact match,
    eş isim çakışmasını azalt."""
    t = target.strip()
    if kind in ("person", "organization") and " " in t and not (t.startswith('"') and t.endswith('"')):
        return f'"{t}"'
    return t


async def _web_pass(
    query: str,
    raw_target: str,
    kind: str,
    search_keys: dict[str, str] | None = None,
) -> list[SourceResult]:
    keys = search_keys or {}
    tasks = [
        _safe("ddg", search_web(query)),
        _safe("ddg_news", search_news(query)),
        _safe("bing", search_bing(query)),
        _safe("yandex", search_yandex(query)),
        _safe("mojeek", search_mojeek(query)),
        _safe("searxng", search_searxng(query)),
        _safe("wiki_en", lookup_wikipedia(raw_target, "en")),
        _safe("wiki_tr", lookup_wikipedia(raw_target, "tr")),
        _safe("wikidata", search_wikidata(raw_target)),
        _safe("github", search_github(query)),
        _safe("gdelt", search_gdelt(query)),
        _safe("arxiv", search_arxiv(query)),
        _safe("wayback", wayback_lookup(raw_target)),
        _safe("archive_today", archive_today_lookup(raw_target)),
    ]
    if keys.get("brave"):
        tasks.append(_safe("brave", search_brave(query, keys["brave"])))
    if keys.get("tavily"):
        tasks.append(_safe("tavily", search_tavily(query, keys["tavily"])))
    if keys.get("serper"):
        tasks.append(_safe("serper", search_serper(query, keys["serper"])))
    if keys.get("google_cse"):
        tasks.append(_safe("google_cse", search_google_cse(query, keys["google_cse"])))
    if kind == "url":
        tasks.append(_safe("crtsh", search_crtsh(raw_target)))
        tasks.append(_safe("dns", lookup_dns(raw_target)))
        tasks.append(_safe("dnstwist", check_typosquats(raw_target)))
    if kind in ("person", "organization", "auto"):
        tasks.append(_safe("person_enrich", enrich_with_variations(raw_target, kind)))
        tasks.append(_safe("sanctions", search_sanctions(raw_target, kind=kind if kind != "auto" else "person")))
    if kind in ("organization", "auto") and not raw_target.startswith("@"):
        tasks.append(_safe("sec_edgar", search_sec_edgar(raw_target)))
        tasks.append(_safe("ransomwatch", check_ransomwatch(raw_target)))
        if keys.get("companies_house"):
            tasks.append(_safe("companies_house", search_companies_house(raw_target, keys["companies_house"])))

    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    diag: dict[str, dict] = {}
    for name, results, err in chunks:
        flat.extend(results)
        diag[name] = {"count": len(results), "error": err}
    return flat, diag


async def _social_pass(query: str, raw_target: str, kind: str):
    tasks = [
        _safe("hn", search_hn(query)),
        _safe("reddit", search_reddit(query)),
    ]
    if kind in ("social", "person"):
        tasks.append(_safe("social_probe", probe_username(raw_target)))
    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    diag: dict[str, dict] = {}
    for name, results, err in chunks:
        flat.extend(results)
        diag[name] = {"count": len(results), "error": err}
    return flat, diag


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


_TR_FOLD = str.maketrans({
    "ç": "c", "Ç": "c", "ğ": "g", "Ğ": "g", "ı": "i", "I": "i",
    "İ": "i", "ö": "o", "Ö": "o", "ş": "s", "Ş": "s", "ü": "u", "Ü": "u",
})


def _fold(text: str) -> str:
    """Türkçe→Latin transliterasyon + lowercase. Filter eşleşmesi için."""
    return (text or "").translate(_TR_FOLD).lower()


def _filter_relevance(target: str, kind: str, sources: list[SourceResult]) -> list[SourceResult]:
    """Eş isim çakışmasını eler — 2+ kelimeli person/org hedefler için
    target'ın **TÜM** anlamlı kelimeleri (Latin fold ile) text'te bulunmalı.

    Eski mantık `any()` idi → "atalay tarhanlı" sorgusuna "Can Atalay" ve
    "Atalay Mutfak" da geçiyordu (sadece "atalay" kelimesi için). Yeni mantık
    `all()` — tüm kelimeler eşleşmezse drop. URL slug eşleşmesi de ek yol.

    Türkçe → Latin fold (Tarhanlı↔Tarhanli) korunuyor. enrich:* / social:* /
    yetkili kaynaklar (wiki/sanction/financial/...) whitelist."""
    if kind not in ("person", "organization"):
        return sources
    sig_raw = _significant_words(target)
    if len(sig_raw) < 2:
        return sources
    sig = [_fold(w) for w in sig_raw]

    out: list[SourceResult] = []
    target_fold = _fold(target).replace(" ", "")
    for s in sources:
        # YAPISAL kaynaklar her zaman geçer — bu modüller target'la doğrudan
        # sorgulandı, snippet'larında target adı geçmese de hedefe aittir
        # (DNS records target domain için, sanction target adıyla query, vs.)
        if s.kind in ("cybint", "sanction", "attack_surface", "financial",
                      "threat_exposure", "corp_registry", "link_signal"):
            out.append(s)
            continue
        # social_probe (Sherlock-style) sonuçları zaten username'den geldi
        if s.source.startswith("social:"):
            out.append(s)
            continue
        # wiki/archive/web/news tümü AND check'e tabi — Wikipedia "Turgay Şahan"
        # sorgusuna "Turgay Bahadır" döndürebiliyor; eş isim çakışmasını eler
        text = _fold(" ".join([s.title or "", s.snippet or "", s.url or ""]))
        # AND: tüm anlamlı kelimeler text'te bulunmalı (eş isim çakışmasını eler)
        if all(w in text for w in sig):
            out.append(s)
            continue
        # URL slug eşleşmesi: "atalaytarhanli" pattern URL'de varsa kabul
        slug_text = text.replace(" ", "").replace("-", "").replace("_", "").replace(".", "")
        if target_fold and target_fold in slug_text:
            out.append(s)
            continue
        # enrich:* için: enrichment query specifically için target kombosunu
        # arattı — yine de tüm kelimeler eşleşmezse alakasız (ör. "atalay tarhanlı
        # LinkedIn" sorgusunun ilgisiz Bing sonucu Can Atalay'ı getirebiliyor)
        log.debug("dropped irrelevant: %s — %s", s.source, s.title[:80] if s.title else s.url)

    # Empty fallback: hiçbir engine sonuç döndürmediyse — sources zaten boş demek.
    # Eğer sources doluysa ama filter hepsini drop ettiyse, eş isim çakışması var
    # demek; filter'ı bypass ETMİYORUZ — kullanıcıya yanlış kişi raporu sunmaktansa
    # boş döndürmek daha doğru. Boş set, downstream'de "doğrulanamadı" raporu üretir.
    log.info("relevance filter: %d → %d (kind=%s, target=%r, AND mode)",
             len(sources), len(out), kind, target)
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


async def _second_pass(
    query: str,
    refined_queries: list[str],
    search_keys: dict[str, str] | None = None,
) -> list[SourceResult]:
    if not refined_queries:
        return []
    keys = search_keys or {}
    tasks = []
    for q in refined_queries:
        tasks.append(_safe("ddg2", search_web(q, max_results=8)))
        tasks.append(_safe("bing2", search_bing(q, max_results=8)))
        tasks.append(_safe("yandex2", search_yandex(q, max_results=6)))
        tasks.append(_safe("gdelt2", search_gdelt(q, max_records=8)))
        if keys.get("brave"):
            tasks.append(_safe("brave2", search_brave(q, keys["brave"], max_results=8)))
        if keys.get("tavily"):
            tasks.append(_safe("tavily2", search_tavily(q, keys["tavily"], max_results=6)))
        if keys.get("serper"):
            tasks.append(_safe("serper2", search_serper(q, keys["serper"], max_results=6)))
        if keys.get("google_cse"):
            tasks.append(_safe("google_cse2", search_google_cse(q, keys["google_cse"], max_results=6)))
    chunks = await asyncio.gather(*tasks)
    flat: list[SourceResult] = []
    diag: dict[str, dict] = {}
    for name, results, err in chunks:
        flat.extend(results)
        diag[name] = {"count": len(results), "error": err}
    for s in flat:
        s.confidence = max(0.3, s.confidence - 0.1)
        s.raw["pass"] = 2
    return flat, diag


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
    search_keys: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict]:
    """
    intensity: 'quick' (1 pass) | 'deep' (2 pass)
    scope:     'web' | 'social' | 'all'
    search_keys: {'brave': '...', 'tavily': '...', 'serper': '...', 'google_cse': '...:...'}

    Döndürür: (sources, diagnostics) — diagnostics motor başına sayı + hata.
    """
    kind = detect_kind(target, kind_hint)
    query = _quote_for_search(target, kind)

    first: list[SourceResult] = []
    diag_combined: dict[str, dict] = {}
    if scope in ("web", "all"):
        results, diag = await _web_pass(query, target, kind, search_keys=search_keys)
        first.extend(results)
        diag_combined.update({f"web/{k}": v for k, v in diag.items()})
    if scope in ("social", "all"):
        results, diag = await _social_pass(query, target, kind)
        first.extend(results)
        diag_combined.update({f"social/{k}": v for k, v in diag.items()})

    enabled = [k for k, v in (search_keys or {}).items() if v]
    log.info("OSINT first pass: %d sources for %r (scope=%s, search APIs=%s)",
             len(first), target, scope, enabled or "none")

    if intensity == "deep" and scope in ("web", "all"):
        refined = _refine_queries(target, first, k=3)
        log.info("OSINT refined queries: %s", refined)
        second_results, diag = await _second_pass(query, refined, search_keys=search_keys)
        diag_combined.update({f"pass2/{k}": v for k, v in diag.items()})
        log.info("OSINT second pass: %d sources", len(second_results))
        all_results = first + second_results
    else:
        all_results = first

    filtered = _filter_relevance(target, kind, all_results)
    deduped = _dedupe(filtered)

    # Post-process: tracking ID çıkarımı (C5 LINKINT)
    tracking_results = extract_tracking_ids(deduped)
    if tracking_results:
        deduped.extend(r.to_dict() for r in tracking_results)
        log.info("OSINT tracking IDs: %d signals extracted", len(tracking_results))

    diagnostics = {
        "engines": diag_combined,
        "totals": {
            "raw": len(all_results),
            "after_filter": len(filtered),
            "after_dedupe": len(deduped),
        },
        "engines_with_results": sum(1 for v in diag_combined.values() if v["count"] > 0),
        "engines_failed": sum(1 for v in diag_combined.values() if v.get("error")),
        "engines_zero": sum(1 for v in diag_combined.values() if v["count"] == 0 and not v.get("error")),
    }
    return deduped, diagnostics


async def collect_geopoints(target: str, sources: list[dict[str, Any]]) -> list[dict]:
    """Pipeline çıktısından koordinat noktalarını çıkar (harita render için).
    Pipeline'dan ayrı çağrılır çünkü hem rapor JSON'una hem frontend'e ihtiyacı var."""
    return await extract_geopoints(target, sources)
