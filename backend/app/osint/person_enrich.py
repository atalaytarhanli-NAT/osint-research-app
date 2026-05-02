"""Kişi/kurum hedefler için varyasyon-bazlı enrichment — Faz 1 (Identifier
Harmanlama, NATO/IC). Hedeften türeyebilecek tüm makul varyasyonları
sistematik olarak çıkarır:

- Latin transliterasyon (Türkçe ç→c, ğ→g, ı→i, ö→o, ş→s, ü→u)
- Site-spesifik aramalar (LinkedIn/GitHub/ORCID/ResearchGate/Crunchbase/
  Bloomberg/AngelList/SEC EDGAR/Companies House/KAP)
- Profil/biyografi/CV sorguları
- E-posta pattern keşfi (firstname.lastname@, flastname@, fl@)
- Kurum için: VKN/MERSIS/Ticaret Sicil/stock ticker/DUNS/LEI sorguları
- Bağlı/iştirak/kardeş şirket sorguları
"""

from __future__ import annotations

import asyncio
import logging
import re
import unicodedata

from .base import SourceResult
from .bing_search import search_bing
from .mojeek_search import search_mojeek
from .web_search import search_web
from .yandex_search import search_yandex


log = logging.getLogger("osint.person_enrich")


# Türkçe → Latin transliterasyon tablosu
_TR_TRANSLIT = {
    "ç": "c", "Ç": "C", "ğ": "g", "Ğ": "G", "ı": "i", "I": "I",
    "İ": "I", "ö": "o", "Ö": "O", "ş": "s", "Ş": "S", "ü": "u", "Ü": "U",
}


def _translit(s: str) -> str:
    return "".join(_TR_TRANSLIT.get(c, c) for c in s)


def _ascii_fold(s: str) -> str:
    """Türkçe karakterleri normalize et + accent stripping."""
    s = _translit(s)
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _is_likely_person(target: str) -> bool:
    t = target.strip()
    if " " not in t:
        return False
    parts = t.split()
    if not 2 <= len(parts) <= 4:
        return False
    return sum(1 for p in parts if p[:1].isupper()) >= max(1, len(parts) - 1)


def _username_seeds(name: str) -> list[str]:
    """İsmden makul kullanıcı adı varyasyonları (e-posta + handle pattern'leri için)."""
    parts = [p for p in re.split(r"\s+", _ascii_fold(name).lower()) if p]
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    first, last = parts[0], parts[-1]
    return [
        f"{first}.{last}",
        f"{first}{last}",
        f"{first[0]}{last}",
        f"{first}_{last}",
        f"{first}-{last}",
        f"{last}.{first}",
        f"{last}{first[0]}",
    ]


_PERSON_VARIATIONS = [
    "{q} LinkedIn",
    "{q} biography biyografi",
    "{q} CV resume özgeçmiş",
    '"{q}" profile',
    "{q} interview röportaj",
    'site:linkedin.com/in "{q}"',
    'site:github.com "{q}"',
    'site:orcid.org "{q}"',
    'site:researchgate.net "{q}"',
    'site:scholar.google.com "{q}"',
    'site:medium.com "{q}"',
    'site:twitter.com OR site:x.com "{q}"',
    'site:crunchbase.com "{q}"',
    'site:bloomberg.com "{q}"',
    'site:about.me "{q}"',
    '"{q}" patent inventor',
    '"{q}" konferans speaker',
]

# Latin transliterasyon eklenir
_PERSON_VARIATIONS_LATIN = [
    '"{q_latin}" LinkedIn',
    'site:linkedin.com/in "{q_latin}"',
    '"{q_latin}" CV',
]

# E-posta pattern keşfi (yapı: kullanıcı kombinasyonu + olası domainler arama)
_EMAIL_PATTERN_QUERIES = [
    '"{u1}@" OR "{u2}@" OR "{u3}@"',  # public mention'larda email arama
]

_ORG_VARIATIONS = [
    "{q} headquarters",
    "{q} CEO founder",
    "{q} crunchbase",
    "{q} annual report yıllık rapor",
    '"{q}" controversy criticism',
    'site:crunchbase.com "{q}"',
    'site:bloomberg.com "{q}"',
    'site:sec.gov "{q}"',
    'site:opencorporates.com "{q}"',
    'site:gov.uk/find-and-update-company-information "{q}"',
    "{q} VKN MERSIS Ticaret Sicil",
    "{q} ticaret sicil gazetesi",
    "{q} KAP açıklama",
    '"{q}" stock ticker NYSE NASDAQ BIST',
    "{q} subsidiary parent company iştirak",
    "{q} ASN AS-number IP block",
    '"{q}" lawsuit dava antitrust',
    '"{q}" data breach veri ihlali',
    '"{q}" annual revenue gelir',
]

# Kurum: yaptırım/uyumluluk arama (Düzenleyici — B7'nin SERP tarafı)
_ORG_COMPLIANCE = [
    '"{q}" OFAC sanctions',
    '"{q}" PEP politically exposed',
    '"{q}" MASAK',
]


async def _safe(name: str, coro):
    try:
        return await coro
    except Exception as exc:
        log.warning("enrich %s failed: %s", name, exc)
        return []


async def enrich_with_variations(target: str, kind: str, per_engine: int = 5) -> list[SourceResult]:
    is_person = kind == "person" or (kind in ("auto", "") and _is_likely_person(target))
    is_org = kind in ("organization",) or (
        kind in ("auto", "") and not is_person and not target.startswith("@") and "." not in target
    )

    if not (is_person or is_org):
        return []

    target_latin = _ascii_fold(target)
    needs_latin = target_latin != target  # Türkçe karakter varsa transliterasyon değerlidir

    queries: list[str] = []

    if is_person:
        for tpl in _PERSON_VARIATIONS:
            queries.append(tpl.format(q=target))
        if needs_latin:
            for tpl in _PERSON_VARIATIONS_LATIN:
                queries.append(tpl.format(q_latin=target_latin))
        # E-posta pattern arama
        seeds = _username_seeds(target)[:3]
        if len(seeds) >= 3:
            queries.append(_EMAIL_PATTERN_QUERIES[0].format(u1=seeds[0], u2=seeds[1], u3=seeds[2]))
    elif is_org:
        for tpl in _ORG_VARIATIONS:
            queries.append(tpl.format(q=target))
        for tpl in _ORG_COMPLIANCE:
            queries.append(tpl.format(q=target))
        if needs_latin:
            queries.append(f'"{target_latin}" company')

    # Engines arasında round-robin
    engines = [search_web, search_bing, search_yandex, search_mojeek]
    tasks = []
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
    log.info(
        "enrich: target=%r kind=%s queries=%d results=%d (latin=%s)",
        target, kind, len(queries), len(out), needs_latin,
    )
    return out
