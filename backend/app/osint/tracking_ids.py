"""Tracking ID extraction — C5 LINKINT (NATO/IC).

Pasif modül: pipeline'da toplanmış mevcut kaynakların (web/wiki vs) snippet/
title alanlarından Google Analytics, AdSense, GTM, Facebook Pixel ID'lerini
regex ile çıkar. Bunlar başka domainlerde tekrar gözükürse aynı sahip/operatör
sinyali (Paylaşılan Sinyaller — C5).

Yeni dependency yok. Toplama sonrası post-process olarak çağırılır.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from urllib.parse import urlparse

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.tracking_ids")


PATTERNS = {
    "GA_UA": re.compile(r"\bUA-\d{4,10}-\d{1,4}\b"),
    "GA4": re.compile(r"\bG-[A-Z0-9]{8,12}\b"),
    "GTM": re.compile(r"\bGTM-[A-Z0-9]{5,8}\b"),
    "AdSense": re.compile(r"\bpub-\d{15,17}\b"),
    "FB_Pixel": re.compile(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{14,17})['\"]"),
    "Yandex_Metrica": re.compile(r"yandex_metrika_counter[s]?[\s\S]{0,40}?(\d{6,10})"),
    "Hotjar": re.compile(r"hjid\s*[:=]\s*[\"']?(\d{6,8})"),
    "Twitter_uwt": re.compile(r"twttr\.[a-z_]+\s*\(\s*['\"]?([a-z0-9]{6,12})"),
}


def extract_tracking_ids(sources: list[dict]) -> list[SourceResult]:
    """Mevcut kaynaklardan tracking ID'leri çıkar, ID başına 1 SourceResult üret."""
    if not sources:
        return []

    # ID → list of (source_idx, domain) mapping
    found: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)
    for i, s in enumerate(sources):
        text = " ".join([s.get("title") or "", s.get("snippet") or "", s.get("url") or ""])
        if not text.strip():
            continue
        domain = ""
        try:
            domain = urlparse(s.get("url", "")).hostname or ""
        except Exception:
            pass

        for label, rx in PATTERNS.items():
            for m in rx.findall(text):
                tid = m if isinstance(m, str) else m[0]
                found[(label, tid)].append((i, domain))

    out: list[SourceResult] = []
    for (label, tid), refs in found.items():
        domains = sorted({d for _, d in refs if d})
        idxs = sorted({i for i, _ in refs})
        # Sadece en az 1 farklı domain'de görünenler (gürültüyü ele)
        if not domains:
            continue
        cross_domain = len(domains) >= 2
        out.append(
            SourceResult(
                source="tracking_id",
                url=f"https://www.google.com/search?q=%22{tid}%22",
                title=f"{'🔗 Cross-domain' if cross_domain else '◇'} Tracking ID: {label} = {tid}",
                snippet=safe_truncate(
                    f"{label} ID '{tid}' {len(domains)} farklı domain'de görüldü: "
                    f"{', '.join(domains[:5])}. "
                    f"{'Aynı operatör/sahip sinyali — LINKINT C5.' if cross_domain else 'Tek domain — düşük sinyal.'}",
                    280,
                ),
                kind="link_signal",
                confidence=0.85 if cross_domain else 0.5,
                raw={
                    "id_type": label,
                    "id_value": tid,
                    "domains": domains,
                    "source_indices": idxs,
                    "cross_domain": cross_domain,
                },
            )
        )
    # Cross-domain'leri öne sırala
    out.sort(key=lambda x: (not x.raw.get("cross_domain"), -len(x.raw.get("domains", []))))
    return out[:10]
