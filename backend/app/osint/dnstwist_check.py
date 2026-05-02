"""dnstwist typo-squat tarama — B4 CORPINT/Saldırı Yüzeyi (NATO/IC).

Bir domain için homoglyph/typo/addition/subdomain permutasyonları üretir,
canlı (registered) olanları DNS lookup ile tespit eder. Phishing/brand-spoofing
saldırı yüzeyini haritalar.

Pip dependency: dnstwist (pure-Python, gerekirse).
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.dnstwist")


def _extract_domain(target: str) -> str:
    if "." not in target:
        return ""
    if target.startswith("http"):
        host = urlparse(target).hostname or ""
    else:
        host = target.strip()
    host = host.lower().rstrip("/")
    return host[4:] if host.startswith("www.") else host


def _scan_sync(domain: str, max_perms: int = 60) -> list[dict]:
    """dnstwist'i sync olarak çalıştır (kütüphane sync). asyncio.to_thread() ile sarmalanır."""
    try:
        import dnstwist  # type: ignore
    except ImportError:
        log.info("dnstwist not installed; skipping typo-squat check")
        return []

    try:
        fuzz = dnstwist.DomainFuzz(domain)
        fuzz.generate()
        # İlk N permutasyona bak (homoglyph/typo öncelikli) — full scan saatler sürer
        domains = fuzz.domains[:max_perms]
        scanner = dnstwist.Scanner(domains=domains, threadcount=8)
        scanner.option_extdns = False
        scanner.option_geoip = False
        scanner.option_ssdeep = False
        scanner.option_banners = False
        scanner.option_lsh = None
        scanner.option_mxcheck = False
        scanner.run()
        results = []
        for d in scanner.domains:
            if d.get("dns_a") or d.get("dns_aaaa") or d.get("dns_ns"):
                # canlı (registered) — risk
                results.append({
                    "domain": d.get("domain"),
                    "fuzzer": d.get("fuzzer"),
                    "ip": (d.get("dns_a") or [None])[0] if d.get("dns_a") else None,
                    "ns": (d.get("dns_ns") or [None])[0] if d.get("dns_ns") else None,
                })
        return results
    except Exception as exc:
        log.warning("dnstwist scan failed: %s", exc)
        return []


async def check_typosquats(target: str) -> list[SourceResult]:
    domain = _extract_domain(target)
    if not domain or " " in domain:
        return []

    try:
        # Library sync; thread'e at, max 25 sn timeout
        results = await asyncio.wait_for(
            asyncio.to_thread(_scan_sync, domain), timeout=25.0
        )
    except asyncio.TimeoutError:
        log.warning("dnstwist timeout for %s", domain)
        return []
    except Exception as exc:
        log.warning("dnstwist async wrapper failed: %s", exc)
        return []

    out: list[SourceResult] = []
    for r in results[:15]:
        d = r["domain"]
        fuzzer = r.get("fuzzer", "?")
        ip = r.get("ip") or "—"
        out.append(
            SourceResult(
                source="dnstwist",
                url=f"http://{d}",
                title=f"⚠ Typosquat: {d}",
                snippet=safe_truncate(
                    f"Permutation type: {fuzzer}. Canlı kayıt (IP: {ip}). "
                    f"Olası phishing/brand-spoofing yüzeyi — manuel doğrulama gerekir.",
                    280,
                ),
                kind="attack_surface",
                confidence=0.7,
                raw={"fuzzer": fuzzer, "ip": ip, "ns": r.get("ns")},
            )
        )
    return out
