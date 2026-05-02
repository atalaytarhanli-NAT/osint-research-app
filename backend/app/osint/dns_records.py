"""DNS records lookup — B3 CYBINT (NATO/IC).

Cloudflare DNS-over-HTTPS (DoH) JSON API ile bir domain için A/AAAA/MX/NS/TXT/
CAA kayıtlarını çeker. SPF (TXT içinde) ve DMARC (`_dmarc.{domain}` TXT'sinde)
otomatik tespit edilir. Yeni dependency yok — sadece httpx.

Kind="url" hedefler için pipeline'da tetiklenir.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.dns_records")

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")


def _extract_domain(target: str) -> str:
    if "." not in target:
        return ""
    if target.startswith("http"):
        host = urlparse(target).hostname or ""
    else:
        host = target.strip()
    host = host.lower().rstrip("/")
    return host[4:] if host.startswith("www.") else host


async def _query(client: httpx.AsyncClient, name: str, qtype: str) -> list[str]:
    try:
        r = await client.get(
            DOH_ENDPOINT,
            params={"name": name, "type": qtype},
            headers={"Accept": "application/dns-json"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        if data.get("Status") != 0:
            return []
        return [a.get("data", "").strip('"') for a in data.get("Answer", []) if a.get("data")]
    except Exception as exc:
        log.warning("DoH %s/%s failed: %s", qtype, name, exc)
        return []


async def lookup_dns(target: str) -> list[SourceResult]:
    domain = _extract_domain(target)
    if not domain or " " in domain:
        return []

    out: list[SourceResult] = []
    async with httpx.AsyncClient(timeout=8.0) as c:
        records: dict[str, list[str]] = {}
        for qt in RECORD_TYPES:
            records[qt] = await _query(c, domain, qt)

        # DMARC ayrı: _dmarc.{domain} TXT
        records["DMARC"] = await _query(c, f"_dmarc.{domain}", "TXT")

    has_spf = any("v=spf1" in r.lower() for r in records.get("TXT", []))
    has_dmarc = any("v=dmarc1" in r.lower() for r in records.get("DMARC", []))

    # Tek özet kayıt: pipeline'a 1 satır SourceResult olarak gir
    summary_lines = []
    for rt in RECORD_TYPES:
        if records.get(rt):
            preview = ", ".join(records[rt][:3])
            summary_lines.append(f"{rt}({len(records[rt])}): {preview}")
    summary_lines.append(f"SPF: {'✓' if has_spf else '✗'}")
    summary_lines.append(f"DMARC: {'✓' if has_dmarc else '✗'}")

    if not any(records.values()):
        return []

    out.append(
        SourceResult(
            source="dns",
            url=f"https://dns.google/resolve?name={domain}&type=ANY",
            title=f"DNS kayıtları: {domain}",
            snippet=safe_truncate(" | ".join(summary_lines), 280),
            kind="cybint",
            confidence=0.85,
            raw={
                "domain": domain,
                "records": records,
                "spf_present": has_spf,
                "dmarc_present": has_dmarc,
            },
        )
    )

    # MX kayıtları → e-posta sağlayıcı sinyali (B3 CYBINT)
    if records.get("MX"):
        providers = []
        for mx in records["MX"][:5]:
            host = mx.split()[-1].rstrip(".") if " " in mx else mx
            if "google" in host:
                providers.append("Google Workspace")
            elif "outlook" in host or "office365" in host or "protection.outlook" in host:
                providers.append("Microsoft 365")
            elif "zoho" in host:
                providers.append("Zoho")
            elif "yandex" in host:
                providers.append("Yandex 360")
            elif "mailgun" in host:
                providers.append("Mailgun")
            elif "amazonses" in host:
                providers.append("Amazon SES")
        if providers:
            out.append(
                SourceResult(
                    source="dns",
                    url=f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}",
                    title=f"E-posta sağlayıcı: {', '.join(set(providers))}",
                    snippet=safe_truncate(
                        f"MX → {', '.join(records['MX'][:3])}", 280
                    ),
                    kind="cybint",
                    confidence=0.9,
                    raw={"providers": list(set(providers)), "mx": records["MX"]},
                )
            )

    return out
