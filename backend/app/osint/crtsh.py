"""crt.sh sertifika şeffaflığı — bir domain için subdomain keşfi (URL hedefleri için)."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.crtsh")


def _extract_domain(target: str) -> str:
    if "." not in target:
        return ""
    if target.startswith("http"):
        host = urlparse(target).hostname or ""
    else:
        host = target.strip()
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


async def search_crtsh(target: str, limit: int = 30) -> list[SourceResult]:
    domain = _extract_domain(target)
    if not domain or " " in domain:
        return []
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(url, params=params)
            if r.status_code != 200 or not r.text.strip():
                return []
            try:
                data = r.json()
            except Exception:
                return []
    except Exception as exc:
        log.warning("crt.sh failed: %s", exc)
        return []

    seen: set[str] = set()
    for row in data:
        names = (row.get("name_value") or "").split("\n")
        for name in names:
            name = name.strip().lower()
            if not name or name in seen or "*" in name:
                continue
            if not name.endswith(domain):
                continue
            seen.add(name)
            iso = (row.get("entry_timestamp") or "")[:10] or None
            out.append(
                SourceResult(
                    source="crtsh",
                    url=f"https://{name}",
                    title=name,
                    snippet=safe_truncate(
                        f"Cert transparency log entry — issuer: {row.get('issuer_name','?')}", 240
                    ),
                    published_at=iso,
                    kind="archive",
                    confidence=0.7,
                    raw={"issuer": row.get("issuer_name"), "id": row.get("id")},
                )
            )
            if len(out) >= limit:
                return out
    return out
