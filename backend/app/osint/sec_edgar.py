"""SEC EDGAR full-text arama — B2 CORPINT (Finansal Açıklamalar) + B5 (Hukuki/Dava).

ABD halka açık şirketleri ve onlarla ilgili filings (10-K, 10-Q, 8-K, lawsuit
disclosures, S-1, vb.) için public arama. Anahtar gerekmez. SEC, scraping yerine
JSON endpoint sağlar.
"""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.sec_edgar")


SEARCH_ENDPOINT = "https://efts.sec.gov/LATEST/search-index"
USER_AGENT = "OSINT Research App contact@example.com"  # SEC zorunlu UA gerek


async def search_sec_edgar(target: str, limit: int = 8) -> list[SourceResult]:
    """SEC EDGAR full-text search — şirket adı/CIK üzerinden filings."""
    target = (target or "").strip()
    if len(target) < 3 or "@" in target or target.startswith("http"):
        return []

    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(
            timeout=10.0, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        ) as c:
            r = await c.get(SEARCH_ENDPOINT, params={"q": f'"{target}"', "dateRange": "custom",
                                                     "startdt": "2015-01-01", "forms": ""})
            if r.status_code != 200:
                log.info("sec_edgar status=%s", r.status_code)
                return []
            data = r.json()
    except Exception as exc:
        log.warning("sec_edgar failed: %s", exc)
        return []

    hits = (data.get("hits") or {}).get("hits") or []
    for h in hits[:limit]:
        src = h.get("_source", {}) or {}
        adsh = h.get("_id", "").split(":")[0]
        cik = (src.get("ciks") or [""])[0]
        form = src.get("form") or "?"
        display_names = src.get("display_names") or []
        company = display_names[0] if display_names else "?"
        date = src.get("file_date")
        if not adsh or not cik:
            continue
        adsh_clean = adsh.replace("-", "")
        url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&type={form}&dateb=&owner=include&count=10"
        out.append(
            SourceResult(
                source="sec_edgar",
                url=url,
                title=f"SEC {form}: {company}",
                snippet=safe_truncate(
                    f"Form {form} — CIK {cik}, accession {adsh}. "
                    f"{src.get('xsl', '')} {src.get('description', '')}".strip(),
                    280,
                ),
                published_at=date,
                kind="financial",
                confidence=0.9,
                raw={"form": form, "cik": cik, "adsh": adsh, "company": company},
            )
        )
    return out
