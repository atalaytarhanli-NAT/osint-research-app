"""UK Companies House — B1 CORPINT (Kurumsal Yapı).

UK halka açık şirket kayıtları için ücretsiz API. Anahtar gerekir ama ücretsiz
tier var (https://developer.company-information.service.gov.uk/). Anahtar
yoksa modul sessizce skip eder.

Hedef şirket adıyla company search yapar, ana şirket + officer'ları + filings
özeti döner.
"""

from __future__ import annotations

import base64
import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.companies_house")


SEARCH_URL = "https://api.company-information.service.gov.uk/search/companies"


async def search_companies_house(target: str, api_key: str, limit: int = 5) -> list[SourceResult]:
    """Companies House (UK) — anahtar varsa şirket arama."""
    target = (target or "").strip()
    if not api_key or len(target) < 3 or "@" in target or target.startswith("http"):
        return []

    # API key Basic Auth (key:'' yerine 'key:')
    auth = base64.b64encode(f"{api_key}:".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}

    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as c:
            r = await c.get(SEARCH_URL, params={"q": target, "items_per_page": limit})
            if r.status_code != 200:
                log.info("companies_house status=%s", r.status_code)
                return []
            data = r.json()
    except Exception as exc:
        log.warning("companies_house failed: %s", exc)
        return []

    for item in (data.get("items") or [])[:limit]:
        title = item.get("title") or "(unnamed)"
        company_number = item.get("company_number")
        company_status = item.get("company_status") or "?"
        company_type = item.get("company_type") or "?"
        date_of_creation = item.get("date_of_creation")
        addr = (item.get("address_snippet") or "").strip()
        url = f"https://find-and-update.company-information.service.gov.uk/company/{company_number}" if company_number else "https://find-and-update.company-information.service.gov.uk/"
        out.append(
            SourceResult(
                source="companies_house",
                url=url,
                title=f"UK Companies House: {title}",
                snippet=safe_truncate(
                    f"No: {company_number or '?'} · Durum: {company_status} · "
                    f"Tip: {company_type} · Kuruluş: {date_of_creation or '?'}. "
                    f"Adres: {addr or '—'}",
                    280,
                ),
                published_at=date_of_creation,
                kind="corp_registry",
                confidence=0.95,
                raw={
                    "company_number": company_number,
                    "status": company_status,
                    "type": company_type,
                    "address": addr,
                },
            )
        )
    return out
