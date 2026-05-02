"""Yaptırım listesi eşleme — B7 CORPINT/PERSINT (NATO/IC).

OpenSanctions.org public API ile global yaptırım listesinde (OFAC SDN, EU CFSP,
UK HMT, UN Security Council, MASAK PEP listesi, Türkiye, Russia listesi vb.)
kişi/kurum adı eşleştirir. Tek API'den tüm major listelerin birleşimi.

Ücretsiz tier: ~1000 sorgu/gün, key gerekmez.
https://api.opensanctions.org/
"""

from __future__ import annotations

import logging

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.sanctions")


async def search_sanctions(target: str, kind: str = "person", limit: int = 5) -> list[SourceResult]:
    """OpenSanctions search API — kişi/kurum adı ile yaptırım eşleşmesi tara."""
    target = (target or "").strip()
    if not target or len(target) < 3:
        return []
    if kind == "url" or " " not in target and len(target) < 5:
        # URL veya çok kısa hedeflerde anlamsız
        return []

    schema = "Person" if kind == "person" else "Organization" if kind == "organization" else None
    params = {"q": target, "limit": limit}
    if schema:
        params["schema"] = schema

    out: list[SourceResult] = []
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get("https://api.opensanctions.org/search/default", params=params)
            if r.status_code != 200:
                log.info("opensanctions status=%s for %r", r.status_code, target)
                return []
            data = r.json()
    except Exception as exc:
        log.warning("opensanctions failed: %s", exc)
        return []

    results = data.get("results", []) or []
    for hit in results[:limit]:
        caption = hit.get("caption") or "(unnamed)"
        datasets = hit.get("datasets") or []
        topics = hit.get("properties", {}).get("topics", []) or []
        countries = hit.get("properties", {}).get("country", []) or []
        score = hit.get("score") or 0.0
        if score < 0.6:
            # Düşük match score'ları ele
            continue
        ds_label = ", ".join(datasets[:5]) if datasets else "—"
        topic_label = ", ".join(topics[:3]) if topics else "—"
        country_label = ", ".join(countries[:3]) if countries else "—"
        snippet = (
            f"Yaptırım/PEP eşleşmesi (score={score:.2f}). "
            f"Liste: {ds_label}. Konu: {topic_label}. Ülke: {country_label}."
        )
        out.append(
            SourceResult(
                source="opensanctions",
                url=f"https://www.opensanctions.org/entities/{hit.get('id', '')}/",
                title=f"⚠ Yaptırım/PEP: {caption}",
                snippet=safe_truncate(snippet, 280),
                kind="sanction",
                confidence=min(0.95, float(score)),
                raw={
                    "id": hit.get("id"),
                    "datasets": datasets,
                    "topics": topics,
                    "countries": countries,
                    "score": score,
                    "schema": hit.get("schema"),
                },
            )
        )
    return out
