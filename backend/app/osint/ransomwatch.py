"""Ransomwatch — B9 CORPINT (Tehdit Maruziyeti).

ransomwatch.telemetry.ltd public JSON feed: ransomware aktörlerinin leak
sitelerinden çekilen kurban listesi. Şirketin daha önce ransomware grubu
tarafından isimlendirilip isimlendirilmediğini gösterir.

Anahtar gerekmez, ücretsiz public dataset.
"""

from __future__ import annotations

import logging
from functools import lru_cache

import httpx

from .base import SourceResult, safe_truncate


log = logging.getLogger("osint.ransomwatch")


VICTIMS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"


_cache: dict = {"data": None, "fetched": False}


async def _fetch_victims() -> list[dict]:
    """In-memory cache — ilk çağrıda indir, sonraki çağrılarda kullan."""
    if _cache["fetched"]:
        return _cache["data"] or []
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(VICTIMS_URL)
            if r.status_code != 200:
                log.info("ransomwatch fetch status=%s", r.status_code)
                _cache["fetched"] = True
                _cache["data"] = []
                return []
            data = r.json()
    except Exception as exc:
        log.warning("ransomwatch fetch failed: %s", exc)
        _cache["fetched"] = True
        _cache["data"] = []
        return []
    _cache["fetched"] = True
    _cache["data"] = data
    log.info("ransomwatch loaded %d victim entries", len(data))
    return data


def _normalize(s: str) -> str:
    return "".join(c.lower() for c in (s or "") if c.isalnum())


async def check_ransomwatch(target: str, limit: int = 5) -> list[SourceResult]:
    """Hedef ismin ransomware leak sitelerinde geçip geçmediğini kontrol et."""
    target = (target or "").strip()
    if len(target) < 4:
        return []

    victims = await _fetch_victims()
    if not victims:
        return []

    target_norm = _normalize(target)
    if len(target_norm) < 4:
        return []

    out: list[SourceResult] = []
    for v in victims:
        post_title = v.get("post_title") or ""
        if _normalize(post_title) and target_norm in _normalize(post_title):
            group = v.get("group_name") or "?"
            date = v.get("discovered") or v.get("published")
            url = v.get("post_url") or f"https://ransomwatch.telemetry.ltd/#/group/{group}"
            out.append(
                SourceResult(
                    source="ransomwatch",
                    url=url,
                    title=f"⚠ Ransomware: {post_title} (grup: {group})",
                    snippet=safe_truncate(
                        f"Ransomware aktör tarafından isimlendirildi. Grup: {group}. "
                        f"Tarih: {date or '—'}. Aktör leak sitesinde post bulundu — "
                        f"veri ihlali/sızıntı sinyali, hukuki bildirim yükümlülüğü olabilir.",
                        280,
                    ),
                    published_at=(date or "")[:10] if date else None,
                    kind="threat_exposure",
                    confidence=0.9,
                    raw={"group": group, "post_title": post_title, "discovered": date},
                )
            )
            if len(out) >= limit:
                break
    return out
