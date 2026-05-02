"""Aday görsel arama — kişi/kurum sorgusuna potansiyel görseller bulur.

Kullanıcı raporda eş isim çakışması veya yetersiz hedefleme yaşadığında
'aday görseller' paneli sunulur — kullanıcı doğru kişiyi seçip o görselle
Yüz Araması başlatabilir.

Bing Images + DDG Images HTML scrape (key gerekmez). Render IP'sinde
captcha yiyebilir; o durumda boş döner, frontend yardım mesajı gösterir.
"""

from __future__ import annotations

import json
import logging
import random
import re
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import quote_plus, urlparse

import httpx
from bs4 import BeautifulSoup


log = logging.getLogger("osint.image_candidates")


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
]


@dataclass
class ImageCandidate:
    """Tek bir aday görsel."""
    thumb_url: str
    full_url: str
    source_url: str = ""    # Görselin geldiği sayfa
    title: str = ""
    domain: str = ""
    width: Optional[int] = None
    height: Optional[int] = None
    engine: str = "?"        # 'bing' / 'ddg'

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d.get("domain") and d.get("source_url"):
            try:
                d["domain"] = urlparse(d["source_url"]).netloc
            except Exception:
                pass
        return d


async def _bing_images(query: str, max_results: int = 20) -> list[ImageCandidate]:
    url = f"https://www.bing.com/images/search?q={quote_plus(query)}&form=HDRSC2&first=1"
    headers = {
        "User-Agent": random.choice(UA_POOL),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7",
    }
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as c:
            r = await c.get(url)
            if r.status_code != 200:
                log.info("bing images status=%s", r.status_code)
                return []
            html = r.text
    except Exception as exc:
        log.warning("bing images failed: %s", exc)
        return []

    soup = BeautifulSoup(html, "lxml")
    out: list[ImageCandidate] = []
    # Bing image cards: <a class="iusc" m='{"murl":"...","purl":"...","t":"..."}'>
    for a in soup.select("a.iusc")[:max_results]:
        m = a.get("m")
        if not m:
            continue
        try:
            meta = json.loads(m)
        except (json.JSONDecodeError, TypeError):
            continue
        full = meta.get("murl") or meta.get("turl") or ""
        thumb = meta.get("turl") or full
        source = meta.get("purl") or ""
        title = (meta.get("t") or meta.get("desc") or "").strip()
        if not full.startswith("http"):
            continue
        out.append(ImageCandidate(
            thumb_url=thumb, full_url=full,
            source_url=source, title=title[:200],
            engine="bing",
        ))
    log.info("bing images: %d candidates for %r", len(out), query)
    return out


async def _ddg_images(query: str, max_results: int = 20) -> list[ImageCandidate]:
    """DDG image search: 1) /js token al, 2) i.js?vqd=token endpoint."""
    headers = {
        "User-Agent": random.choice(UA_POOL),
        "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7",
    }
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as c:
            # 1) vqd token al
            r1 = await c.get(
                "https://duckduckgo.com/",
                params={"q": query, "iax": "images", "ia": "images"},
            )
            if r1.status_code != 200:
                return []
            m = re.search(r'vqd="?([\d-]+)"?', r1.text)
            if not m:
                # Yeni format: vqd='1-2-...'
                m = re.search(r"vqd=([\d-]+)", r1.text)
                if not m:
                    return []
            vqd = m.group(1)

            # 2) i.js JSON endpoint
            r2 = await c.get(
                "https://duckduckgo.com/i.js",
                params={"l": "tr-tr", "o": "json", "q": query, "vqd": vqd, "f": ",,,", "p": "1"},
            )
            if r2.status_code != 200:
                return []
            data = r2.json()
    except Exception as exc:
        log.warning("ddg images failed: %s", exc)
        return []

    out: list[ImageCandidate] = []
    for item in (data.get("results") or [])[:max_results]:
        full = item.get("image") or ""
        thumb = item.get("thumbnail") or full
        if not full.startswith("http"):
            continue
        out.append(ImageCandidate(
            thumb_url=thumb, full_url=full,
            source_url=item.get("url", ""),
            title=(item.get("title") or "")[:200],
            width=item.get("width"), height=item.get("height"),
            engine="ddg",
        ))
    log.info("ddg images: %d candidates for %r", len(out), query)
    return out


async def fetch_image_candidates(
    target: str, kind: str = "person", max_results: int = 24,
) -> list[dict]:
    """Aday görsellerini çoklu motor ile getir, dedupe et."""
    if kind not in ("person", "organization", "auto"):
        return []
    target = target.strip()
    if len(target) < 2:
        return []

    # Bing önce (genelde daha tutarlı), DDG fallback
    candidates = await _bing_images(target, max_results=max_results)
    if not candidates:
        candidates = await _ddg_images(target, max_results=max_results)
    elif len(candidates) < 8:
        # Bing az dönerse DDG ile birleştir
        ddg = await _ddg_images(target, max_results=max_results)
        candidates.extend(ddg)

    # Dedupe by full_url
    seen: set[str] = set()
    out: list[dict] = []
    for c in candidates:
        key = (c.full_url or "").rstrip("/").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(c.to_dict())
        if len(out) >= max_results:
            break
    return out
