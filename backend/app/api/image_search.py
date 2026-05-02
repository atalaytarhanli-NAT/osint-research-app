"""Görsel ters arama API.

Görsel YALNIZCA geçici (TTL'li) host'larda saklanır ve otomatik silinir.
Anthropic veya Render sunucusunda kalıcı saklanmaz.

Fallback chain (Render dahil herhangi bir IP'den çalışır):
  1. litterbox.catbox.moe — 1h/12h/24h/72h TTL seçenekleri
  2. uguu.se — 30 dk TTL (sabit)

İki endpoint:
- POST /api/image/reverse {url} — verilen URL → reverse search linkleri
- POST /api/image/upload (multipart) — dosya → temp host → reverse search linkleri
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..crypto import decrypt
from ..database import get_db
from ..face_search import AdapterOrchestrator
from ..models import ApiKey, SystemApiKey, User
from ..osint.exif_extract import extract_exif


log = logging.getLogger("image_search")
router = APIRouter(prefix="/api/image", tags=["image"])

ALLOWED_TTL = {"1h", "12h", "24h", "72h"}
DEFAULT_TTL = "1h"
MAX_BYTES = 10 * 1024 * 1024  # 10 MB

# Some browsers may send octet-stream; we trust the file extension in that case.
ALLOWED_MIME_PREFIX = ("image/",)


class ImageSearchOut(BaseModel):
    image_url: str
    reverse_links: dict[str, str]
    ttl: Optional[str] = None
    host: Optional[str] = None
    note: Optional[str] = None
    exif: Optional[dict] = None  # EXIF metadata (A9 IMINT) — sadece upload'da


class ImageUrlIn(BaseModel):
    url: HttpUrl


def _build_reverse_links(image_url: str) -> dict[str, str]:
    enc = quote_plus(image_url)
    return {
        "google_lens": f"https://lens.google.com/uploadbyurl?url={enc}",
        "google_images": f"https://www.google.com/searchbyimage?image_url={enc}",
        "yandex_images": f"https://yandex.com/images/search?rpt=imageview&url={enc}",
        "tineye": f"https://www.tineye.com/search?url={enc}",
        "bing_visual": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIDP&sbisrc=UrlPaste&q=imgurl%3A{enc}",
        "baidu_images": f"https://image.baidu.com/n/pc_search?queryImageUrl={enc}",
    }


@router.post("/reverse", response_model=ImageSearchOut)
def reverse_by_url(data: ImageUrlIn, _: User = Depends(get_current_user)):
    return ImageSearchOut(
        image_url=str(data.url),
        reverse_links=_build_reverse_links(str(data.url)),
        host="external",
        note="URL'yi sen verdin, biz hiçbir yere yüklemedik.",
    )


# ---------- temp host implementations ----------


async def _upload_litterbox(
    client: httpx.AsyncClient, filename: str, content: bytes, mime: str, ttl: str
) -> tuple[str, str]:
    """Returns (image_url, ttl). Raises on failure."""
    r = await client.post(
        "https://litterbox.catbox.moe/resources/internals/api.php",
        data={"reqtype": "fileupload", "time": ttl},
        files={"fileToUpload": (filename, content, mime)},
    )
    text = r.text.strip()
    if r.status_code != 200 or not text.startswith("http"):
        raise RuntimeError(f"litterbox HTTP {r.status_code}: {text[:200] or 'empty body'}")
    return text, ttl


async def _upload_uguu(
    client: httpx.AsyncClient, filename: str, content: bytes, mime: str
) -> tuple[str, str]:
    """Returns (image_url, '30m'). Raises on failure."""
    r = await client.post(
        "https://uguu.se/upload.php",
        files={"files[]": (filename, content, mime)},
    )
    if r.status_code != 200:
        raise RuntimeError(f"uguu HTTP {r.status_code}: {r.text[:200]}")
    try:
        data = json.loads(r.text)
        url = data["files"][0]["url"]
    except Exception as exc:
        raise RuntimeError(f"uguu parse: {exc} body={r.text[:200]!r}")
    if not url.startswith("http"):
        raise RuntimeError(f"uguu invalid URL: {url}")
    return url, "30m"


@router.post("/upload", response_model=ImageSearchOut)
async def reverse_by_upload(
    file: UploadFile = File(...),
    ttl: str = Form(default=DEFAULT_TTL),
    _: User = Depends(get_current_user),
):
    if ttl not in ALLOWED_TTL:
        ttl = DEFAULT_TTL

    if file.content_type and not (
        file.content_type.startswith(ALLOWED_MIME_PREFIX)
        or file.content_type == "application/octet-stream"
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Sadece görsel dosyaları kabul edilir (MIME: {file.content_type}).",
        )

    content = await file.read()
    size = len(content)
    if size > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Dosya çok büyük: {size / 1_048_576:.1f} MB (maksimum 10 MB).",
        )
    if size < 32:
        raise HTTPException(status_code=400, detail="Dosya boş veya çok küçük.")

    filename = file.filename or "image.jpg"
    mime = file.content_type or "image/jpeg"

    # EXIF extraction — A9 IMINT (NATO/IC). Pillow yoksa graceful skip.
    exif_data = extract_exif(content)

    timeout = httpx.Timeout(connect=10.0, read=90.0, write=60.0, pool=10.0)
    headers = {"User-Agent": "OsintResearchApp/1.0"}

    errors: list[str] = []
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        # 1. Try litterbox (with selected TTL)
        try:
            url, used_ttl = await _upload_litterbox(client, filename, content, mime, ttl)
            return ImageSearchOut(
                image_url=url,
                reverse_links=_build_reverse_links(url),
                ttl=used_ttl,
                host="litterbox.catbox.moe",
                note=f"~{used_ttl} sonra otomatik silinir. Sunucumuzda saklanmadı.",
                exif=exif_data,
            )
        except Exception as exc:
            log.warning("litterbox upload failed: %s", exc)
            errors.append(f"litterbox: {exc}")

        # 2. Fallback: uguu (30m fixed)
        try:
            url, used_ttl = await _upload_uguu(client, filename, content, mime)
            return ImageSearchOut(
                image_url=url,
                reverse_links=_build_reverse_links(url),
                ttl=used_ttl,
                host="uguu.se",
                note=f"~{used_ttl} sonra otomatik silinir (uguu.se yedek host). Sunucumuzda saklanmadı.",
                exif=exif_data,
            )
        except Exception as exc:
            log.warning("uguu upload failed: %s", exc)
            errors.append(f"uguu: {exc}")

    raise HTTPException(
        status_code=502,
        detail=(
            "Tüm geçici barındırma servisleri başarısız: "
            + " | ".join(errors)
            + ". Görsel URL'sini biliyorsan onu yapıştırarak ters arama yapabilirsin."
        ),
    )


# ===== Face / Reverse Image Search (10 dış adaptör) =====


_FACE_ADAPTER_PROVIDER_IDS = (
    "facecheck", "pimeyes", "lenso", "faceseek", "tineye",
    "bing_visual", "google_vision", "saucenao",
)


def _collect_face_keys(user_id: int, db: Session) -> dict[str, str | None]:
    """User key öncelikli, sonra sistem key, sonra env var. Her adaptör için."""
    user_keys = {
        k.provider: decrypt(k.encrypted_value)
        for k in db.scalars(select(ApiKey).where(ApiKey.user_id == user_id)).all()
    }
    sys_keys = {
        r.provider: decrypt(r.encrypted_value)
        for r in db.scalars(
            select(SystemApiKey).where(SystemApiKey.enabled == True)  # noqa
        ).all()
    }
    out: dict[str, str | None] = {}
    for pid in _FACE_ADAPTER_PROVIDER_IDS:
        out[pid] = (
            user_keys.get(pid)
            or sys_keys.get(pid)
            or os.environ.get(f"APP_{pid.upper()}_API_KEY")
            or None
        )
    return out


@router.get("/face-search/adapters")
def list_face_adapters(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Yapılandırılmış (etkin) yüz/görsel arama adaptörlerini listele."""
    keys = _collect_face_keys(user.id, db)
    orch = AdapterOrchestrator(api_keys=keys)
    return orch.available


@router.post("/face-search")
async def face_search(
    image: UploadFile = File(...),
    adapters: Optional[str] = Form(
        None,
        description="Virgülle ayrılmış adaptör listesi. Boş ise tüm etkinler kullanılır.",
    ),
    timeout_seconds: int = Form(120, ge=10, le=600),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Yüz/görsel ile dış servislerde paralel arama (10 adaptör destekli).

    UYARI (KVKK): Bu sorgu görseli ABD/AB/RU sunucularına gönderir. Açık rıza
    veya meşru menfaat dayanağı şart. Yandex/Search4Faces (RU) varsayılan
    kapalı — hukuki onay sonrası key girerek aktif edilir.
    """
    # Image okuma
    if image.content_type and not (
        image.content_type.startswith(ALLOWED_MIME_PREFIX)
        or image.content_type == "application/octet-stream"
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Sadece görsel dosyaları kabul edilir (MIME: {image.content_type}).",
        )
    content = await image.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Dosya çok büyük: {len(content) / 1_048_576:.1f} MB (maksimum 10 MB).",
        )
    if len(content) < 32:
        raise HTTPException(status_code=400, detail="Dosya boş veya çok küçük.")

    # API key'leri topla → orchestrator'ı initialize et
    keys = _collect_face_keys(user.id, db)
    orch = AdapterOrchestrator(api_keys=keys)

    # Adaptör seçimi
    adapter_list: list[str] | None = None
    if adapters:
        adapter_list = [a.strip() for a in adapters.split(",") if a.strip()]

    # EXIF her zaman çıkarılır
    exif_data = extract_exif(content)

    # Paralel arama
    report = await orch.search_all(
        image_bytes=content,
        adapters=adapter_list,
        timeout_seconds=timeout_seconds,
    )

    log.info(
        "face_search user=%s adapters=%s success=%s failed=%s matches=%d elapsed=%dms",
        user.id, report.requested_adapters, report.successful,
        list(report.failed.keys()), report.total_matches, report.total_elapsed_ms,
    )

    return {
        "exif": exif_data,
        "requested_adapters": report.requested_adapters,
        "successful": report.successful,
        "failed": report.failed,
        "total_matches": report.total_matches,
        "total_elapsed_ms": report.total_elapsed_ms,
        "aggregated": [
            {
                "url": r.url,
                "domain": r.domain,
                "title": r.title,
                "sources": r.sources,
                "scores": r.scores,
                "consensus_score": r.consensus_score,
                "confidence": r.confidence.value,
                "thumbnails": r.thumbnails[:3],
            }
            for r in report.aggregated[:50]
        ],
        "per_adapter": [
            {
                "source": resp.source,
                "success": resp.success,
                "error": resp.error,
                "matches_count": len(resp.matches),
                "elapsed_ms": resp.elapsed_ms,
                "matches": [
                    {
                        "url": m.url,
                        "score": m.score,
                        "confidence": m.confidence.value,
                        "title": m.title,
                        "domain": m.domain,
                        "thumbnail_url": m.thumbnail_url,
                    }
                    for m in resp.matches[:20]
                ],
            }
            for resp in report.raw_responses
        ],
    }
