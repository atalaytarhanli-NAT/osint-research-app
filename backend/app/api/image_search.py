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
from typing import Optional
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, HttpUrl

from ..auth import get_current_user
from ..models import User
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
