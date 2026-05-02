"""Görsel ters arama API.

İki mod:
1. Kullanıcı görsel URL'si verir → reverse search linkleri döner.
2. Kullanıcı dosya yükler → catbox.moe'ye public host edilir, sonra reverse
   search linkleri döner.

Hiçbir görsel sunucumuzda kalıcı saklanmaz. catbox upload başarısız olursa
URL fallback'i kullanıcıya bildirilir."""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, HttpUrl

from ..auth import get_current_user
from ..models import User


log = logging.getLogger("image_search")
router = APIRouter(prefix="/api/image", tags=["image"])

CATBOX_URL = "https://catbox.moe/user/api.php"
MAX_BYTES = 8 * 1024 * 1024  # 8 MB
ALLOWED_MIME = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp"}


class ImageSearchOut(BaseModel):
    image_url: str
    reverse_links: dict[str, str]
    note: Optional[str] = None


class ImageUrlIn(BaseModel):
    url: HttpUrl


def _build_reverse_links(image_url: str) -> dict[str, str]:
    enc = quote_plus(image_url)
    return {
        "google_lens": f"https://lens.google.com/uploadbyurl?url={enc}",
        "yandex_images": f"https://yandex.com/images/search?rpt=imageview&url={enc}",
        "tineye": f"https://www.tineye.com/search?url={enc}",
        "bing_visual": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIDP&sbisrc=UrlPaste&q=imgurl%3A{enc}",
        "google_images": f"https://www.google.com/searchbyimage?image_url={enc}",
        "baidu_images": f"https://image.baidu.com/n/pc_search?queryImageUrl={enc}",
    }


@router.post("/reverse", response_model=ImageSearchOut)
def reverse_by_url(data: ImageUrlIn, _: User = Depends(get_current_user)):
    return ImageSearchOut(image_url=str(data.url), reverse_links=_build_reverse_links(str(data.url)))


@router.post("/upload", response_model=ImageSearchOut)
async def reverse_by_upload(
    file: UploadFile = File(...),
    _: User = Depends(get_current_user),
):
    if file.content_type not in ALLOWED_MIME:
        raise HTTPException(status_code=400, detail=f"Unsupported MIME: {file.content_type}")

    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large (>8 MB)")
    if len(content) < 100:
        raise HTTPException(status_code=400, detail="File too small / empty")

    try:
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(
                CATBOX_URL,
                data={"reqtype": "fileupload"},
                files={"fileToUpload": (file.filename or "image", content, file.content_type)},
            )
            text = r.text.strip()
            if r.status_code != 200 or not text.startswith("http"):
                raise HTTPException(status_code=502, detail=f"catbox.moe rejected upload: {text[:200]}")
            image_url = text
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("catbox upload failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"Upload failed: {exc}")

    return ImageSearchOut(
        image_url=image_url,
        reverse_links=_build_reverse_links(image_url),
        note="Görsel catbox.moe'da public host edildi (Anthropic değil). Linki yalnızca sen görürsün ama kalıcıdır.",
    )
