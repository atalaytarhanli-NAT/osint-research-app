"""TinEye reverse image search adaptörü.

API: https://api.tineye.com/rest/
Auth: x-api-key header
Veri lokasyonu: Kanada
Not: TinEye yüze özel değil — TÜM görsel arar (manipüle edilmiş halleri dahil).
OSINT'te görselin kaynağını bulmak için çok güçlüdür.
Skor: backlinks count + image_size match — 0-100 ölçeğine yaklaştırılır.
"""
from __future__ import annotations

import time
import httpx

from .base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class TinEyeAdapter(FaceSearchAdapter):
    name = "tineye"
    tier = AdapterTier.TIER_1_DOCUMENTED_API
    category = AdapterCategory.REVERSE_IMAGE
    requires_api_key = True
    data_residency = "CA"

    BASE_URL = "https://api.tineye.com/rest"

    async def search(
        self,
        image_bytes: bytes,
        limit: int = 20,
        **kwargs,
    ) -> AdapterResponse:
        if not self.enabled:
            return AdapterResponse(
                source=self.name, success=False,
                error="TinEye API key tanımlı değil",
            )

        started = time.time()
        headers = {"x-api-key": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/search/",
                    headers=headers,
                    files={"image_upload": ("query.jpg", image_bytes, "image/jpeg")},
                    data={"limit": limit, "sort": "score", "order": "desc"},
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("code") != 200:
                    return AdapterResponse(
                        source=self.name, success=False,
                        error=f"TinEye kodu: {data.get('code')} — {data.get('messages')}",
                        elapsed_ms=int((time.time() - started) * 1000),
                    )

                results = data.get("results", {})
                tineye_matches = results.get("matches", [])

                matches: list[ExternalMatch] = []
                for m in tineye_matches:
                    # TinEye 'score' 0-100 arasında döner (image similarity)
                    score = float(m.get("score", 0))
                    backlinks = m.get("backlinks", [])
                    # En çok backlink'i olan ilk URL'yi temsilci olarak al
                    primary_url = ""
                    page_title = None
                    if backlinks:
                        primary_url = backlinks[0].get("url", "")
                        page_title = backlinks[0].get("backlink", "")

                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=primary_url,
                            score=score,
                            confidence=MatchConfidence.from_score(score),
                            thumbnail_url=m.get("image_url"),
                            title=page_title,
                            domain=m.get("domain"),
                            raw=m,
                        )
                    )

                return AdapterResponse(
                    source=self.name, success=True,
                    matches=matches,
                    elapsed_ms=int((time.time() - started) * 1000),
                )

        except Exception as e:
            return AdapterResponse(
                source=self.name, success=False,
                error=str(e),
                elapsed_ms=int((time.time() - started) * 1000),
            )
