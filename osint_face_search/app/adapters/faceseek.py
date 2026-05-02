"""FaceSeek adaptörü.

API: https://faceseek.online (Gradio tabanlı)
Auth: api_token parametre olarak gönderilir
Özellik: FaceCheck/Lenso/PimEyes'i agregat eden meta-servis (kendi indeksleri var)
Veri lokasyonu: US/EU karma
"""
from __future__ import annotations

import time
import httpx

from app.adapters.base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class FaceSeekAdapter(FaceSearchAdapter):
    name = "faceseek"
    tier = AdapterTier.TIER_1_DOCUMENTED_API
    category = AdapterCategory.FACE_SEARCH
    requires_api_key = True
    data_residency = "US"

    BASE_URL = "https://faceseek.online"

    async def search(
        self,
        image_bytes: bytes,
        is_premium: bool = False,
        **kwargs,
    ) -> AdapterResponse:
        if not self.enabled:
            return AdapterResponse(
                source=self.name, success=False,
                error="FaceSeek API key tanımlı değil",
            )

        started = time.time()

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                # Gradio API: 2 adımlı — POST /call/search_face → GET /call/search_face/{event_id}
                init = await client.post(
                    f"{self.BASE_URL}/gradio_api/call/search_face",
                    json={"data": [None, self.api_key, is_premium]},
                    files={"data[0]": ("query.jpg", image_bytes, "image/jpeg")},
                )
                init.raise_for_status()
                init_data = init.json()
                event_id = init_data.get("event_id")
                if not event_id:
                    return AdapterResponse(
                        source=self.name, success=False,
                        error="event_id alınamadı",
                        elapsed_ms=int((time.time() - started) * 1000),
                    )

                # Sonuçları al (Gradio SSE stream — ama bekleyen polling de çalışır)
                result = await client.get(
                    f"{self.BASE_URL}/gradio_api/call/search_face/{event_id}",
                    timeout=120,
                )
                result.raise_for_status()
                data = result.json()

                # FaceSeek yanıt formatı zaman zaman değişebilir; defansif parse
                items = []
                if isinstance(data, dict):
                    items = data.get("data", [])
                elif isinstance(data, list):
                    items = data

                matches: list[ExternalMatch] = []
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    score = float(item.get("score", item.get("confidence", 0)))
                    if score <= 1:
                        score *= 100
                    url = item.get("url", "")
                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=url,
                            score=score,
                            confidence=MatchConfidence.from_score(score),
                            thumbnail_url=item.get("thumbnail"),
                            domain=self._extract_domain(url),
                            raw=item,
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

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        if not url:
            return None
        from urllib.parse import urlparse
        return urlparse(url).netloc
