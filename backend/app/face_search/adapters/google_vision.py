"""Google Cloud Vision API adaptörü.

API: https://vision.googleapis.com/v1/images:annotate
Auth: API key (URL parametresi)
Veri lokasyonu: ABD (Google Cloud)
Özellik: Web Detection — görselin web'deki kullanımları, benzer sayfalar.
Yüz tanımaya özel değil; FACE_DETECTION sadece tespit yapar, eşleştirme yapmaz.
OSINT için "Web Detection" en yararlısıdır.
"""
from __future__ import annotations

import base64
import time
import httpx

from .base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class GoogleVisionAdapter(FaceSearchAdapter):
    name = "google_vision"
    tier = AdapterTier.TIER_1_DOCUMENTED_API
    category = AdapterCategory.REVERSE_IMAGE
    requires_api_key = True
    data_residency = "US"

    BASE_URL = "https://vision.googleapis.com/v1/images:annotate"

    async def search(
        self,
        image_bytes: bytes,
        max_results: int = 20,
        **kwargs,
    ) -> AdapterResponse:
        if not self.enabled:
            return AdapterResponse(
                source=self.name, success=False,
                error="Google Vision API key tanımlı değil",
            )

        started = time.time()
        image_b64 = base64.b64encode(image_bytes).decode("ascii")

        payload = {
            "requests": [
                {
                    "image": {"content": image_b64},
                    "features": [
                        {"type": "WEB_DETECTION", "maxResults": max_results},
                        {"type": "FACE_DETECTION", "maxResults": 10},
                    ],
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    self.BASE_URL,
                    params={"key": self.api_key},
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()

                response = data["responses"][0]
                if "error" in response:
                    return AdapterResponse(
                        source=self.name, success=False,
                        error=response["error"].get("message", "bilinmeyen hata"),
                        elapsed_ms=int((time.time() - started) * 1000),
                    )

                web = response.get("webDetection", {})
                matches: list[ExternalMatch] = []

                # Tam eşleşen sayfalar — score 95
                for page in web.get("pagesWithMatchingImages", []):
                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=page.get("url", ""),
                            score=95,
                            confidence=MatchConfidence.CERTAIN,
                            title=page.get("pageTitle"),
                            domain=self._extract_domain(page.get("url", "")),
                            raw=page,
                        )
                    )

                # Kısmi eşleşmeler — score 70
                for img in web.get("partialMatchingImages", []):
                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=img.get("url", ""),
                            score=70,
                            confidence=MatchConfidence.UNCERTAIN,
                            domain=self._extract_domain(img.get("url", "")),
                            raw=img,
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
