"""PimEyes adaptörü.

API: https://pimeyes.com (PRO/PROtect API erişimi gerekir — özel anlaşma)
Auth: Bearer token
Veri lokasyonu: AB (Polonya merkezli)
Not: PimEyes'in tam API dökümantasyonu kapalıdır. Bu adaptör genel bir
şablondur — anlaşma yaptıktan sonra resmi dökümanlardan endpoint
yapısını teyit edip ince ayar yapın.
"""
from __future__ import annotations

import time
import base64
import httpx

from .base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class PimEyesAdapter(FaceSearchAdapter):
    name = "pimeyes"
    tier = AdapterTier.TIER_2_COMMERCIAL
    category = AdapterCategory.FACE_SEARCH
    requires_api_key = True
    data_residency = "EU"

    BASE_URL = "https://api.pimeyes.com"   # placeholder, gerçek endpoint anlaşmaya göre değişir

    async def search(
        self,
        image_bytes: bytes,
        **kwargs,
    ) -> AdapterResponse:
        if not self.enabled:
            return AdapterResponse(
                source=self.name, success=False,
                error="PimEyes API token tanımlı değil",
            )

        started = time.time()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                # PimEyes tipik olarak base64 görsel kabul eder
                image_b64 = base64.b64encode(image_bytes).decode("ascii")

                resp = await client.post(
                    f"{self.BASE_URL}/v2/search",
                    headers=headers,
                    json={
                        "image": image_b64,
                        "search_type": "PUBLIC",   # PUBLIC | PROTECT
                    },
                )
                resp.raise_for_status()
                data = resp.json()

                results = data.get("results", [])
                matches: list[ExternalMatch] = []
                for r in results:
                    # PimEyes 0-1 ölçeğinde similarity döner — 0-100'e çevir
                    similarity = float(r.get("similarity", 0))
                    score = similarity * 100 if similarity <= 1 else similarity
                    url = r.get("source_url", "")
                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=url,
                            score=score,
                            confidence=MatchConfidence.from_score(score),
                            thumbnail_url=r.get("thumbnail_url"),
                            title=r.get("page_title"),
                            domain=self._extract_domain(url),
                            raw=r,
                        )
                    )

                return AdapterResponse(
                    source=self.name,
                    success=True,
                    matches=matches,
                    elapsed_ms=int((time.time() - started) * 1000),
                    cost_credits=data.get("credits_used"),
                )

        except httpx.HTTPStatusError as e:
            return AdapterResponse(
                source=self.name, success=False,
                error=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
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
