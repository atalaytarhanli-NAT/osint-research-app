"""Lenso.ai adaptörü.

API: https://lenso.ai (yeni nesil, AB merkezli)
Auth: API key (header: X-API-Key)
Veri lokasyonu: EU — KVKK için PimEyes ile aynı statüde
Özellik: Sadece yüz değil; logo, manzara, eşya araması da yapabilir.
Not: Resmi public API dökümantasyonu sınırlı — kurumsal anlaşma sonrası
spec'leri doğrulayın. Bu kod genel pattern olarak yazılmıştır.
"""
from __future__ import annotations

import time
import httpx

from app.adapters.base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class LensoAdapter(FaceSearchAdapter):
    name = "lenso"
    tier = AdapterTier.TIER_2_COMMERCIAL
    category = AdapterCategory.HYBRID
    requires_api_key = True
    data_residency = "EU"

    BASE_URL = "https://api.lenso.ai"

    async def search(
        self,
        image_bytes: bytes,
        search_type: str = "people",   # people | places | logos | duplicates
        **kwargs,
    ) -> AdapterResponse:
        if not self.enabled:
            return AdapterResponse(
                source=self.name, success=False,
                error="Lenso API key tanımlı değil",
            )

        started = time.time()
        headers = {"X-API-Key": self.api_key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/v1/search",
                    headers=headers,
                    files={"image": ("query.jpg", image_bytes, "image/jpeg")},
                    data={"type": search_type},
                )
                resp.raise_for_status()
                data = resp.json()

                results = data.get("results", [])
                matches: list[ExternalMatch] = []
                for r in results:
                    score = float(r.get("similarity", r.get("score", 0)))
                    if score <= 1:
                        score *= 100
                    url = r.get("url", "")
                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=url,
                            score=score,
                            confidence=MatchConfidence.from_score(score),
                            thumbnail_url=r.get("thumbnail"),
                            title=r.get("title"),
                            domain=self._extract_domain(url),
                            raw=r,
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
