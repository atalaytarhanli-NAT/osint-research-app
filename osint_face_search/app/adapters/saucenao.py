"""SauceNAO adaptörü.

API: https://saucenao.com/search.php
Auth: API key (URL parametresi)
Veri lokasyonu: ABD
Özellik: Sanat eserleri, çizimler, manga, anime kapakları için en iyi reverse image.
OSINT için: Profil resmi olarak kullanılan sanat eserlerinin kaynağını bulur.
Free tier: 100 sorgu/gün, 4/30sn.
"""
from __future__ import annotations

import time
import httpx

from app.adapters.base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class SauceNAOAdapter(FaceSearchAdapter):
    name = "saucenao"
    tier = AdapterTier.TIER_1_DOCUMENTED_API
    category = AdapterCategory.REVERSE_IMAGE
    requires_api_key = False  # API key opsiyonel; key olmadan günlük 100 sorgu
    data_residency = "US"

    BASE_URL = "https://saucenao.com/search.php"

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(api_key)
        self._enabled = True   # API key olmasa da çalışır

    async def search(
        self,
        image_bytes: bytes,
        num_results: int = 10,
        **kwargs,
    ) -> AdapterResponse:
        started = time.time()

        params = {
            "output_type": 2,    # JSON
            "numres": num_results,
            "db": 999,           # tüm dbleri ara
        }
        if self.api_key:
            params["api_key"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    self.BASE_URL,
                    params=params,
                    files={"file": ("query.jpg", image_bytes, "image/jpeg")},
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("header", {}).get("status", -1) != 0:
                    return AdapterResponse(
                        source=self.name, success=False,
                        error=data.get("header", {}).get("message", "bilinmeyen hata"),
                        elapsed_ms=int((time.time() - started) * 1000),
                    )

                matches: list[ExternalMatch] = []
                for r in data.get("results", []):
                    header = r.get("header", {})
                    body = r.get("data", {})
                    similarity = float(header.get("similarity", 0))
                    urls = body.get("ext_urls", [])
                    primary_url = urls[0] if urls else ""

                    title_parts = [
                        body.get("title"),
                        body.get("source"),
                        body.get("eng_name"),
                    ]
                    title = " — ".join(p for p in title_parts if p)

                    matches.append(
                        ExternalMatch(
                            source=self.name,
                            url=primary_url,
                            score=similarity,
                            confidence=MatchConfidence.from_score(similarity),
                            thumbnail_url=header.get("thumbnail"),
                            title=title or None,
                            domain=self._extract_domain(primary_url),
                            raw=r,
                        )
                    )

                return AdapterResponse(
                    source=self.name, success=True,
                    matches=matches,
                    elapsed_ms=int((time.time() - started) * 1000),
                    cost_credits=float(
                        data.get("header", {}).get("short_remaining", 0)
                    ),
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
