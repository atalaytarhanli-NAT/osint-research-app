"""Bing Visual Search adaptörü (Microsoft Azure).

API: https://api.bing.microsoft.com/v7.0/images/visualsearch
Auth: Ocp-Apim-Subscription-Key header
Veri lokasyonu: ABD/Avrupa (Azure region'a göre)
Özellik: Görselin web'deki kullanımları, benzer görseller, görüntülenen ürünler.
Yüz tanımaya özel değil ama OSINT için faydalı bağlam üretir.
"""
from __future__ import annotations

import json
import time
import httpx

from app.adapters.base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class BingVisualSearchAdapter(FaceSearchAdapter):
    name = "bing_visual"
    tier = AdapterTier.TIER_1_DOCUMENTED_API
    category = AdapterCategory.REVERSE_IMAGE
    requires_api_key = True
    data_residency = "US"

    BASE_URL = "https://api.bing.microsoft.com/v7.0/images/visualsearch"

    async def search(
        self,
        image_bytes: bytes,
        market: str = "tr-TR",
        **kwargs,
    ) -> AdapterResponse:
        if not self.enabled:
            return AdapterResponse(
                source=self.name, success=False,
                error="Bing API key tanımlı değil",
            )

        started = time.time()
        headers = {"Ocp-Apim-Subscription-Key": self.api_key}

        # Bing multipart/form-data ister: 'image' alanı + 'knowledgeRequest' JSON
        knowledge_request = {"invokedSkills": ["SimilarImages"]}
        files = {
            "image": ("query.jpg", image_bytes, "image/jpeg"),
            "knowledgeRequest": (
                None, json.dumps(knowledge_request), "application/json",
            ),
        }
        params = {"mkt": market}

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    self.BASE_URL,
                    headers=headers,
                    files=files,
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()

                matches: list[ExternalMatch] = []
                for tag in data.get("tags", []):
                    for action in tag.get("actions", []):
                        if action.get("actionType") != "VisualSearch":
                            continue
                        for value in action.get("data", {}).get("value", []):
                            url = value.get("hostPageUrl", "")
                            # Bing similarity skoru döndürmez — sıralama bilgisini kullan
                            # Yüksek sırada olanlara yüksek skor verelim (başka çare yok)
                            matches.append(
                                ExternalMatch(
                                    source=self.name,
                                    url=url,
                                    score=70,   # nominal — Bing skor vermez
                                    confidence=MatchConfidence.UNCERTAIN,
                                    thumbnail_url=value.get("thumbnailUrl"),
                                    title=value.get("name"),
                                    domain=value.get("hostPageDisplayUrl"),
                                    raw=value,
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
