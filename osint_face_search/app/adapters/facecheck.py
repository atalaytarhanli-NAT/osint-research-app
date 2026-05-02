"""FaceCheck.ID adaptörü.

API: https://facecheck.id
Auth: API token (Authorization header)
Akış: upload_pic → search (polling)
Veri lokasyonu: ABD — KVKK için yurt dışı aktarım sayılır.
Skor ölçeği: 0-100 (FaceCheck.ID kendi standardı, doğrudan kullanılır).
"""
from __future__ import annotations

import asyncio
import time
import httpx

from app.adapters.base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)


class FaceCheckAdapter(FaceSearchAdapter):
    name = "facecheck"
    tier = AdapterTier.TIER_1_DOCUMENTED_API
    category = AdapterCategory.FACE_SEARCH
    requires_api_key = True
    data_residency = "US"

    BASE_URL = "https://facecheck.id"
    POLL_INTERVAL_SEC = 2
    MAX_POLL_ATTEMPTS = 60   # ~2 dakika

    async def search(
        self,
        image_bytes: bytes,
        testing_mode: bool = False,
        **kwargs,
    ) -> AdapterResponse:
        if not self.enabled:
            return AdapterResponse(
                source=self.name, success=False,
                error="FaceCheck API token tanımlı değil",
            )

        started = time.time()
        headers = {"accept": "application/json", "Authorization": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # 1. Görseli yükle
                upload_resp = await client.post(
                    f"{self.BASE_URL}/api/upload_pic",
                    headers=headers,
                    files={"images": ("query.jpg", image_bytes, "image/jpeg")},
                )
                upload_resp.raise_for_status()
                upload_data = upload_resp.json()

                if upload_data.get("error"):
                    return self._error(upload_data["error"], started)

                id_search = upload_data.get("id_search")
                if not id_search:
                    return self._error("id_search alınamadı", started)

                # 2. Polling ile arama sonucu bekle
                for _ in range(self.MAX_POLL_ATTEMPTS):
                    poll_resp = await client.post(
                        f"{self.BASE_URL}/api/search",
                        headers={**headers, "Content-Type": "application/json"},
                        json={
                            "id_search": id_search,
                            "with_progress": True,
                            "status_only": False,
                            "demo": testing_mode,
                        },
                    )
                    poll_resp.raise_for_status()
                    poll_data = poll_resp.json()

                    if poll_data.get("error"):
                        return self._error(poll_data["error"], started)

                    if poll_data.get("output"):
                        items = poll_data["output"].get("items", [])
                        return self._normalize(items, started)

                    await asyncio.sleep(self.POLL_INTERVAL_SEC)

                return self._error("Polling zaman aşımı", started)

        except httpx.HTTPError as e:
            return self._error(f"HTTP hatası: {e}", started)
        except Exception as e:
            return self._error(f"Beklenmeyen hata: {e}", started)

    def _normalize(self, items: list[dict], started: float) -> AdapterResponse:
        matches: list[ExternalMatch] = []
        for item in items:
            score = float(item.get("score", 0))
            url = item.get("url", "")
            domain = self._extract_domain(url)
            matches.append(
                ExternalMatch(
                    source=self.name,
                    url=url,
                    score=score,
                    confidence=MatchConfidence.from_score(score),
                    thumbnail_b64=item.get("base64"),
                    domain=domain,
                    raw=item,
                )
            )
        return AdapterResponse(
            source=self.name,
            success=True,
            matches=matches,
            elapsed_ms=int((time.time() - started) * 1000),
        )

    def _error(self, msg: str, started: float) -> AdapterResponse:
        return AdapterResponse(
            source=self.name,
            success=False,
            error=msg,
            elapsed_ms=int((time.time() - started) * 1000),
        )

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        if not url:
            return None
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except Exception:
            return None
