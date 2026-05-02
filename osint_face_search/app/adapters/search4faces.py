"""Search4Faces adaptörü.

Site: https://search4faces.com
Resmi public API YOK. Site VKontakte ve Odnoklassniki gibi Rus sosyal
medyalarını indeksler. Sadece web arayüzü üzerinden çalışır.

Bu adaptör bir İSKELET'tir — gerçek scraper koduna ihtiyaç var.
KVKK ve Yandex ile aynı yurt dışı aktarım risklerini taşır (RU).

Production'a almadan önce:
1. Site otomasyona izin veriyor mu (TOS) kontrol edin
2. CAPTCHA bypass etiği/yasallığı değerlendirin
3. Hukuk ekibi onayı şart
"""
from __future__ import annotations

import time

from app.adapters.base import (
    FaceSearchAdapter, AdapterResponse,
    AdapterTier, AdapterCategory,
)


class Search4FacesAdapter(FaceSearchAdapter):
    name = "search4faces"
    tier = AdapterTier.TIER_3_SCRAPER
    category = AdapterCategory.FACE_SEARCH
    requires_api_key = False
    data_residency = "RU"

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(api_key)
        # Varsayılan olarak DEVRE DIŞI — açıkça etkinleştirilmeli
        self._enabled = False

    async def search(self, image_bytes: bytes, **kwargs) -> AdapterResponse:
        return AdapterResponse(
            source=self.name,
            success=False,
            error=(
                "Search4Faces adaptörü iskelet halinde. "
                "Production scraper kodu ve hukuki onay olmadan "
                "etkinleştirilmemelidir."
            ),
            elapsed_ms=0,
        )
