"""Dış yüz/görüntü arama servisleri için ortak arayüz.

Tüm adaptörler aynı imzaya sahip olmalıdır ki orkestratör hepsini paralel
çalıştırıp sonuçları normalize edebilsin.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class AdapterTier(str, Enum):
    """Adaptör güvenilirlik seviyesi."""
    TIER_1_DOCUMENTED_API = "TIER_1_DOCUMENTED_API"   # FaceCheck, TinEye, Bing, FaceSeek, SauceNAO
    TIER_2_COMMERCIAL = "TIER_2_COMMERCIAL"            # PimEyes, Lenso (özel anlaşma gerekir)
    TIER_3_SCRAPER = "TIER_3_SCRAPER"                  # Yandex, Search4Faces (kırılgan)


class AdapterCategory(str, Enum):
    FACE_SEARCH = "FACE_SEARCH"          # Yüze özel
    REVERSE_IMAGE = "REVERSE_IMAGE"       # Tüm görüntü
    HYBRID = "HYBRID"                     # İkisi de


class MatchConfidence(str, Enum):
    """FaceCheck.ID standardı — diğer adaptörler de buna eşlenir."""
    CERTAIN = "CERTAIN"          # 90-100
    CONFIDENT = "CONFIDENT"       # 83-89
    UNCERTAIN = "UNCERTAIN"       # 70-82
    WEAK = "WEAK"                 # 50-69
    NONE = "NONE"                 # <50

    @classmethod
    def from_score(cls, score: float) -> "MatchConfidence":
        """0-100 ölçeğindeki skoru kategoriye eşler."""
        if score >= 90:
            return cls.CERTAIN
        if score >= 83:
            return cls.CONFIDENT
        if score >= 70:
            return cls.UNCERTAIN
        if score >= 50:
            return cls.WEAK
        return cls.NONE


@dataclass
class ExternalMatch:
    """Tek bir dış servis sonucu (normalize edilmiş)."""
    source: str                      # Adaptör adı (örn. "facecheck")
    url: str                          # Bulunan kaynak URL
    score: float                      # 0-100 normalize skor
    confidence: MatchConfidence
    thumbnail_url: str | None = None
    thumbnail_b64: str | None = None
    title: str | None = None
    domain: str | None = None
    raw: dict = field(default_factory=dict)   # Servisin döndürdüğü ham yanıt


@dataclass
class AdapterResponse:
    """Bir adaptörün tek bir aramaya dönüşü."""
    source: str
    success: bool
    matches: list[ExternalMatch] = field(default_factory=list)
    error: str | None = None
    elapsed_ms: int = 0
    cost_credits: float | None = None    # Servis kredisi tüketildiyse
    queried_at: datetime = field(default_factory=datetime.utcnow)


class FaceSearchAdapter(ABC):
    """Tüm adaptörlerin uyması gereken arayüz."""

    name: str = "base"
    tier: AdapterTier = AdapterTier.TIER_1_DOCUMENTED_API
    category: AdapterCategory = AdapterCategory.FACE_SEARCH
    requires_api_key: bool = True
    data_residency: str = "UNKNOWN"   # KVKK için: ülke kodu (US, EU, RU, ...)

    def __init__(self, api_key: str | None = None) -> None:
        if self.requires_api_key and not api_key:
            self._enabled = False
        else:
            self._enabled = True
        self.api_key = api_key

    @property
    def enabled(self) -> bool:
        """Bu adaptör config'de doğru ayarlanmış mı?"""
        return self._enabled

    @abstractmethod
    async def search(self, image_bytes: bytes, **kwargs) -> AdapterResponse:
        """Görseli ara, normalize edilmiş sonuçları döndür.

        Hata durumunda exception fırlatmaz; AdapterResponse(success=False)
        döner. Bu sayede orkestratör bir adaptörün başarısız olmasını
        diğerlerinin çalışmasına engel olarak görmez.
        """
        ...
