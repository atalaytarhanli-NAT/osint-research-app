"""Yüz/görüntü dış servis arama modülü.

Faz 1: 10 dış adaptör (FaceCheck, PimEyes, Lenso, FaceSeek, TinEye,
Bing Visual, Google Vision, SauceNAO, Yandex, Search4Faces) HTTP üzerinden
paralel sorgulama + sonuç birleştirme (consensus scoring).

Faz 2 (planlanan): InsightFace yerel embedding + Qdrant watchlist + KVKK
audit + vaka yönetimi (osint_face_search/ standalone projesinden port).
"""
from .adapters.base import (
    AdapterCategory,
    AdapterResponse,
    AdapterTier,
    ExternalMatch,
    FaceSearchAdapter,
    MatchConfidence,
)
from .orchestrator import (
    AdapterOrchestrator,
    AggregatedResult,
    OrchestratorReport,
)

__all__ = [
    "AdapterOrchestrator",
    "AdapterCategory",
    "AdapterResponse",
    "AdapterTier",
    "AggregatedResult",
    "ExternalMatch",
    "FaceSearchAdapter",
    "MatchConfidence",
    "OrchestratorReport",
]
