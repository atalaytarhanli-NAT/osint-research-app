"""Adaptör orkestratörü — paralel arama ve sonuç birleştirme."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field

from .adapters.base import (
    FaceSearchAdapter, AdapterResponse, ExternalMatch,
    MatchConfidence, AdapterTier, AdapterCategory,
)
from .adapters.facecheck import FaceCheckAdapter
from .adapters.pimeyes import PimEyesAdapter
from .adapters.lenso import LensoAdapter
from .adapters.faceseek import FaceSeekAdapter
from .adapters.tineye import TinEyeAdapter
from .adapters.bing_visual import BingVisualSearchAdapter
from .adapters.google_vision import GoogleVisionAdapter
from .adapters.saucenao import SauceNAOAdapter
from .adapters.yandex import YandexImagesAdapter
from .adapters.search4faces import Search4FacesAdapter



@dataclass
class AggregatedResult:
    """Birden fazla adaptörün aynı URL üzerindeki bulgularını birleştirir."""
    url: str
    domain: str | None
    title: str | None
    sources: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    consensus_score: float = 0.0
    confidence: MatchConfidence = MatchConfidence.NONE
    thumbnails: list[str] = field(default_factory=list)


@dataclass
class OrchestratorReport:
    """Tüm adaptörlerin toplu sonucu."""
    requested_adapters: list[str]
    successful: list[str]
    failed: dict[str, str]   # adapter_name → error
    total_matches: int
    aggregated: list[AggregatedResult]
    raw_responses: list[AdapterResponse]
    total_elapsed_ms: int


class AdapterOrchestrator:
    """Tüm dış servisleri paralel çalıştırıp normalize eder.

    api_keys dict olarak verilir — ana uygulama Settings/DB'den anahtarları
    çekip orchestrator'ı initialize eder. Boş anahtarlı adaptörler otomatik
    olarak `enabled=False` durumuna düşer.
    """

    def __init__(self, api_keys: dict[str, str | None] | None = None) -> None:
        keys = api_keys or {}
        self._adapters: dict[str, FaceSearchAdapter] = {
            "facecheck":     FaceCheckAdapter(keys.get("facecheck")),
            "pimeyes":       PimEyesAdapter(keys.get("pimeyes")),
            "lenso":         LensoAdapter(keys.get("lenso")),
            "faceseek":      FaceSeekAdapter(keys.get("faceseek")),
            "tineye":        TinEyeAdapter(keys.get("tineye")),
            "bing_visual":   BingVisualSearchAdapter(keys.get("bing_visual")),
            "google_vision": GoogleVisionAdapter(keys.get("google_vision")),
            "saucenao":      SauceNAOAdapter(keys.get("saucenao")),
            "yandex":        YandexImagesAdapter(),
            "search4faces":  Search4FacesAdapter(),
        }

    @property
    def available(self) -> list[dict]:
        """Yapılandırılmış (etkin) adaptörlerin listesi."""
        return [
            {
                "name": a.name,
                "tier": a.tier.value,
                "category": a.category.value,
                "data_residency": a.data_residency,
                "enabled": a.enabled,
            }
            for a in self._adapters.values()
        ]

    async def search_all(
        self,
        image_bytes: bytes,
        adapters: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> OrchestratorReport:
        """Belirtilen adaptörleri (None ise tüm etkin olanları) paralel çalıştır."""
        if adapters:
            selected = {n: a for n, a in self._adapters.items() if n in adapters}
        else:
            selected = {n: a for n, a in self._adapters.items() if a.enabled}

        import time
        started = time.time()

        async def _run(adapter: FaceSearchAdapter) -> AdapterResponse:
            try:
                return await asyncio.wait_for(
                    adapter.search(image_bytes), timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                return AdapterResponse(
                    source=adapter.name, success=False,
                    error=f"Zaman aşımı ({timeout_seconds}s)",
                )
            except Exception as e:
                return AdapterResponse(
                    source=adapter.name, success=False,
                    error=f"Beklenmeyen hata: {e}",
                )

        responses = await asyncio.gather(*(_run(a) for a in selected.values()))
        return self._build_report(
            list(selected.keys()),
            responses,
            int((time.time() - started) * 1000),
        )

    # ---------- Birleştirme mantığı ----------

    def _build_report(
        self,
        requested: list[str],
        responses: list[AdapterResponse],
        elapsed: int,
    ) -> OrchestratorReport:
        successful: list[str] = []
        failed: dict[str, str] = {}
        all_matches: list[ExternalMatch] = []
        for r in responses:
            if r.success:
                successful.append(r.source)
                all_matches.extend(r.matches)
            else:
                failed[r.source] = r.error or "bilinmeyen hata"

        return OrchestratorReport(
            requested_adapters=requested,
            successful=successful,
            failed=failed,
            total_matches=len(all_matches),
            aggregated=self._aggregate(all_matches),
            raw_responses=responses,
            total_elapsed_ms=elapsed,
        )

    @staticmethod
    def _aggregate(matches: list[ExternalMatch]) -> list[AggregatedResult]:
        """Aynı URL üzerinden gelen farklı kaynak bulgularını birleştirir.

        Birden fazla servis aynı URL'yi döndürürse güven artar.
        Consensus skoru = ortalama × kaynak sayısı bonusu.
        """
        bucket: dict[str, list[ExternalMatch]] = defaultdict(list)
        for m in matches:
            key = m.url.rstrip("/").lower() if m.url else f"_{m.source}_{id(m)}"
            bucket[key].append(m)

        results: list[AggregatedResult] = []
        for url, group in bucket.items():
            sources = [g.source for g in group]
            scores = {g.source: g.score for g in group}
            avg = sum(scores.values()) / len(scores)
            # Çoklu kaynak bonusu (her ek kaynak %5 artırır, max %20)
            multi_bonus = min((len(set(sources)) - 1) * 5, 20)
            consensus = min(100.0, avg + multi_bonus)
            thumbnails = [
                t for t in (g.thumbnail_url for g in group) if t
            ]
            title = next((g.title for g in group if g.title), None)
            domain = next((g.domain for g in group if g.domain), None)

            results.append(
                AggregatedResult(
                    url=group[0].url,
                    domain=domain,
                    title=title,
                    sources=sorted(set(sources)),
                    scores=scores,
                    consensus_score=consensus,
                    confidence=MatchConfidence.from_score(consensus),
                    thumbnails=thumbnails,
                )
            )

        # En yüksek skordan başla
        results.sort(key=lambda r: r.consensus_score, reverse=True)
        return results
