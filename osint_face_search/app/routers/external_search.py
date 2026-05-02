"""Dış servis (FaceCheck, PimEyes vb.) arama endpoint'leri.

KVKK kritik nokta: BU endpoint'ler veriyi YURT DIŞINA çıkarır.
Her sorgu external_search_results tablosuna yazılır.
Vakanın legal_basis'i bu aktarımı KVKK md. 9 kapsamında karşılamak zorunda.
"""
from uuid import UUID
from fastapi import APIRouter, Depends, UploadFile, File, Form, Request, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_actor
from app.audit import AuditService
from app.adapters import AdapterOrchestrator
from app.models import Case, CaseStatus, ExternalSearchResult, AuditAction
from app.exceptions import CaseNotFound, CaseClosed, InvalidImage
from app.config import get_settings

router = APIRouter(prefix="/external-search", tags=["external-search"])

# Singleton orchestrator
_orchestrator: AdapterOrchestrator | None = None


def get_orchestrator() -> AdapterOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AdapterOrchestrator()
    return _orchestrator


@router.get("/adapters")
def list_adapters(actor: str = Depends(get_current_actor)):
    """Yapılandırılmış tüm adaptörleri ve durumlarını listele."""
    return get_orchestrator().available


@router.post("")
async def search_external(
    request: Request,
    image: UploadFile = File(...),
    case_id: UUID = Form(...),
    adapters: str | None = Form(
        None,
        description="Virgülle ayrılmış adaptör listesi. Boş ise tüm etkinler kullanılır."
    ),
    timeout_seconds: int = Form(120, ge=10, le=600),
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    """Görseli seçilen dış servislerde paralel olarak arar.

    UYARI: Bu sorgu görseli ABD/AB/RU sunucularına gönderir.
    Vaka legal_basis'i KVKK md. 9 yurt dışı aktarım koşullarını
    karşılamak zorundadır.
    """
    settings = get_settings()

    # Vaka kontrolü
    case = db.get(Case, case_id)
    if not case:
        raise CaseNotFound(str(case_id))
    if case.status in (CaseStatus.CLOSED, CaseStatus.ARCHIVED):
        raise CaseClosed(str(case_id))

    # Görsel
    image_bytes = await image.read()
    if len(image_bytes) > settings.max_image_size_mb * 1024 * 1024:
        raise InvalidImage(f"Görsel {settings.max_image_size_mb} MB sınırını aşıyor")

    # Adaptör seçimi
    adapter_list: list[str] | None = None
    if adapters:
        adapter_list = [a.strip() for a in adapters.split(",") if a.strip()]
    elif settings.orchestrator_default_adapters:
        adapter_list = [
            a.strip() for a in settings.orchestrator_default_adapters.split(",")
            if a.strip()
        ]

    # Paralel arama
    orch = get_orchestrator()
    report = await orch.search_all(
        image_bytes=image_bytes,
        adapters=adapter_list,
        timeout_seconds=timeout_seconds,
    )

    # Her adaptör için ExternalSearchResult kaydı (KVKK)
    for resp in report.raw_responses:
        adapter = orch._adapters.get(resp.source)
        residency = adapter.data_residency if adapter else "UNKNOWN"
        # Yanıt payload'unu özetle (büyük base64 thumbnail'leri kaydetme)
        payload_summary = {
            "matches": [
                {
                    "url": m.url,
                    "score": m.score,
                    "confidence": m.confidence.value,
                    "domain": m.domain,
                }
                for m in resp.matches
            ]
        }
        record = ExternalSearchResult(
            case_id=case_id,
            adapter_name=resp.source,
            data_residency=residency,
            success=resp.success,
            error=resp.error,
            matches_count=len(resp.matches),
            elapsed_ms=resp.elapsed_ms,
            cost_credits=resp.cost_credits,
            response_payload=payload_summary,
            queried_by=actor,
        )
        db.add(record)
    db.commit()

    # Audit log özet kaydı
    AuditService(db).log(
        actor=actor,
        action=AuditAction.EXTERNAL_SEARCH_PERFORMED,
        resource_type="external_search",
        resource_id=str(case_id),
        case_id=case_id,
        request=request,
        details={
            "adapters_used": report.successful,
            "adapters_failed": list(report.failed.keys()),
            "total_matches": report.total_matches,
            "elapsed_ms": report.total_elapsed_ms,
        },
    )

    # JSON yanıtı
    return {
        "case_id": str(case_id),
        "requested_adapters": report.requested_adapters,
        "successful": report.successful,
        "failed": report.failed,
        "total_matches": report.total_matches,
        "total_elapsed_ms": report.total_elapsed_ms,
        "aggregated": [
            {
                "url": r.url,
                "domain": r.domain,
                "title": r.title,
                "sources": r.sources,
                "scores": r.scores,
                "consensus_score": r.consensus_score,
                "confidence": r.confidence.value,
                "thumbnails": r.thumbnails[:3],
            }
            for r in report.aggregated
        ],
        "per_adapter": [
            {
                "source": r.source,
                "success": r.success,
                "error": r.error,
                "matches": [
                    {
                        "url": m.url,
                        "score": m.score,
                        "confidence": m.confidence.value,
                        "title": m.title,
                        "domain": m.domain,
                        "thumbnail_url": m.thumbnail_url,
                    }
                    for m in r.matches
                ],
                "elapsed_ms": r.elapsed_ms,
            }
            for r in report.raw_responses
        ],
    }


@router.get("/history/{case_id}")
def case_external_history(
    case_id: UUID,
    limit: int = Query(50, le=500),
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    """Bir vakanın dış servis sorgu geçmişi (KVKK denetim çıktısı için)."""
    rows = (
        db.query(ExternalSearchResult)
        .filter(ExternalSearchResult.case_id == case_id)
        .order_by(ExternalSearchResult.queried_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": str(r.id),
            "adapter_name": r.adapter_name,
            "data_residency": r.data_residency,
            "success": r.success,
            "error": r.error,
            "matches_count": r.matches_count,
            "elapsed_ms": r.elapsed_ms,
            "cost_credits": r.cost_credits,
            "queried_by": r.queried_by,
            "queried_at": r.queried_at.isoformat(),
        }
        for r in rows
    ]
