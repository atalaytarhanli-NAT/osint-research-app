"""Yüz arama endpoint'i — sistemin çekirdeği.

Bir görsel yüklenir, içindeki tüm yüzler tespit edilir,
her biri Qdrant'taki watchlist ile eşleştirilir,
sonuçlar audit log'a yazılır ve istemciye döner.
"""
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, UploadFile, File, Form, Request, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_actor
from app.audit import AuditService
from app.face_engine import FaceEngine
from app.vector_store import VectorStore
from app.models import Case, Identity, CaseStatus, AuditAction, IdentityType
from app.schemas import SearchResponse, FaceMatch
from app.exceptions import CaseNotFound, CaseClosed, InvalidImage
from app.config import get_settings

router = APIRouter(prefix="/search", tags=["search"])


@router.post("", response_model=SearchResponse)
async def search_face(
    request: Request,
    image: UploadFile = File(..., description="Aranacak görsel (JPEG/PNG)"),
    case_id: UUID = Form(..., description="Bu sorgunun bağlanacağı vaka ID'si"),
    top_k: int = Form(5, ge=1, le=20),
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    """Görseldeki yüzleri watchlist ile eşleştir.

    KVKK gereği her sorgu bir vakaya bağlanmak zorundadır.
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

    # Yüz tespiti + embedding
    try:
        faces = FaceEngine.get_instance().detect_and_embed(image_bytes)
    except Exception as e:
        raise InvalidImage(f"Görsel işlenemedi: {e}")

    # Eşleştirme
    vstore = VectorStore()
    all_matches: list[FaceMatch] = []

    for face in faces:
        hits = vstore.search(
            embedding=face.embedding,
            limit=top_k,
            score_threshold=settings.face_match_threshold,
        )
        for hit in hits:
            # Qdrant payload'undan zenginleştirilmiş bilgiyi al
            # Identity tablosundan tam veriyi çek (audit için)
            identity = db.query(Identity).filter(
                Identity.qdrant_point_id == hit.point_id
            ).first()
            if not identity:
                continue
            all_matches.append(
                FaceMatch(
                    identity_id=identity.id,
                    display_name=identity.display_name,
                    identity_type=identity.identity_type,
                    external_ref=identity.external_ref,
                    similarity=hit.score,
                    notes=identity.notes,
                )
            )

    query_id = uuid4()
    AuditService(db).log(
        actor=actor,
        action=AuditAction.SEARCH_PERFORMED,
        resource_type="search",
        resource_id=str(query_id),
        case_id=case_id,
        request=request,
        details={
            "detected_faces": len(faces),
            "matches_found": len(all_matches),
            "threshold": settings.face_match_threshold,
            "top_match_similarity": (
                max(m.similarity for m in all_matches) if all_matches else None
            ),
        },
    )

    return SearchResponse(
        case_id=case_id,
        detected_faces=len(faces),
        matches=all_matches,
        threshold_used=settings.face_match_threshold,
        query_id=query_id,
    )
