"""Watchlist (izleme listesi) yönetimi.

Yeni bir kişiyi sisteme kaydetmek için tek-yüzlü bir görsel yüklenir.
InsightFace embedding üretir, Qdrant'a yazılır, PostgreSQL'de meta veri tutulur.
"""
from uuid import UUID
from fastapi import APIRouter, Depends, UploadFile, File, Form, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_actor
from app.audit import AuditService
from app.face_engine import FaceEngine
from app.vector_store import VectorStore
from app.models import Identity, IdentityType, AuditAction
from app.schemas import IdentityRead
from app.exceptions import InvalidImage
from app.config import get_settings

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


@router.post("", response_model=IdentityRead, status_code=status.HTTP_201_CREATED)
async def add_identity(
    request: Request,
    image: UploadFile = File(...),
    display_name: str = Form(...),
    identity_type: IdentityType = Form(...),
    external_ref: str | None = Form(None),
    notes: str | None = Form(None),
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    """Watchlist'e yeni kayıt ekle.

    - image: tek yüzlü, net bir referans görseli
    - identity_type: PERSONNEL / WATCHLIST / INCIDENT / UNKNOWN
    """
    settings = get_settings()
    image_bytes = await image.read()

    if len(image_bytes) > settings.max_image_size_mb * 1024 * 1024:
        raise InvalidImage(f"Görsel {settings.max_image_size_mb} MB sınırını aşıyor")

    # Embedding çıkar
    try:
        face = FaceEngine.get_instance().embed_single_face(image_bytes)
    except ValueError as e:
        raise InvalidImage(str(e))

    # Qdrant'a yaz
    vstore = VectorStore()
    point_id = vstore.upsert_face(
        embedding=face.embedding,
        payload={
            "display_name": display_name,
            "identity_type": identity_type.value,
            "external_ref": external_ref,
            "is_active": True,
        },
    )

    # PostgreSQL meta
    identity = Identity(
        external_ref=external_ref,
        identity_type=identity_type,
        display_name=display_name,
        notes=notes,
        qdrant_point_id=point_id,
        created_by=actor,
    )
    db.add(identity)
    db.commit()
    db.refresh(identity)

    AuditService(db).log(
        actor=actor,
        action=AuditAction.IDENTITY_CREATED,
        resource_type="identity",
        resource_id=str(identity.id),
        request=request,
        details={
            "display_name": display_name,
            "identity_type": identity_type.value,
            "detection_confidence": face.confidence,
        },
    )
    return identity


@router.get("", response_model=list[IdentityRead])
def list_identities(
    identity_type: IdentityType | None = None,
    is_active: bool = True,
    limit: int = 100,
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    q = db.query(Identity).filter(Identity.is_active == is_active)
    if identity_type:
        q = q.filter(Identity.identity_type == identity_type)
    return q.order_by(Identity.created_at.desc()).limit(limit).all()


@router.delete("/{identity_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_identity(
    identity_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    """Watchlist'ten kayıt sil — KVKK silme talepleri için."""
    identity = db.get(Identity, identity_id)
    if not identity:
        return

    # Qdrant'tan da sil
    VectorStore().delete_face(identity.qdrant_point_id)

    db.delete(identity)
    db.commit()

    AuditService(db).log(
        actor=actor,
        action=AuditAction.IDENTITY_DELETED,
        resource_type="identity",
        resource_id=str(identity_id),
        request=request,
        details={"display_name": identity.display_name},
    )
