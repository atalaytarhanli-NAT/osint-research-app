"""Pydantic istek/yanıt şemaları."""
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict

from app.models import CaseStatus, IdentityType, AuditAction


# ---------- Case ----------

class CaseCreate(BaseModel):
    case_number: str = Field(..., max_length=50, examples=["TAVS-2026-0042"])
    title: str = Field(..., max_length=255)
    description: str | None = None
    legal_basis: str = Field(
        ..., max_length=500,
        description="KVKK md. 5/6 dayanağı (örn: 'KVKK md. 5/2-e meşru menfaat')"
    )


class CaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_number: str
    title: str
    description: str | None
    status: CaseStatus
    legal_basis: str
    created_by: str
    created_at: datetime
    closed_at: datetime | None


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: CaseStatus | None = None


# ---------- Identity (watchlist) ----------

class IdentityCreate(BaseModel):
    external_ref: str | None = None
    identity_type: IdentityType
    display_name: str = Field(..., max_length=200)
    notes: str | None = None


class IdentityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    external_ref: str | None
    identity_type: IdentityType
    display_name: str
    notes: str | None
    is_active: bool
    qdrant_point_id: str
    created_by: str
    created_at: datetime
    updated_at: datetime


# ---------- Search ----------

class FaceMatch(BaseModel):
    """Tek bir eşleşme sonucu."""
    identity_id: UUID
    display_name: str
    identity_type: IdentityType
    external_ref: str | None
    similarity: float = Field(..., ge=0.0, le=1.0)
    notes: str | None = None


class SearchResponse(BaseModel):
    """/search endpoint yanıtı."""
    case_id: UUID
    detected_faces: int = Field(..., description="Görselde bulunan toplam yüz sayısı")
    matches: list[FaceMatch]
    threshold_used: float
    query_id: UUID = Field(..., description="Audit log korelasyon ID'si")


# ---------- Audit ----------

class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID | None
    actor: str
    action: AuditAction
    resource_type: str
    resource_id: str | None
    ip_address: str | None
    details: dict
    timestamp: datetime


# ---------- Sağlık kontrolü ----------

class HealthCheck(BaseModel):
    status: str
    version: str
    qdrant_connected: bool
    db_connected: bool
    face_engine_loaded: bool
