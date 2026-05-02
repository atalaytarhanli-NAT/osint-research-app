"""SQLAlchemy ORM modelleri."""
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    String, DateTime, Integer, ForeignKey, JSON, Enum, Boolean, Text, Float, func
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.database import Base


class CaseStatus(str, PyEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class IdentityType(str, PyEnum):
    PERSONNEL = "PERSONNEL"
    WATCHLIST = "WATCHLIST"
    INCIDENT = "INCIDENT"
    UNKNOWN = "UNKNOWN"


class AuditAction(str, PyEnum):
    SEARCH_PERFORMED = "SEARCH_PERFORMED"
    EXTERNAL_SEARCH_PERFORMED = "EXTERNAL_SEARCH_PERFORMED"
    IDENTITY_CREATED = "IDENTITY_CREATED"
    IDENTITY_DELETED = "IDENTITY_DELETED"
    CASE_CREATED = "CASE_CREATED"
    CASE_UPDATED = "CASE_UPDATED"
    EXPORT_PERFORMED = "EXPORT_PERFORMED"


class Case(Base):
    """Soruşturma vakası — tüm sorgular bir vakaya bağlı yapılır (KVKK gerekliliği)."""

    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_number: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[CaseStatus] = mapped_column(
        Enum(CaseStatus), default=CaseStatus.OPEN, nullable=False
    )
    legal_basis: Mapped[str] = mapped_column(
        String(500), nullable=False,
        comment="KVKK md. 5/6 hangi bend uyarınca işleme yapıldığı"
    )
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)

    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    external_searches: Mapped[list["ExternalSearchResult"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


class Identity(Base):
    """Watchlist veya personel kaydı."""

    __tablename__ = "identities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    external_ref: Mapped[str | None] = mapped_column(
        String(100), index=True,
        comment="HR sistem ID veya vaka referansı"
    )
    identity_type: Mapped[IdentityType] = mapped_column(
        Enum(IdentityType), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    qdrant_point_id: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class AuditLog(Base):
    """KVKK denetim kaydı — append-only."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), index=True
    )
    actor: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction), nullable=False, index=True
    )
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )

    case: Mapped["Case | None"] = relationship(back_populates="audit_logs")


class ExternalSearchResult(Base):
    """Dış servis (FaceCheck, PimEyes, vb.) sorgu kaydı.

    KVKK md. 9 uyarınca yurt dışına veri aktarımının kanıtı.
    Her dış sorgu burada saklanır — denetimde gösterilebilir.
    """

    __tablename__ = "external_search_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False, index=True
    )
    adapter_name: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    data_residency: Mapped[str] = mapped_column(
        String(10), nullable=False,
        comment="Aktarım yapılan ülke (US, EU, RU, ...)"
    )
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    matches_count: Mapped[int] = mapped_column(Integer, default=0)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    cost_credits: Mapped[float | None] = mapped_column(Float)
    response_payload: Mapped[dict] = mapped_column(
        JSON, default=dict,
        comment="Adaptör yanıtının özeti (eşleşme URL'leri ve skorları)"
    )
    queried_by: Mapped[str] = mapped_column(String(100), nullable=False)
    queried_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )

    case: Mapped["Case"] = relationship(back_populates="external_searches")
