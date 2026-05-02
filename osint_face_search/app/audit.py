"""KVKK denetim kayıt servisi.

Her arama, ekleme ve silme işlemi append-only audit_logs tablosuna yazılır.
İmmutability uygulama seviyesinde sağlanır (UPDATE/DELETE iznine sahip rol yok).
"""
from __future__ import annotations

from uuid import UUID
from sqlalchemy.orm import Session
from fastapi import Request

from app.models import AuditLog, AuditAction


class AuditService:
    """Denetim kaydı yardımcısı."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def log(
        self,
        actor: str,
        action: AuditAction,
        resource_type: str,
        resource_id: str | None = None,
        case_id: UUID | None = None,
        request: Request | None = None,
        details: dict | None = None,
    ) -> AuditLog:
        """Audit kaydı oluştur ve commit et."""
        entry = AuditLog(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            case_id=case_id,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=details or {},
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry
