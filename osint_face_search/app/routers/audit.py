"""Audit log sorgulama endpoint'leri (sadece okuma)."""
from datetime import datetime
from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_actor
from app.models import AuditLog, AuditAction
from app.schemas import AuditLogRead

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(
    case_id: UUID | None = Query(None),
    actor: str | None = Query(None),
    action: AuditAction | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
    _current_actor: str = Depends(get_current_actor),
):
    """Audit kayıtlarını filtrele ve getir."""
    q = db.query(AuditLog)
    if case_id:
        q = q.filter(AuditLog.case_id == case_id)
    if actor:
        q = q.filter(AuditLog.actor == actor)
    if action:
        q = q.filter(AuditLog.action == action)
    if since:
        q = q.filter(AuditLog.timestamp >= since)
    if until:
        q = q.filter(AuditLog.timestamp <= until)

    return q.order_by(AuditLog.timestamp.desc()).limit(limit).all()
