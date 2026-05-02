"""Vaka (case) yönetimi endpoint'leri."""
from uuid import UUID
from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_actor
from app.audit import AuditService
from app.models import Case, CaseStatus, AuditAction
from app.schemas import CaseCreate, CaseRead, CaseUpdate
from app.exceptions import CaseNotFound

router = APIRouter(prefix="/cases", tags=["cases"])


@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    """Yeni soruşturma vakası oluştur."""
    existing = db.query(Case).filter(Case.case_number == payload.case_number).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Vaka numarası zaten mevcut: {payload.case_number}",
        )

    case = Case(
        case_number=payload.case_number,
        title=payload.title,
        description=payload.description,
        legal_basis=payload.legal_basis,
        created_by=actor,
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    AuditService(db).log(
        actor=actor,
        action=AuditAction.CASE_CREATED,
        resource_type="case",
        resource_id=str(case.id),
        case_id=case.id,
        request=request,
        details={"case_number": case.case_number, "legal_basis": case.legal_basis},
    )
    return case


@router.get("", response_model=list[CaseRead])
def list_cases(
    status_filter: CaseStatus | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    """Vakaları listele (varsayılan: hepsi)."""
    q = db.query(Case)
    if status_filter:
        q = q.filter(Case.status == status_filter)
    return q.order_by(Case.created_at.desc()).limit(limit).all()


@router.get("/{case_id}", response_model=CaseRead)
def get_case(
    case_id: UUID,
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    case = db.get(Case, case_id)
    if not case:
        raise CaseNotFound(str(case_id))
    return case


@router.patch("/{case_id}", response_model=CaseRead)
def update_case(
    case_id: UUID,
    payload: CaseUpdate,
    request: Request,
    db: Session = Depends(get_db),
    actor: str = Depends(get_current_actor),
):
    case = db.get(Case, case_id)
    if not case:
        raise CaseNotFound(str(case_id))

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(case, field, value)
    db.commit()
    db.refresh(case)

    AuditService(db).log(
        actor=actor,
        action=AuditAction.CASE_UPDATED,
        resource_type="case",
        resource_id=str(case.id),
        case_id=case.id,
        request=request,
        details={"changes": changes},
    )
    return case
