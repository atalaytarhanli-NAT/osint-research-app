from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..auth import get_current_user, hash_password
from ..crypto import decrypt, encrypt
from ..database import get_db
from ..llm.providers import PROVIDERS, default_model_for
from ..models import ApiKey, ResearchJob, SystemApiKey, SystemSetting, User


router = APIRouter(prefix="/api/admin", tags=["admin"])


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# ----------------------- users -----------------------


class AdminUserOut(BaseModel):
    id: int
    email: EmailStr
    display_name: str | None
    is_admin: bool
    is_active: bool
    created_at: datetime
    job_count: int
    key_count: int


class UserPatchIn(BaseModel):
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None
    display_name: Optional[str] = Field(default=None, max_length=120)
    new_password: Optional[str] = Field(default=None, min_length=8, max_length=200)


class UserCreateIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    display_name: Optional[str] = None
    is_admin: bool = False


@router.get("/users", response_model=list[AdminUserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.scalars(select(User).order_by(User.id)).all()
    out: list[AdminUserOut] = []
    for u in rows:
        jc = db.scalar(select(func.count(ResearchJob.id)).where(ResearchJob.user_id == u.id)) or 0
        kc = db.scalar(select(func.count(ApiKey.id)).where(ApiKey.user_id == u.id)) or 0
        out.append(
            AdminUserOut(
                id=u.id,
                email=u.email,
                display_name=u.display_name,
                is_admin=u.is_admin,
                is_active=u.is_active,
                created_at=u.created_at,
                job_count=jc,
                key_count=kc,
            )
        )
    return out


@router.post("/users", response_model=AdminUserOut)
def create_user(
    data: UserCreateIn,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if db.scalar(select(User).where(User.email == data.email)):
        raise HTTPException(status_code=409, detail="Email already registered")
    u = User(
        email=data.email,
        password_hash=hash_password(data.password),
        display_name=data.display_name or data.email.split("@")[0],
        is_admin=data.is_admin,
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return AdminUserOut(
        id=u.id,
        email=u.email,
        display_name=u.display_name,
        is_admin=u.is_admin,
        is_active=u.is_active,
        created_at=u.created_at,
        job_count=0,
        key_count=0,
    )


@router.patch("/users/{user_id}", response_model=AdminUserOut)
def patch_user(
    user_id: int,
    data: UserPatchIn,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Don't allow admin to demote themselves if they are the last admin
    if data.is_admin is False and u.id == me.id:
        admin_count = db.scalar(select(func.count(User.id)).where(User.is_admin == True)) or 0  # noqa
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote last admin")

    if data.is_admin is not None:
        u.is_admin = data.is_admin
    if data.is_active is not None:
        u.is_active = data.is_active
    if data.display_name is not None:
        u.display_name = data.display_name
    if data.new_password:
        u.password_hash = hash_password(data.new_password)

    db.commit()
    db.refresh(u)
    jc = db.scalar(select(func.count(ResearchJob.id)).where(ResearchJob.user_id == u.id)) or 0
    kc = db.scalar(select(func.count(ApiKey.id)).where(ApiKey.user_id == u.id)) or 0
    return AdminUserOut(
        id=u.id,
        email=u.email,
        display_name=u.display_name,
        is_admin=u.is_admin,
        is_active=u.is_active,
        created_at=u.created_at,
        job_count=jc,
        key_count=kc,
    )


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if user_id == me.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")
    if u.is_admin:
        admin_count = db.scalar(select(func.count(User.id)).where(User.is_admin == True)) or 0  # noqa
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete last admin")
    db.delete(u)
    db.commit()


# ----------------------- system keys -----------------------


class SystemKeyOut(BaseModel):
    provider: str
    has_value: bool
    enabled: bool
    model: str | None
    masked: str | None
    updated_at: datetime | None


class SystemKeyIn(BaseModel):
    value: str = Field(min_length=4, max_length=4096)
    model: str | None = None
    enabled: bool = True


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return value[:4] + "•" * 8 + value[-4:]


@router.get("/system-keys", response_model=list[SystemKeyOut])
def list_system_keys(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = {r.provider: r for r in db.scalars(select(SystemApiKey)).all()}
    out: list[SystemKeyOut] = []
    for pid in PROVIDERS:
        r = rows.get(pid)
        if r is None:
            out.append(
                SystemKeyOut(
                    provider=pid,
                    has_value=False,
                    enabled=False,
                    model=None,
                    masked=None,
                    updated_at=None,
                )
            )
        else:
            plain = decrypt(r.encrypted_value)
            out.append(
                SystemKeyOut(
                    provider=pid,
                    has_value=bool(plain),
                    enabled=r.enabled,
                    model=r.model,
                    masked=_mask(plain),
                    updated_at=r.updated_at,
                )
            )
    return out


@router.put("/system-keys/{provider}", response_model=SystemKeyOut)
def upsert_system_key(
    provider: str,
    data: SystemKeyIn,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail="Unknown provider")
    r = db.get(SystemApiKey, provider)
    enc = encrypt(data.value.strip())
    model = data.model or default_model_for(provider)
    if r is None:
        r = SystemApiKey(provider=provider, encrypted_value=enc, model=model, enabled=data.enabled)
        db.add(r)
    else:
        r.encrypted_value = enc
        r.model = model
        r.enabled = data.enabled
    db.commit()
    db.refresh(r)
    return SystemKeyOut(
        provider=r.provider,
        has_value=True,
        enabled=r.enabled,
        model=r.model,
        masked=_mask(data.value.strip()),
        updated_at=r.updated_at,
    )


@router.delete("/system-keys/{provider}", status_code=204)
def delete_system_key(
    provider: str,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    r = db.get(SystemApiKey, provider)
    if r:
        db.delete(r)
        db.commit()


# ----------------------- jobs -----------------------


class AdminJobOut(BaseModel):
    id: int
    user_id: int
    user_email: str
    target: str
    kind: str
    status: str
    used_llm: str | None
    created_at: datetime
    finished_at: datetime | None


@router.get("/jobs", response_model=list[AdminJobOut])
def list_all_jobs(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
    limit: int = 200,
):
    rows = db.execute(
        select(ResearchJob, User)
        .join(User, ResearchJob.user_id == User.id)
        .order_by(desc(ResearchJob.created_at))
        .limit(limit)
    ).all()
    return [
        AdminJobOut(
            id=j.id,
            user_id=j.user_id,
            user_email=u.email,
            target=j.target,
            kind=j.kind,
            status=j.status,
            used_llm=j.used_llm,
            created_at=j.created_at,
            finished_at=j.finished_at,
        )
        for j, u in rows
    ]


@router.delete("/jobs/{job_id}", status_code=204)
def delete_any_job(
    job_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    j = db.get(ResearchJob, job_id)
    if j is None:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(j)
    db.commit()


# ----------------------- system settings -----------------------


class SystemConfigOut(BaseModel):
    registration_open: bool
    user_count: int
    admin_count: int
    job_count: int
    system_keys_enabled: list[str]


class SystemConfigIn(BaseModel):
    registration_open: bool


def _get_setting(db: Session, key: str, default: str) -> str:
    r = db.get(SystemSetting, key)
    return r.value if r else default


def _set_setting(db: Session, key: str, value: str) -> None:
    r = db.get(SystemSetting, key)
    if r is None:
        db.add(SystemSetting(key=key, value=value))
    else:
        r.value = value


@router.get("/system", response_model=SystemConfigOut)
def get_system(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    from ..config import get_settings

    reg_default = "1" if get_settings().allow_registration else "0"
    reg = _get_setting(db, "registration_open", reg_default) == "1"
    uc = db.scalar(select(func.count(User.id))) or 0
    ac = db.scalar(select(func.count(User.id)).where(User.is_admin == True)) or 0  # noqa
    jc = db.scalar(select(func.count(ResearchJob.id))) or 0
    keys = db.scalars(select(SystemApiKey).where(SystemApiKey.enabled == True)).all()  # noqa
    return SystemConfigOut(
        registration_open=reg,
        user_count=uc,
        admin_count=ac,
        job_count=jc,
        system_keys_enabled=[k.provider for k in keys],
    )


@router.put("/system", response_model=SystemConfigOut)
def update_system(
    data: SystemConfigIn,
    me: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _set_setting(db, "registration_open", "1" if data.registration_open else "0")
    db.commit()
    return get_system(_=me, db=db)
