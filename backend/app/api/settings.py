from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..crypto import encrypt
from ..database import get_db
from ..llm.providers import PROVIDERS, default_model_for
from ..models import ApiKey, User


router = APIRouter(prefix="/api/settings", tags=["settings"])


class KeyIn(BaseModel):
    value: str = Field(min_length=4, max_length=4096)
    model: str | None = None


class KeyOut(BaseModel):
    provider: str
    has_value: bool
    model: str | None
    masked: str | None


class ProvidersOut(BaseModel):
    providers: list[dict]


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return value[:4] + "•" * 8 + value[-4:]


@router.get("/providers", response_model=ProvidersOut)
def list_providers():
    return ProvidersOut(
        providers=[
            {
                "id": p.id,
                "name": p.name,
                "open_source": p.open_source,
                "free_tier": p.free_tier,
                "default_model": p.default_model,
                "models": p.models,
                "docs_url": p.docs_url,
                "key_hint": p.key_hint,
            }
            for p in PROVIDERS.values()
        ]
    )


@router.get("/keys", response_model=list[KeyOut])
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(ApiKey).where(ApiKey.user_id == user.id)).all()
    out: list[KeyOut] = []
    for row in rows:
        from ..crypto import decrypt

        plain = decrypt(row.encrypted_value)
        out.append(
            KeyOut(
                provider=row.provider,
                has_value=bool(plain),
                model=row.model,
                masked=_mask(plain),
            )
        )
    return out


@router.put("/keys/{provider}", response_model=KeyOut)
def upsert_key(
    provider: str,
    payload: KeyIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider '{provider}'")

    row = db.scalar(
        select(ApiKey).where(ApiKey.user_id == user.id, ApiKey.provider == provider)
    )
    enc = encrypt(payload.value.strip())
    model = payload.model or default_model_for(provider)
    if row is None:
        row = ApiKey(user_id=user.id, provider=provider, encrypted_value=enc, model=model)
        db.add(row)
    else:
        row.encrypted_value = enc
        row.model = model
    db.commit()
    db.refresh(row)

    return KeyOut(
        provider=row.provider,
        has_value=True,
        model=row.model,
        masked=_mask(payload.value.strip()),
    )


@router.delete("/keys/{provider}", status_code=204)
def delete_key(
    provider: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(ApiKey).where(ApiKey.user_id == user.id, ApiKey.provider == provider)
    )
    if row:
        db.delete(row)
        db.commit()
