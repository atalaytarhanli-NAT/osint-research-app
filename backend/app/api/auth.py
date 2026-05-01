from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from ..config import get_settings
from ..database import get_db
from ..models import User


router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    display_name: str | None = Field(default=None, max_length=120)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: EmailStr
    display_name: str | None
    is_admin: bool


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        secure=get_settings().env == "production",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )


@router.post("/register", response_model=TokenOut)
def register(data: RegisterIn, response: Response, db: Session = Depends(get_db)):
    if not get_settings().allow_registration:
        raise HTTPException(status_code=403, detail="Registration disabled")

    existing = db.scalar(select(User).where(User.email == data.email))
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        display_name=data.display_name or data.email.split("@")[0],
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id)
    _set_cookie(response, token)
    return TokenOut(access_token=token)


@router.post("/login", response_model=TokenOut)
def login(data: LoginIn, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == data.email))
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.id)
    _set_cookie(response, token)
    return TokenOut(access_token=token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response):
    response.delete_cookie("access_token", path="/")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut(
        id=user.id, email=user.email, display_name=user.display_name, is_admin=user.is_admin
    )
