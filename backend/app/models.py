from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(120))
    is_admin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    jobs: Mapped[list["ResearchJob"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class ApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("user_id", "provider", name="uq_user_provider"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(40), index=True)
    encrypted_value: Mapped[str] = mapped_column(Text)
    model: Mapped[Optional[str]] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    user: Mapped[User] = relationship(back_populates="api_keys")


class ResearchJob(Base):
    __tablename__ = "research_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(String(40))  # auto/person/organization/url/keyword/social
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending/running/done/error
    result_json: Mapped[Optional[str]] = mapped_column(Text)
    error: Mapped[Optional[str]] = mapped_column(Text)
    used_llm: Mapped[Optional[str]] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="jobs")
