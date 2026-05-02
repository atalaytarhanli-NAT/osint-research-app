"""SQLAlchemy bağlantı yönetimi."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from typing import Generator

from app.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=settings.app_env == "development",
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """SQLAlchemy 2.0 stili declarative base."""

    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: per-request DB oturumu."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
