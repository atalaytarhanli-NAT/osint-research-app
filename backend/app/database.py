from __future__ import annotations

import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


log = logging.getLogger("db")

settings = get_settings()

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Lightweight, idempotent column migrations. SQLAlchemy's create_all does not
# add columns to pre-existing tables, so when we add a new column to an
# existing model we list it here. Each entry: (table, column_name, ddl_for_postgres, ddl_for_sqlite).
_PENDING_COLUMNS: list[tuple[str, str, str, str]] = [
    (
        "users",
        "is_active",
        "BOOLEAN DEFAULT TRUE NOT NULL",
        "BOOLEAN DEFAULT 1 NOT NULL",
    ),
    (
        "research_jobs",
        "intensity",
        "VARCHAR(10) DEFAULT 'deep' NOT NULL",
        "VARCHAR(10) DEFAULT 'deep' NOT NULL",
    ),
    (
        "research_jobs",
        "scope",
        "VARCHAR(10) DEFAULT 'all' NOT NULL",
        "VARCHAR(10) DEFAULT 'all' NOT NULL",
    ),
]


def _run_pending_migrations() -> None:
    is_sqlite = settings.database_url.startswith("sqlite")
    inspector = inspect(engine)
    for table, column, pg_ddl, sqlite_ddl in _PENDING_COLUMNS:
        if not inspector.has_table(table):
            continue
        existing = {c["name"] for c in inspector.get_columns(table)}
        if column in existing:
            continue
        ddl = sqlite_ddl if is_sqlite else pg_ddl
        stmt = f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"
        try:
            with engine.begin() as conn:
                conn.execute(text(stmt))
            log.info("migrated: %s", stmt)
        except Exception as exc:
            log.warning("migration failed for %s.%s: %s", table, column, exc)


def init_db() -> None:
    from . import models  # noqa: F401  ensure models are registered

    Base.metadata.create_all(bind=engine)
    _run_pending_migrations()
