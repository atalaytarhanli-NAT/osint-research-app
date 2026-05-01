from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True, parents=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    env: str = "development"
    secret_key: str = secrets.token_urlsafe(32)
    encryption_key: str = ""  # Fernet base64 key, generated on first run if empty
    database_url: str = f"sqlite:///{DATA_DIR / 'app.db'}"
    access_token_expire_minutes: int = 60 * 24 * 7
    allow_registration: bool = True
    cors_origins: str = "*"

    # Default LLM (used only if a system-wide key is provided via env; otherwise rule-based)
    default_llm_provider: str = ""
    default_llm_key: str = ""
    default_llm_model: str = ""


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    # Render Postgres compatibility: rewrite legacy postgres:// scheme.
    if s.database_url.startswith("postgres://"):
        s.database_url = s.database_url.replace("postgres://", "postgresql://", 1)
    if not s.encryption_key:
        # Generate and persist a Fernet key on first run for local dev convenience.
        # In production, set APP_ENCRYPTION_KEY explicitly (Render render.yaml does this).
        from cryptography.fernet import Fernet

        keyfile = DATA_DIR / ".fernet_key"
        if keyfile.exists():
            s.encryption_key = keyfile.read_text().strip()
        else:
            new_key = Fernet.generate_key().decode()
            keyfile.write_text(new_key)
            s.encryption_key = new_key
            os.environ["APP_ENCRYPTION_KEY"] = new_key
    return s
