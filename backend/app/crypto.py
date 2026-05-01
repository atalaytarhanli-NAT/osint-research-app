from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings


def _cipher() -> Fernet:
    return Fernet(get_settings().encryption_key.encode())


def encrypt(value: str) -> str:
    return _cipher().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _cipher().decrypt(token.encode()).decode()
    except InvalidToken:
        return ""
