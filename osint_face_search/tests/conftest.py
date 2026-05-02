"""Pytest fixtures."""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.config import get_settings


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_headers():
    settings = get_settings()
    return {"X-API-Key": settings.api_key}
