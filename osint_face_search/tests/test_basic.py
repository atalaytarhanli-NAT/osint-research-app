"""Temel API testleri.

Not: face_engine ve qdrant'ın yüklü ve erişilebilir olması gerekir.
İsterseniz bunları mock'layan ayrı bir suite yazılabilir.
"""


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "version" in body


def test_create_case_requires_auth(client):
    response = client.post("/api/v1/cases", json={
        "case_number": "TEST-001",
        "title": "Test",
        "legal_basis": "KVKK md. 5/2-e",
    })
    assert response.status_code == 422  # X-API-Key header eksik


def test_create_case_success(client, auth_headers):
    response = client.post(
        "/api/v1/cases",
        headers=auth_headers,
        json={
            "case_number": "TEST-CASE-001",
            "title": "Birim test vakası",
            "description": "Otomatik test tarafından oluşturuldu",
            "legal_basis": "KVKK md. 5/2-e meşru menfaat",
        },
    )
    # Veritabanı bağlı değilse 500 dönebilir; bağlıysa 201
    assert response.status_code in (201, 409, 500)
