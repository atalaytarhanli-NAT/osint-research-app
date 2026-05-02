"""API key tabanlı kimlik doğrulama.

Bu MVP için basit bir API key kullanıyoruz. Production'da:
- OAuth2/OIDC (Keycloak veya Azure AD)
- Rol tabanlı erişim (admin, investigator, auditor)
- Per-user API key + rate limiting
"""
from fastapi import Header, HTTPException, status, Depends
from app.config import get_settings


def verify_api_key(x_api_key: str = Header(...)) -> str:
    """API key kontrolü. Header: X-API-Key"""
    settings = get_settings()
    if x_api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz API key",
        )
    # Production'da bu, kullanıcı ID'sini döndürecek şekilde genişletilir
    return "service-account"


def get_current_actor(actor_id: str = Depends(verify_api_key)) -> str:
    """Audit log için mevcut aktörü döndürür."""
    return actor_id
