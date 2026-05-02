"""Uygulama yapılandırma yönetimi (Pydantic Settings)."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Ortam değişkenlerinden okunan tüm yapılandırma."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Uygulama
    app_name: str = "osint-face-search"
    app_env: str = "development"
    log_level: str = "INFO"

    # API
    api_v1_prefix: str = "/api/v1"
    api_key: str = "change-me"

    # Veri tabanı
    database_url: str

    # Qdrant
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection: str = "face_embeddings"
    qdrant_vector_size: int = 512

    # Yüz tanıma
    face_model_name: str = "buffalo_l"
    face_detection_threshold: float = 0.6
    face_match_threshold: float = 0.55
    max_image_size_mb: int = 10

    # KVKK / saklama
    embedding_retention_days: int = 90
    audit_log_retention_days: int = 730

    # ---------- Dış servis adaptör API key'leri ----------
    # Hepsi opsiyonel — hangileri tanımlıysa o adaptör etkin olur

    facecheck_api_key: str | None = None
    pimeyes_api_key: str | None = None
    lenso_api_key: str | None = None
    faceseek_api_key: str | None = None
    tineye_api_key: str | None = None
    bing_api_key: str | None = None
    google_vision_api_key: str | None = None
    saucenao_api_key: str | None = None    # opsiyonel; key olmadan da çalışır

    # Orkestratör
    orchestrator_timeout_seconds: int = 120
    orchestrator_default_adapters: str = "facecheck,tineye,saucenao"
    """Virgülle ayrılmış varsayılan adaptör listesi.
    Boş bırakılırsa: tüm etkin adaptörler kullanılır."""


@lru_cache
def get_settings() -> Settings:
    """Singleton ayar nesnesi (lru_cache ile cache'lenir)."""
    return Settings()
