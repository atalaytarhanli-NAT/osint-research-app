"""Qdrant koleksiyonunu manuel oluşturma scripti.

Normalde uygulama lifespan içinde otomatik yapar; bu script
bağımsız bir kontrol veya CI/CD'de kullanım içindir.

Kullanım: python -m scripts.init_qdrant
"""
from app.vector_store import VectorStore
from app.config import get_settings


def main() -> None:
    settings = get_settings()
    print(f"Qdrant: {settings.qdrant_host}:{settings.qdrant_port}")
    print(f"Koleksiyon: {settings.qdrant_collection}")

    vstore = VectorStore()
    if not vstore.health_check():
        print("✗ Qdrant'a bağlanılamıyor. Docker servisi çalışıyor mu?")
        return

    vstore.ensure_collection()
    print("✓ Koleksiyon hazır.")


if __name__ == "__main__":
    main()
