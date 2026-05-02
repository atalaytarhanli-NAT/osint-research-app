"""FastAPI uygulama girişi."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app import __version__
from app.config import get_settings
from app.database import get_db, engine
from app.face_engine import FaceEngine
from app.vector_store import VectorStore
from app.schemas import HealthCheck
from app.routers import cases, search, watchlist, audit, external_search


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlangıcı: model yükleme ve Qdrant koleksiyonu hazırlama."""
    # Qdrant koleksiyonunu oluştur
    VectorStore().ensure_collection()
    # InsightFace modelini önceden yükle (ilk istekte gecikmesin)
    FaceEngine.get_instance()
    yield
    # Kapanış: kaynaklarla ilgili özel temizlik gerekirse buraya


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="OSINT Face Search",
        description="Kurumsal yüz tanıma ve OSINT entegrasyonu — KVKK uyumlu",
        version=__version__,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],   # production'da kısıtlanmalı
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    prefix = settings.api_v1_prefix
    app.include_router(cases.router, prefix=prefix)
    app.include_router(watchlist.router, prefix=prefix)
    app.include_router(search.router, prefix=prefix)
    app.include_router(external_search.router, prefix=prefix)
    app.include_router(audit.router, prefix=prefix)

    @app.get("/health", response_model=HealthCheck, tags=["system"])
    def health():
        # DB
        db_ok = False
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                db_ok = True
        except Exception:
            pass

        # Qdrant
        qdrant_ok = VectorStore().health_check()

        # Face engine
        face_ok = False
        try:
            FaceEngine.get_instance()
            face_ok = True
        except Exception:
            pass

        return HealthCheck(
            status="ok" if all([db_ok, qdrant_ok, face_ok]) else "degraded",
            version=__version__,
            qdrant_connected=qdrant_ok,
            db_connected=db_ok,
            face_engine_loaded=face_ok,
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
