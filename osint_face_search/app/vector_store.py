"""Qdrant vektör veri tabanı sarmalayıcısı."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue,
)

from app.config import get_settings


@dataclass
class VectorMatch:
    """Qdrant'tan dönen tek bir benzerlik sonucu."""
    point_id: str
    score: float
    payload: dict


class VectorStore:
    """Qdrant koleksiyon yönetimi ve arama."""

    def __init__(self) -> None:
        settings = get_settings()
        self._client = QdrantClient(
            host=settings.qdrant_host,
            port=settings.qdrant_port,
        )
        self._collection = settings.qdrant_collection
        self._vector_size = settings.qdrant_vector_size

    # ---------- Koleksiyon yönetimi ----------

    def ensure_collection(self) -> None:
        """Koleksiyon yoksa oluştur. Uygulama başlangıcında çağrılır."""
        collections = {c.name for c in self._client.get_collections().collections}
        if self._collection not in collections:
            self._client.create_collection(
                collection_name=self._collection,
                vectors_config=VectorParams(
                    size=self._vector_size,
                    distance=Distance.COSINE,
                ),
            )

    def health_check(self) -> bool:
        try:
            self._client.get_collections()
            return True
        except Exception:
            return False

    # ---------- Yazma ----------

    def upsert_face(
        self,
        embedding: np.ndarray,
        payload: dict,
        point_id: str | None = None,
    ) -> str:
        """Tek bir yüz embedding'ini koleksiyona ekler/günceller."""
        if point_id is None:
            point_id = str(uuid.uuid4())

        self._client.upsert(
            collection_name=self._collection,
            points=[
                PointStruct(
                    id=point_id,
                    vector=embedding.tolist(),
                    payload=payload,
                )
            ],
        )
        return point_id

    def delete_face(self, point_id: str) -> None:
        self._client.delete(
            collection_name=self._collection,
            points_selector=[point_id],
        )

    # ---------- Arama ----------

    def search(
        self,
        embedding: np.ndarray,
        limit: int = 5,
        score_threshold: float = 0.55,
        only_active: bool = True,
    ) -> list[VectorMatch]:
        """Cosine similarity tabanlı en yakın komşu araması."""
        query_filter = None
        if only_active:
            query_filter = Filter(
                must=[FieldCondition(key="is_active", match=MatchValue(value=True))]
            )

        hits = self._client.search(
            collection_name=self._collection,
            query_vector=embedding.tolist(),
            limit=limit,
            score_threshold=score_threshold,
            query_filter=query_filter,
        )

        return [
            VectorMatch(
                point_id=str(h.id),
                score=float(h.score),
                payload=dict(h.payload or {}),
            )
            for h in hits
        ]
