"""InsightFace tabanlı yüz tespit ve embedding üretimi.

Singleton yaklaşımı kullanılır — model yüklemesi pahalıdır,
uygulama başlangıcında bir kez yüklenir.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from threading import Lock
import numpy as np
from PIL import Image

from app.config import get_settings


@dataclass
class DetectedFace:
    """Tespit edilmiş tek bir yüz."""
    bbox: tuple[float, float, float, float]   # x1, y1, x2, y2
    confidence: float
    embedding: np.ndarray                      # 512-boyutlu ArcFace vektörü
    age: int | None = None
    gender: str | None = None


class FaceEngine:
    """InsightFace ArcFace + RetinaFace orkestratörü."""

    _instance: "FaceEngine | None" = None
    _lock = Lock()

    def __init__(self) -> None:
        from insightface.app import FaceAnalysis  # lazy import — model dosyaları indirilir

        settings = get_settings()
        self._threshold = settings.face_detection_threshold

        # buffalo_l: RetinaFace + ArcFace (512-d) + age/gender
        # CPU için providers=["CPUExecutionProvider"]; GPU varsa CUDAExecutionProvider eklenir
        self._app = FaceAnalysis(
            name=settings.face_model_name,
            providers=["CPUExecutionProvider"],
        )
        self._app.prepare(ctx_id=-1, det_size=(640, 640))

    @classmethod
    def get_instance(cls) -> "FaceEngine":
        """Thread-safe singleton."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @staticmethod
    def _bytes_to_array(image_bytes: bytes) -> np.ndarray:
        """Görüntü baytlarını OpenCV BGR numpy dizisine çevirir."""
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.array(img)
        # PIL RGB → OpenCV BGR
        return arr[:, :, ::-1].copy()

    def detect_and_embed(self, image_bytes: bytes) -> list[DetectedFace]:
        """Görüntüdeki tüm yüzleri tespit eder ve embedding'lerini çıkarır."""
        img = self._bytes_to_array(image_bytes)
        faces = self._app.get(img)

        results: list[DetectedFace] = []
        for f in faces:
            if f.det_score < self._threshold:
                continue
            results.append(
                DetectedFace(
                    bbox=tuple(float(x) for x in f.bbox),
                    confidence=float(f.det_score),
                    embedding=f.normed_embedding.astype(np.float32),
                    age=int(f.age) if hasattr(f, "age") else None,
                    gender="M" if getattr(f, "gender", None) == 1 else
                           "F" if getattr(f, "gender", None) == 0 else None,
                )
            )
        return results

    def embed_single_face(self, image_bytes: bytes) -> DetectedFace:
        """Watchlist kaydı için: tek yüzlü görselde en yüksek skorlu yüzü döndürür.

        Birden fazla yüz varsa veya hiç yüz yoksa hata fırlatır.
        """
        faces = self.detect_and_embed(image_bytes)
        if not faces:
            raise ValueError("Görselde yüz tespit edilemedi")
        if len(faces) > 1:
            raise ValueError(
                f"Görselde {len(faces)} yüz var. Watchlist kaydı için tek yüzlü "
                "görsel gereklidir."
            )
        return faces[0]
