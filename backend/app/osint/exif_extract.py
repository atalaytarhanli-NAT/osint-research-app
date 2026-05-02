"""EXIF metadata extraction — A9 IMINT (NATO/IC).

Yüklenen görselin EXIF metadata'sı (kamera markası/modeli, çekim tarihi, GPS
koordinatları, yönelim) çıkartılır. GPS varsa lat/lon decimal olarak döner —
geolocation modülünün kullanması için.

Pillow dependency.
"""

from __future__ import annotations

import io
import logging
from typing import Any


log = logging.getLogger("osint.exif")


# Önemli EXIF tag'leri
INTERESTING_TAGS = {
    "Make", "Model", "Software", "DateTime", "DateTimeOriginal", "DateTimeDigitized",
    "Artist", "Copyright", "ImageDescription", "Orientation", "ExposureTime", "FNumber",
    "ISOSpeedRatings", "FocalLength", "GPSInfo", "LensModel", "LensMake",
}


def _gps_to_decimal(gps_info: dict) -> tuple[float, float] | None:
    """GPSInfo tag dict → (lat, lon) decimal. None if missing/invalid."""
    try:
        from PIL.ExifTags import GPSTAGS
    except ImportError:
        return None

    # GPSInfo numeric tag'lerini name'e çevir
    parsed: dict[str, Any] = {}
    for k, v in (gps_info or {}).items():
        name = GPSTAGS.get(k, str(k))
        parsed[name] = v

    lat_ref = parsed.get("GPSLatitudeRef")
    lon_ref = parsed.get("GPSLongitudeRef")
    lat = parsed.get("GPSLatitude")
    lon = parsed.get("GPSLongitude")
    if not (lat and lon and lat_ref and lon_ref):
        return None

    def _to_decimal(dms) -> float:
        d, m, s = float(dms[0]), float(dms[1]), float(dms[2])
        return d + (m / 60.0) + (s / 3600.0)

    try:
        lat_d = _to_decimal(lat) * (-1 if lat_ref in ("S", "s") else 1)
        lon_d = _to_decimal(lon) * (-1 if lon_ref in ("W", "w") else 1)
        if -90 <= lat_d <= 90 and -180 <= lon_d <= 180 and (lat_d, lon_d) != (0.0, 0.0):
            return (lat_d, lon_d)
    except (TypeError, ValueError, IndexError):
        return None
    return None


def extract_exif(image_bytes: bytes) -> dict:
    """Görsel byte'ından EXIF metadata çıkar. Boş döner Pillow yoksa veya hata olursa.

    Çıktı:
    {
      'has_exif': bool,
      'tags': {tag_name: str_value, ...},
      'gps': {'lat': float, 'lon': float} | None,
      'camera': str | None,
      'taken_at': str | None,
      'software': str | None,
    }
    """
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        log.info("Pillow not installed; EXIF extraction skipped")
        return {"has_exif": False, "tags": {}, "gps": None}

    try:
        img = Image.open(io.BytesIO(image_bytes))
        raw = img._getexif()  # type: ignore
    except Exception as exc:
        log.debug("EXIF read failed: %s", exc)
        return {"has_exif": False, "tags": {}, "gps": None}

    if not raw:
        return {"has_exif": False, "tags": {}, "gps": None}

    tags: dict[str, str] = {}
    gps_info = None
    for tag_id, value in raw.items():
        name = TAGS.get(tag_id, str(tag_id))
        if name == "GPSInfo":
            gps_info = value
            continue
        if name not in INTERESTING_TAGS:
            continue
        # Bytes/tuple representation'ları string'e çevir
        if isinstance(value, bytes):
            try:
                value = value.decode(errors="ignore").strip("\x00").strip()
            except Exception:
                value = str(value)
        if isinstance(value, (tuple, list)):
            value = ", ".join(str(v) for v in value)
        s = str(value).strip()
        if s:
            tags[name] = s[:200]

    gps = None
    if gps_info:
        coord = _gps_to_decimal(gps_info)
        if coord:
            gps = {"lat": coord[0], "lon": coord[1]}

    camera = None
    if tags.get("Make") or tags.get("Model"):
        camera = " ".join(filter(None, [tags.get("Make"), tags.get("Model")]))

    taken_at = tags.get("DateTimeOriginal") or tags.get("DateTime")
    software = tags.get("Software")

    return {
        "has_exif": True,
        "tags": tags,
        "gps": gps,
        "camera": camera,
        "taken_at": taken_at,
        "software": software,
    }
