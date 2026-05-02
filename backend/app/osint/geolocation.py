"""Coğrafi konum çıkarımı — A4 GEOINT (NATO/IC).

Mevcut kaynaklardan koordinat sinyali toplar:
1. Wikidata raw'da P625 (coordinate location) — en güvenilir
2. Snippet/title regex (ör. "lat,lon", "Istanbul, Turkey", popüler şehir adları)
3. crt.sh DNS hostname → IP geo (ip-api.com ücretsiz)
4. Sources içindeki city/country mention'lardan jeo-kodlama (Nominatim)

Pasif post-process: pipeline kaynaklarını alır, harita için lat/lon noktaları üretir.
Yeni dependency yok (httpx + regex).
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlparse

import httpx


log = logging.getLogger("osint.geolocation")


# Ön tanımlı şehir koordinatları (Türkiye + global ana şehirler) — hızlı eşleşme
_KNOWN_CITIES: dict[str, tuple[float, float, str]] = {
    "istanbul": (41.0082, 28.9784, "TR"),
    "ankara": (39.9334, 32.8597, "TR"),
    "izmir": (38.4192, 27.1287, "TR"),
    "bursa": (40.1828, 29.0665, "TR"),
    "antalya": (36.8969, 30.7133, "TR"),
    "konya": (37.8746, 32.4932, "TR"),
    "adana": (37.0000, 35.3213, "TR"),
    "gaziantep": (37.0662, 37.3833, "TR"),
    "trabzon": (41.0027, 39.7168, "TR"),
    "kayseri": (38.7312, 35.4787, "TR"),
    "london": (51.5074, -0.1278, "GB"),
    "new york": (40.7128, -74.0060, "US"),
    "san francisco": (37.7749, -122.4194, "US"),
    "los angeles": (34.0522, -118.2437, "US"),
    "washington": (38.9072, -77.0369, "US"),
    "boston": (42.3601, -71.0589, "US"),
    "chicago": (41.8781, -87.6298, "US"),
    "paris": (48.8566, 2.3522, "FR"),
    "berlin": (52.5200, 13.4050, "DE"),
    "munich": (48.1351, 11.5820, "DE"),
    "amsterdam": (52.3676, 4.9041, "NL"),
    "brussels": (50.8503, 4.3517, "BE"),
    "madrid": (40.4168, -3.7038, "ES"),
    "barcelona": (41.3851, 2.1734, "ES"),
    "rome": (41.9028, 12.4964, "IT"),
    "milan": (45.4642, 9.1900, "IT"),
    "vienna": (48.2082, 16.3738, "AT"),
    "zurich": (47.3769, 8.5417, "CH"),
    "stockholm": (59.3293, 18.0686, "SE"),
    "moscow": (55.7558, 37.6173, "RU"),
    "tokyo": (35.6762, 139.6503, "JP"),
    "seoul": (37.5665, 126.9780, "KR"),
    "beijing": (39.9042, 116.4074, "CN"),
    "shanghai": (31.2304, 121.4737, "CN"),
    "singapore": (1.3521, 103.8198, "SG"),
    "hong kong": (22.3193, 114.1694, "HK"),
    "dubai": (25.2048, 55.2708, "AE"),
    "tel aviv": (32.0853, 34.7818, "IL"),
    "jerusalem": (31.7683, 35.2137, "IL"),
    "doha": (25.2854, 51.5310, "QA"),
    "riyadh": (24.7136, 46.6753, "SA"),
    "cairo": (30.0444, 31.2357, "EG"),
    "athens": (37.9838, 23.7275, "GR"),
    "sydney": (-33.8688, 151.2093, "AU"),
    "melbourne": (-37.8136, 144.9631, "AU"),
    "toronto": (43.6532, -79.3832, "CA"),
    "vancouver": (49.2827, -123.1207, "CA"),
    "sao paulo": (-23.5505, -46.6333, "BR"),
    "mexico city": (19.4326, -99.1332, "MX"),
    "buenos aires": (-34.6037, -58.3816, "AR"),
}


# Lat/lon decimal regex
_COORD_RE = re.compile(r"\b(-?\d{1,2}\.\d{2,6})\s*[,;]\s*(-?\d{1,3}\.\d{2,6})\b")


def _extract_from_text(text: str) -> list[tuple[float, float, str]]:
    """Metinden lat/lon decimal pair çıkar."""
    points: list[tuple[float, float, str]] = []
    for m in _COORD_RE.finditer(text or ""):
        try:
            lat, lon = float(m.group(1)), float(m.group(2))
            if -90 <= lat <= 90 and -180 <= lon <= 180 and (lat, lon) != (0.0, 0.0):
                points.append((lat, lon, "regex"))
        except ValueError:
            continue
    return points


def _city_match(text: str) -> list[tuple[float, float, str]]:
    """Tanınan şehir adlarını eşle."""
    if not text:
        return []
    low = text.lower()
    out: list[tuple[float, float, str]] = []
    seen: set[str] = set()
    for city, (lat, lon, country) in _KNOWN_CITIES.items():
        # Word boundary kontrolü — "san" "san francisco"u tetiklemesin diye
        if re.search(rf"\b{re.escape(city)}\b", low):
            if city in seen:
                continue
            seen.add(city)
            out.append((lat, lon, f"city:{city}"))
    return out


def _from_wikidata(s: dict) -> list[tuple[float, float, str]]:
    """Wikidata raw P625 koordinatı varsa çıkar."""
    raw = s.get("raw") or {}
    coord = raw.get("coordinate") or raw.get("P625")
    if not coord:
        return []
    if isinstance(coord, dict):
        lat = coord.get("latitude") or coord.get("lat")
        lon = coord.get("longitude") or coord.get("lon")
        if lat is not None and lon is not None:
            try:
                return [(float(lat), float(lon), "wikidata")]
            except (ValueError, TypeError):
                pass
    if isinstance(coord, (list, tuple)) and len(coord) >= 2:
        try:
            return [(float(coord[0]), float(coord[1]), "wikidata")]
        except (ValueError, TypeError):
            pass
    return []


async def _ip_geo(client: httpx.AsyncClient, host: str) -> list[tuple[float, float, str]]:
    """ip-api.com ücretsiz JSON — host adından coğrafi konum (45 req/dk free)."""
    if not host or " " in host:
        return []
    try:
        r = await client.get(
            f"http://ip-api.com/json/{host}",
            params={"fields": "status,country,lat,lon,city,query"},
            timeout=4.0,
        )
        if r.status_code != 200:
            return []
        d = r.json()
        if d.get("status") != "success":
            return []
        lat, lon = d.get("lat"), d.get("lon")
        if lat is None or lon is None:
            return []
        label = f"ip:{d.get('city') or '?'}"
        return [(float(lat), float(lon), label)]
    except Exception as exc:
        log.debug("ip-api failed for %s: %s", host, exc)
        return []


async def extract_geopoints(target: str, sources: list[dict], max_ip_lookups: int = 5) -> list[dict]:
    """Tüm kaynaklardan koordinat noktası topla. Frontend harita için liste döndür.

    Çıktı: [{lat, lon, label, source_indices: [...], origin: 'wikidata'|'city'|'ip'|'regex'}]
    """
    if not sources:
        return []

    # (lat, lon) → {origins: set, source_indices: list, label}
    bucket: dict[tuple[float, float], dict] = {}

    def _add(lat: float, lon: float, origin: str, idx: int, label_hint: str = ""):
        # Quantize 4 decimal — yakın komşu noktaları birleştir
        key = (round(lat, 4), round(lon, 4))
        if key not in bucket:
            bucket[key] = {"lat": lat, "lon": lon, "origins": set(), "source_indices": [], "label": label_hint or origin}
        bucket[key]["origins"].add(origin)
        if idx not in bucket[key]["source_indices"]:
            bucket[key]["source_indices"].append(idx)
        if label_hint and len(label_hint) > len(bucket[key]["label"]):
            bucket[key]["label"] = label_hint

    # 1) Wikidata + text mining (her source)
    for i, s in enumerate(sources):
        for lat, lon, origin in _from_wikidata(s):
            _add(lat, lon, "wikidata", i, label_hint=s.get("title", "")[:80])
        text = " ".join([s.get("title") or "", s.get("snippet") or ""])
        for lat, lon, origin in _extract_from_text(text):
            _add(lat, lon, origin, i, label_hint=s.get("title", "")[:80])
        for lat, lon, origin in _city_match(text):
            _add(lat, lon, origin, i, label_hint=origin.replace("city:", "").title())

    # 2) IP geo (sadece dns/cybint kaynakları + crtsh subdomain hostname'leri için)
    ip_lookup_hosts: list[tuple[int, str]] = []
    for i, s in enumerate(sources):
        kind = s.get("kind", "")
        if kind in ("cybint", "archive") and s.get("source") in ("crtsh", "dns"):
            try:
                host = urlparse(s.get("url", "")).hostname or ""
            except Exception:
                host = ""
            if host:
                ip_lookup_hosts.append((i, host))
        if len(ip_lookup_hosts) >= max_ip_lookups:
            break

    if ip_lookup_hosts:
        async with httpx.AsyncClient() as c:
            results = await asyncio.gather(*[_ip_geo(c, h) for _, h in ip_lookup_hosts])
            for (idx, _host), points in zip(ip_lookup_hosts, results):
                for lat, lon, origin in points:
                    _add(lat, lon, origin, idx, label_hint=origin)

    out: list[dict] = []
    for (k1, k2), v in bucket.items():
        out.append({
            "lat": v["lat"],
            "lon": v["lon"],
            "label": v["label"][:120],
            "origins": sorted(v["origins"]),
            "source_indices": v["source_indices"][:10],
        })
    # Sort: origins çeşidi yüksek + source_indices çok olanlar öne
    out.sort(key=lambda p: (-len(p["origins"]), -len(p["source_indices"])))
    return out[:30]
