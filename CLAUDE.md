# OSINT Research App — Geliştirici Notları

Bu dosya, Claude Code asistanları için proje konvansiyonlarını özetler.

## Stack

- **Python 3.12**, **FastAPI 0.115**, **SQLAlchemy 2.0** (sync, basit)
- SQLite (lokal + Render free disk persist), Fernet ile şifreli API key kolonu
- Frontend: Jinja2 + Tailwind CDN + Alpine.js + Chart.js (build yok)
- Auth: JWT (HS256), httpOnly cookie + Authorization bearer

## Konvansiyonlar

- Tüm dış HTTP çağrıları `httpx.AsyncClient` ile, 8 sn timeout, 1 retry
- OSINT modülleri ortak `SourceResult` döner; pipeline `asyncio.gather` ile paralel
- Hassas veri (API anahtarları) **asla loglanmaz**, DB'ye Fernet ile şifreli yazılır
- LLM çağrısı opsiyonel — kullanıcının anahtarı yoksa kuralsal sentez devreye girer
- Endpoint isimleri: `/api/{resource}` (REST), HTML rotaları kök altında

## Deploy

`render.yaml` Blueprint olarak deploy eder. `APP_SECRET_KEY` ve `APP_ENCRYPTION_KEY`
Render tarafından otomatik üretilir. SQLite veritabanı container içi `data/app.db`'de
durur (free tier'da kalıcı disk yok — kayıtlar restart sonrası gider; Plus tier
yükseltmesinde `disk:` eklenir).

## Etik kural

OSINT yalnızca açık kaynak. Sızıntı verisi, kapalı sistem, ToS ihlali yok.

## Skill'ler

`.claude/skills/` altındaki skill'ler bu uygulamanın CLI eşlenikleri.
