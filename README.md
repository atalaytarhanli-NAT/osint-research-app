# OSINT Research App

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/atalaytarhanli-NAT/osint-research-app)

Açık kaynak istihbarat (OSINT) ve dijital iz analizi için çoklu kullanıcılı web uygulaması.
Bir kişi, kurum, marka, anahtar kelime, sosyal medya hesabı veya link verildiğinde açık web
kaynaklarından derlenmiş yapılandırılmış bir analiz raporu üretir.

> **Test edildi**: Lokal e2e — bir araştırma çalıştırması ortalama 5–8 saniyede 30–50
> kaynak toplar. Anahtarsız modda rule-based rapor, anahtar eklendiğinde tam LLM sentezi.

## Özellikler

- **Çoklu kullanıcı**: kayıt + JWT login, her kullanıcının kendi geçmişi ve API anahtarları
- **API anahtarsız çalışır**: DuckDuckGo, Wikipedia, Wayback, HN, Reddit, GitHub, crt.sh,
  DNS-over-HTTPS, OpenSanctions, Ransomwatch, SEC EDGAR, SearXNG public
- **Pluggable LLM**: Settings'ten Groq / HuggingFace / OpenRouter / Anthropic /
  OpenAI / Google anahtarları; yoksa kural-bazlı + LLM-free template sentezi
- **NATO/IC standardı rapor**: BLUF + PIR matrisi + Admiralty Code (A-F × 1-6)
  + ACH (Çakışan Hipotezler) + Risk Matrisi (L×I) + Pivot Önerileri +
  İstihbarat Boşlukları + Yasal/Etik Beyan
- **20+ OSINT vektörü**: PERSINT (kişi) · CORPINT (kurum) · LINKINT (ilişki) · GEOINT (harita)
- **Yüz/görsel arama**: 10 dış adaptör (FaceCheck/PimEyes/Lenso/FaceSeek/TinEye/
  Bing Visual/Google Vision/SauceNAO + Yandex/Search4Faces) paralel + consensus skoru
- **PDF rapor çıktısı**: Server-side xhtml2pdf, DejaVu Sans (Türkçe), 14 bölüm
- **Koyu tema dashboard**: Tailwind + Alpine.js, build adımı yok, Leaflet harita
- **Auto-log**: Her assistant turu sonrası `docs/changelog/auto-log.md`'ye otomatik kayıt

## Etik / Yasal kapsam

Bu uygulama **yalnızca açık kaynaklı (OSINT) verilerle çalışır**. Aşağıdakileri yapmaz:

- Kapalı/şifreli alanlara, özel mesajlara veya kişisel cihazlara erişim
- Sızdırılmış / ihlal edilmiş veri kullanımı
- ToS ihlali içeren scraping veya kimlik doğrulama atlama

Kullandığınız her ülkede uygulanan yasalara (KVKK, GDPR vb.) uyumdan kullanıcı sorumludur.

## Lokal çalıştırma

```bash
pip install -r requirements.txt
export APP_SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export APP_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
uvicorn backend.app.main:app --reload
```

`http://localhost:8000` → kayıt ol → araştırma başlat.

## Deploy (Render) — 5 tıklamada canlı

Repo `render.yaml` blueprint içerir. Adımlar:

1. Yukarıdaki **Deploy to Render** butonuna bas (veya
   [render.com/deploy?repo=…](https://render.com/deploy?repo=https://github.com/atalaytarhanli-NAT/osint-research-app))
2. Render hesabı **atalay.tarhanli@gmail.com** ile giriş yap
3. Blueprint apply ekranında repoyu (`atalaytarhanli-NAT/osint-research-app`) seç
4. **Apply** — `APP_SECRET_KEY` ve `APP_ENCRYPTION_KEY` Render tarafından otomatik üretilir
5. Build ve deploy ~3–5 dakika; canlı URL Render'dan verilir

**Free tier notu:** SQLite, container içi diske yazılır; restart sonrası kullanıcı
verisi sıfırlanır. Kalıcılık için `render.yaml`'a `disks:` bloku eklenip Plus plan'a
geçilmelidir (10 GB ~$1/ay). Free tier ayrıca 15 dk inaktivite sonrası uyur (~30 sn cold start).

## Çalışma sırasında karşılaşabileceğin durumlar

- **İlk açılışta**: Kayıt ol → Settings → istersen Groq veya HuggingFace ücretsiz
  anahtarını yapıştır → araştır.
- **LLM olmadan**: Kuralsal rapor üretilir; bulgular var ama sentez sığ olur.
- **DDG bazen rate-limit yapar**: Wikipedia/HN/Reddit/GitHub fallback'ları çalıştığı
  için yine yeterli kaynak toplanır.

## Mimari

```
backend/app/
  main.py            # FastAPI app + router'lar
  config.py          # Env, secrets
  database.py        # SQLAlchemy session
  models.py          # User, ResearchJob, ApiKey, SystemApiKey
  auth.py            # JWT + bcrypt
  crypto.py          # Fernet ile API key şifreleme
  pdf_export.py      # Server-side PDF (xhtml2pdf + DejaVu Sans)
  api/
    auth.py          # /api/auth/*
    research.py      # /api/research/* + /export.pdf
    settings.py      # /api/settings/* (provider/admin keys)
    image_search.py  # /api/image/* (upload, reverse, EXIF, face-search)
  osint/
    base.py          # SourceResult, Pipeline
    pipeline.py      # Async orchestrator + diagnostics
    web_search.py    # DDG (TR/wt-wt/lite fallback)
    bing_search.py   # Bing (TR locale + UA pool + URL decoder)
    yandex_search.py # Yandex (.com.tr/.com/.ru fallback)
    mojeek_search.py # Mojeek
    brave_search.py  # Brave Search API
    tavily_search.py # Tavily API
    serper_search.py # Serper.dev (Google) API
    google_cse.py    # Google Programmable Search
    searxng.py       # SearXNG public meta-search
    wikipedia.py wikidata.py wayback.py archive_today.py
    hackernews.py reddit.py github_oss.py arxiv.py gdelt.py
    social_probe.py  # Sherlock-style username probe (20+ platform)
    person_enrich.py # Türkçe→Latin translit + 29 advanced query template
    crtsh.py         # Certificate Transparency (subdomain enum)
    dns_records.py   # DNS-over-HTTPS (A/MX/SPF/DMARC)
    dnstwist_check.py # Typo-squat (B4 saldırı yüzeyi)
    sanctions.py     # OpenSanctions (OFAC/EU/UN/MASAK)
    sec_edgar.py     # SEC EDGAR full-text
    ransomwatch.py   # Ransomware leak victim listesi
    companies_house.py # UK Companies House
    tracking_ids.py  # GA/GA4/GTM/AdSense/FB Pixel cross-domain
    geolocation.py   # Wikidata + 50 şehir + IP geo + EXIF GPS
    exif_extract.py  # Pillow ile EXIF + GPS DMS→decimal
    content_synthesizer.py # LLM-free entity/topic/temporal sentezi
  face_search/        # ◄── YENİ: yüz/görsel dış arama (10 adaptör)
    __init__.py
    orchestrator.py  # Paralel + consensus scoring
    adapters/
      base.py        # FaceSearchAdapter ABC + ExternalMatch
      facecheck.py   # T1 yüz arama, US
      pimeyes.py     # T2 kurumsal, EU
      lenso.py       # T2 EU/GDPR yüz+nesne
      faceseek.py    # T1 meta (FaceCheck+Lenso+PimEyes)
      tineye.py      # T1 reverse image, CA
      bing_visual.py # T1 Microsoft Azure
      google_vision.py # T1 GCP Web Detection
      saucenao.py    # T1 sanat/anime, opsiyonel key
      yandex.py      # T3 RU scraper (KVKK riski — varsayılan kapalı)
      search4faces.py # T3 RU scraper iskelet
  llm/
    providers.py     # 6 LLM + 5 search + 8 face_search adaptör tanımı
    analyzer.py      # JSON rapor sentezi (NATO/IC + LLM/rule-based)
    intelligence_brief.py # 13-bölümlü Markdown brief (LLM veya template)
  templates/         # Jinja2 HTML (executive dashboard hero, harita, ...)
  static/
    css/app.css      # prose-osint, Mermaid stilleri
    js/app.js        # Alpine.js helpers
    fonts/           # DejaVu Sans TTF (PDF Türkçe karakter)
```

## Claude Code skill'leri

`.claude/skills/` altında ek araştırma skill'leri:

- `osint-research` — uçtan uca araştırma
- `web-search` — açık web tarama
- `wayback-check` — arşiv kontrolü
- `social-trace` — kullanıcı adı çoklu platform taraması
- `report-generate` — yapılandırılmış A–I raporu üretimi

## Yüz / Görsel arama (Faz 1)

Image upload akışına 10 dış adaptör entegre edildi (FaceCheck.ID, PimEyes,
Lenso.ai, FaceSeek, TinEye, Bing Visual, Google Vision, SauceNAO, Yandex,
Search4Faces). Settings'ten her adaptör için API key girilebilir; key girilmemiş
adaptörler otomatik devre dışı.

**Endpoints:**
- `GET /api/image/face-search/adapters` — etkin adaptörleri listele
- `POST /api/image/face-search` — paralel arama + consensus skoru

**Frontend:** Image upload kartında "🔍 Yüz Araması" butonu; sonuçlar adaptör
durumu çiplerinden + aggregate eşleşme listesinden oluşan panelde gösterilir.

**KVKK uyarısı:** Bu endpoint görseli ABD/AB sunucularına gönderir. Açık rıza
veya meşru menfaat dayanağı şart. RU adaptörleri (Yandex, Search4Faces)
varsayılan kapalı — hukuki onay sonrası key girerek aktif edilir.

### Faz 2 (planlanan, `osint_face_search/` standalone projede mevcut)

- **InsightFace** yerel embedding + **Qdrant** watchlist eşleştirme (ArcFace 512d)
- **Vaka yönetimi** (Case + Identity + AuditLog modelleri, `legal_basis` zorunlu)
- **KVKK audit log** + **embedding_retention_days** + **audit_log_retention_days**
- **Alembic** migration zinciri (Postgres + Qdrant)

Standalone proje ayrı Render service olarak deploy edilebilir; ana app HTTP
ile çağırır. Detaylar: `osint_face_search/README.md`.

## docs/changelog/

- `auto-log.md` — her assistant turu sonrası Stop hook otomatik kayıt
  (timestamp + son commit + working tree durumu)
