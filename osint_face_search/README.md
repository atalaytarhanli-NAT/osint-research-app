# OSINT Face Search

Kurumsal yüz tanıma + watchlist eşleştirme + dış servis arama servisi.
KVKK uyumlu audit log ve vaka yönetimi içerir.

## Mimari

```
                    ┌─────────────────────┐
                    │      FastAPI        │
                    └──────────┬──────────┘
                               │
            ┌──────────────────┼─────────────────────┐
            ▼                  ▼                     ▼
   ┌────────────────┐  ┌────────────────┐   ┌────────────────────┐
   │  InsightFace   │  │     Qdrant     │   │  10 Dış Adaptör    │
   │ (ArcFace 512d) │  │  (cosine sim)  │   │ (paralel, async)   │
   └────────────────┘  └────────────────┘   └────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │    PostgreSQL       │
                    │ vakalar, audit log, │
                    │ ext. search history │
                    └─────────────────────┘
```

## Adaptör Matrisi

| Adaptör | Tier | Kategori | Veri Lokasyonu | API Key | Not |
|---|---|---|---|---|---|
| **FaceCheck.ID** | T1 | Yüz arama | US | gerekli | En iyi belgelenmiş yüz API'si |
| **TinEye** | T1 | Reverse image | CA | gerekli | Görsel kaynak takibi (yüz değil) |
| **Bing Visual** | T1 | Reverse image | US | gerekli | Microsoft Azure, web kullanımları |
| **Google Vision** | T1 | Reverse image | US | gerekli | Web Detection + face detection |
| **SauceNAO** | T1 | Reverse image | US | opsiyonel | Sanat/anime için en iyi |
| **FaceSeek** | T1 | Yüz arama | US | gerekli | FaceCheck+Lenso+PimEyes meta |
| **PimEyes** | T2 | Yüz arama | EU | gerekli | Kurumsal anlaşma şart |
| **Lenso.ai** | T2 | Yüz+nesne | EU | gerekli | AB merkezli, GDPR uyumlu |
| **Yandex Images** | T3 | Reverse image | **RU** | scraper | Hukuki risk yüksek, KVK Kurulu yeterli koruma listesinde değil |
| **Search4Faces** | T3 | Yüz arama | **RU** | scraper | Sadece iskelet — production scraper yok |

**Tier açıklaması:**
- **T1 (Documented API):** Resmi REST API var, sözleşme ile kolayca alınır
- **T2 (Commercial):** Kurumsal satış üzerinden, fiyat müzakereye bağlı
- **T3 (Scraper):** API yok, web kazıma — kırılgan, hukuki risk

## Hızlı başlangıç (Windows)

### 1. Python ortamı

> Python 3.11 veya 3.12 önerilir.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**InsightFace Windows kurulum sorunları:**
```powershell
pip install numpy==1.26.4 cython
pip install insightface==0.7.3 --no-build-isolation
```

İlk çalıştırmada `buffalo_l` (~280 MB) otomatik iner.

### 2. Yapılandırma

```powershell
copy .env.example .env
# .env içinde API_KEY ve istediğiniz adaptör key'lerini doldurun
```

### 3. Servisleri başlat

```powershell
docker compose up -d
alembic upgrade head
uvicorn app.main:app --reload
```

Swagger UI: http://localhost:8000/docs

## Endpoint Haritası

### Çekirdek (dahili)
- `POST /api/v1/cases` — Vaka oluştur
- `GET /api/v1/cases` — Vaka listele
- `POST /api/v1/watchlist` — Kimlik ekle (görsel + meta)
- `POST /api/v1/search` — Dahili Qdrant'ta yüz ara

### Dış servisler (yeni)
- `GET /api/v1/external-search/adapters` — Yapılandırılmış adaptör listesi
- `POST /api/v1/external-search` — Seçili adaptörlerde paralel arama
- `GET /api/v1/external-search/history/{case_id}` — Vakanın dış sorgu geçmişi

### Denetim
- `GET /api/v1/audit` — Audit log sorgula

## Kullanım örnekleri

### Mevcut adaptörleri gör

```bash
curl -X GET http://localhost:8000/api/v1/external-search/adapters \
  -H "X-API-Key: your-api-key"
```

Yanıt:
```json
[
  {"name": "facecheck", "tier": "TIER_1_DOCUMENTED_API", "category": "FACE_SEARCH",
   "data_residency": "US", "enabled": true},
  {"name": "tineye", "tier": "TIER_1_DOCUMENTED_API", "category": "REVERSE_IMAGE",
   "data_residency": "CA", "enabled": true},
  ...
]
```

### Sadece belirli adaptörlerle ara

```bash
curl -X POST http://localhost:8000/api/v1/external-search \
  -H "X-API-Key: your-api-key" \
  -F "image=@suspect.jpg" \
  -F "case_id=<UUID>" \
  -F "adapters=facecheck,tineye"
```

### Tüm etkin adaptörlerde ara

```bash
curl -X POST http://localhost:8000/api/v1/external-search \
  -H "X-API-Key: your-api-key" \
  -F "image=@suspect.jpg" \
  -F "case_id=<UUID>"
```

Yanıt çoklu kaynak konsensüs skorlarıyla gelir:
```json
{
  "successful": ["facecheck", "tineye", "saucenao"],
  "failed": {},
  "total_matches": 24,
  "aggregated": [
    {
      "url": "https://example.com/profile/...",
      "sources": ["facecheck", "tineye"],
      "scores": {"facecheck": 91.5, "tineye": 87.2},
      "consensus_score": 94.3,
      "confidence": "CERTAIN"
    }
  ]
}
```

## KVKK uyum — Dış servis sorguları için kritik

Dış servisler veriyi YURT DIŞINA çıkarır. Sistem otomatik olarak şunları yapar:

1. **Her dış sorgu `external_search_results` tablosuna yazılır**
   — adaptör adı, veri lokasyonu (US/EU/RU), zaman, sorgulayan kullanıcı, eşleşme sayısı
2. **Audit log'a `EXTERNAL_SEARCH_PERFORMED` kaydı düşer**
3. **Vakanın `legal_basis` alanı zorunlu** — yurt dışı aktarımı KVKK md. 9 hangi koşulla karşıladığını belirtir

**Önerilen `legal_basis` formülasyonu:**
> "KVKK md. 5/2-e (meşru menfaat — havalimanı/AVM güvenliği) + md. 9/6 (açık rıza yokluğunda yeterli koruma garantisi sağlayan ülke listesi gözetilerek yapılan aktarım)"

**KVK Kurulu yeterli koruma kararına sahip olmayan ülkelere aktarım** (RU dahil), Kurul'un BAĞLAYICI kurallar veya açık rıza şartını arar. Yandex/Search4Faces adaptörlerini açmadan önce hukuk ekibinizle özel olarak değerlendirin.

## Proje yapısı

```
osint_face_search/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models.py            # Case, Identity, AuditLog, ExternalSearchResult
│   ├── schemas.py
│   ├── face_engine.py       # InsightFace
│   ├── vector_store.py      # Qdrant
│   ├── audit.py
│   ├── auth.py
│   ├── exceptions.py
│   ├── adapters/            # ◄── YENİ
│   │   ├── base.py
│   │   ├── orchestrator.py
│   │   ├── facecheck.py
│   │   ├── pimeyes.py
│   │   ├── lenso.py
│   │   ├── faceseek.py
│   │   ├── tineye.py
│   │   ├── bing_visual.py
│   │   ├── google_vision.py
│   │   ├── saucenao.py
│   │   ├── yandex.py
│   │   └── search4faces.py
│   └── routers/
│       ├── cases.py
│       ├── watchlist.py
│       ├── search.py
│       ├── external_search.py    # ◄── YENİ
│       └── audit.py
├── alembic/
│   └── versions/
│       ├── 001_initial_schema.py
│       └── 002_external_search.py    # ◄── YENİ
├── scripts/init_qdrant.py
├── tests/
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

## Sonraki aşamalar

- **Aşama 3:** SpiderFoot HX entegrasyonu — yüz eşleşmesinden kullanıcı adına, oradan diğer platformlara zincirleme
- **Aşama 4:** React + Vite frontend — vaka ekranı, eşleşme ağ grafiği, audit görüntüleyici
- **Otomasyon:** `embedding_retention_days` ve `audit_log_retention_days` için Celery beat job'ları

## Yandex/Search4Faces (Tier 3) için ek kurulum

Sadece hukuki onay aldıktan sonra:

```powershell
pip install playwright==1.48.0
playwright install chromium
```

Ardından `app/adapters/search4faces.py` dosyasındaki `_enabled = False` satırını
`True` yapıp gerçek scraper mantığını ekleyin. Yandex adaptörü hazır şablon olarak
gelir — Yandex UI selector'ları zaman içinde değişebilir, periyodik bakım gerektirir.
