# OSINT Research App

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/atalaytarhanli-NAT/osint-research-app)

Açık kaynak istihbarat (OSINT) ve dijital iz analizi için çoklu kullanıcılı web uygulaması.
Bir kişi, kurum, marka, anahtar kelime, sosyal medya hesabı veya link verildiğinde açık web
kaynaklarından derlenmiş yapılandırılmış bir analiz raporu üretir.

> **Test edildi**: Lokal e2e — bir araştırma çalıştırması ortalama 5–8 saniyede 30–50
> kaynak toplar. Anahtarsız modda rule-based rapor, anahtar eklendiğinde tam LLM sentezi.

## Özellikler

- **Çoklu kullanıcı**: kayıt + JWT login, her kullanıcının kendi geçmişi ve API anahtarları
- **API anahtarsız çalışır**: DuckDuckGo, Wikipedia, Wayback Machine, HN, Reddit, GitHub
- **Pluggable LLM**: Settings ekranından Groq / HuggingFace / OpenRouter / Anthropic /
  OpenAI / Google anahtarları girilebilir; yoksa kuralsal sentez kullanılır
- **A–I formatlı rapor**: Yönetici özeti, kim/ne, dijital iz, zaman çizelgesi, ilişki,
  içerik analizi, risk, kaynak tablosu, sonuç
- **Koyu tema dashboard**: Tailwind + Alpine.js, build adımı yok

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
  main.py          # FastAPI app + router'lar
  config.py        # Env, secrets
  database.py      # SQLAlchemy session
  models.py        # User, ResearchJob, ApiKey
  auth.py          # JWT + bcrypt
  crypto.py        # Fernet ile API key şifreleme
  api/
    auth.py        # /api/auth/*
    research.py    # /api/research/*
    settings.py    # /api/settings/*
  osint/
    base.py        # SourceResult, Pipeline
    web_search.py  # DuckDuckGo
    wikipedia.py
    wayback.py
    hackernews.py
    reddit.py
    github_oss.py
    social_probe.py # Sherlock-style username probe
    pipeline.py    # Async orchestrator
  llm/
    providers.py   # Groq/HF/OpenRouter/Anthropic/OpenAI/Google
    analyzer.py    # Rapor sentezi (LLM + rule-based fallback)
  templates/       # Jinja2 HTML
  static/          # Tailwind via CDN, Alpine.js, Chart.js
```

## Claude Code skill'leri

`.claude/skills/` altında ek araştırma skill'leri:

- `osint-research` — uçtan uca araştırma
- `web-search` — açık web tarama
- `wayback-check` — arşiv kontrolü
- `social-trace` — kullanıcı adı çoklu platform taraması
- `report-generate` — yapılandırılmış A–I raporu üretimi
