# OSINT Research App

Açık kaynak istihbarat (OSINT) ve dijital iz analizi için çoklu kullanıcılı web uygulaması.
Bir kişi, kurum, marka, anahtar kelime, sosyal medya hesabı veya link verildiğinde açık web
kaynaklarından derlenmiş yapılandırılmış bir analiz raporu üretir.

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

## Deploy (Render)

Repo `render.yaml` ile blueprint olarak hazırdır. Render Dashboard → New → Blueprint → repoyu seç.

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
