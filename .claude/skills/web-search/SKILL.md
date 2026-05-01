---
name: web-search
description: Açık web ve haber kaynaklarında bir terimi tarayıp her sonucu (kaynak, başlık, link, tarih, güven skoru) yapılandırılmış halde döndür. OSINT için temel arama bloğu.
---

# web-search

Bir sorgu için açık web sonuçlarını OSINT-formatlı şekilde toparla.

## Akış

1. `WebSearch query: "{q}"` çalıştır → genel web (max 10).
2. `WebSearch query: "{q} site:reuters.com OR site:bbc.com OR site:apnews.com OR site:bloomberg.com OR site:hurriyetdailynews.com OR site:dailysabah.com"` → haber (max 8).
3. Sonuçları aşağıdaki şemada çıkar:

```json
[
  {
    "source": "web|news",
    "url": "…",
    "title": "…",
    "snippet": "…",
    "published_at": "YYYY-MM-DD veya null",
    "confidence": 0.0,
    "kind": "web|news"
  }
]
```

## İpuçları

- Tarihler belirgin değilse `null` bırak. Asla tarih uydurma.
- Aynı URL'yi tekrar verme (dedup).
- Türkçe sorgular için aynı zamanda İngilizce çevirisini de dene.
- Birinci taraf kaynak (resmi site, kurumun kendi domaini) bulunduysa `confidence: 0.8`, gazete `0.7`, blog/forum `0.4–0.5`, sosyal medya `0.3`.

## Kullanım

```
/web-search q="climate policy Turkey 2024"
```
