---
name: wayback-check
description: Bir URL veya domain için Wayback Machine arşivinden eski snapshot'ları çek; tarih/orijinal URL/arşiv linki çıkar. Silinmiş veya değiştirilmiş içeriği tespit etmek için.
---

# wayback-check

Hedef bir URL veya domain için Wayback Machine arşivini sorgular.

## Akış

1. Eğer hedef bare domain ise `http://{domain}` olarak normalize et.
2. CDX API çağır:
   ```
   WebFetch url=https://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=20&filter=statuscode:200&from=2000
   ```
3. Dönen array'i parse et — ilk satır başlık, gerisi snapshot satırlarıdır.
4. Her snapshot için:
   - `timestamp` (YYYYMMDDhhmmss) → ISO `YYYY-MM-DD`
   - `original` → kaynak URL
   - Arşiv URL'si: `https://web.archive.org/web/{timestamp}/{original}`
5. Çıktı:

```json
[
  {
    "source": "wayback",
    "url": "https://web.archive.org/web/2018.../...",
    "title": "Archive snapshot — example.com/page",
    "published_at": "2018-04-12",
    "confidence": 0.9,
    "kind": "archive"
  }
]
```

## İpuçları

- En eski + en yeni 5 snapshot'u sun, ortayı dengeli örnekle.
- İçerik değişmiş gibi görünüyorsa (statuscode 200'lü ardışık snapshot'lar arasında title farkı) bunu açıkça not et.
- Hedef URL değilse skill'i çalıştırma; "uygulanamaz" döndür.
