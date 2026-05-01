---
name: osint-research
description: Bir kişi, kurum, marka, kullanıcı adı, URL veya anahtar kelime hakkında uçtan uca açık kaynak istihbarat (OSINT) araştırması yap; A–I formatlı yapılandırılmış rapor üret. Web/haber/Wikipedia/Wayback/sosyal profil/GitHub/Reddit/HN paralel taranır. Sızıntı verisi veya yetkisiz sistem erişimi YOKTUR.
---

# osint-research

Kullanıcı bir hedef verdiğinde (`@kullanici_adi`, kurum adı, kişi adı, URL veya anahtar kelime) bu skill'i çalıştır.

## Etik kapsam (zorunlu)

- Yalnızca **açık (public) kaynaklar**
- Sızdırılmış veri / kapalı sistem / şifreli kanal erişimi **yok**
- ToS ihlali olabilecek scraping yok (kamuya açık API/HTML uçlarıyla sınırlı)
- Çıktıyı her zaman *iddia / söylenti / doğrulanmış / yorum* olarak ayrı sınıflandır

## Akış

1. **Hedef türünü tespit et**: kişi, kurum, sosyal kullanıcı adı, URL/domain, anahtar kelime/cümle.
2. **Paralel kaynak taraması** (her biri ayrı `WebSearch` veya `WebFetch` çağrısı, mümkünse paralel):
   - Açık web → `WebSearch query: "{target}"`
   - Haberler → `WebSearch query: "{target} site:reuters.com OR site:bbc.com OR site:apnews.com OR site:bloomberg.com"`
   - Wikipedia → `WebFetch https://en.wikipedia.org/wiki/Special:Search?search={target}` ve `https://tr.wikipedia.org/...`
   - Wayback → eğer hedef URL/domain ise `WebFetch https://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=10`
   - Reddit → `WebFetch https://www.reddit.com/search.json?q={target}`
   - HackerNews → `WebFetch https://hn.algolia.com/api/v1/search?query={target}`
   - GitHub → `WebFetch https://api.github.com/search/users?q={target}` ve `.../repositories?q={target}`
   - Eğer hedef kullanıcı adı görünüyorsa **`social-trace` skill'ini çağır**.
3. **Görsel ters arama önerileri** (sadece link, manuel):
   - `https://lens.google.com/uploadbyurl?url={img}`
   - `https://yandex.com/images/search?rpt=imageview&url={img}`
   - `https://www.tineye.com/search?url={img}`
4. **Çıktıyı `report-generate` skill'i ile A–I formatına dök.**

## Çıktı formatı (A–I)

A) Yönetici Özeti (özet, top 5 bulgu, güven 0–1, risk: düşük/orta/yüksek)
B) Kim / Ne (tanım, bağlam, bilinen bağlantılar, eş isim riski)
C) Dijital İz (web/haber/sosyal/medya/arşiv özetleri)
D) Zaman Çizelgesi (tarih sırasında olaylar, kaynak indeksi)
E) İlişki ve Bağlantı (kişi-kurum-kurum, kuvvet: strong/weak/unverified)
F) İçerik Analizi (ana iddia, ton, manipülasyon riski, doğrulanabilirlik)
G) Risk Profili (legal/operational/commercial/reputation; her biri low/med/high + açıklama)
H) Kaynak Tablosu (#, kaynak, başlık, link, tarih, güven, doğrulama, not)
I) Sonuç ve Öneriler (net sonuç, açık sorular, sonraki adımlar)

## Kullanım

```
/osint-research target="Atalay Tarhanlı"
/osint-research target="@openai" kind=social
/osint-research target="https://example.com" kind=url
```

## Notlar

- Bulguları çapraz doğrulamak için en az 2 kaynak ara.
- Kesin olmayan bilgileri "uncertain: true" işaretle.
- Eğer aynı isim farklı kişilere ait olabiliyorsa eş isim riskini açıkça belirt.
- Bu skill'in çalıştığı projedeki `backend/app/osint/` modülleri aynı işi web app olarak yapar; uygulama açık ise `POST /api/research` üzerinden de tetiklenebilir.
