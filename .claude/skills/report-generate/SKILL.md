---
name: report-generate
description: Toplanmış OSINT kaynak listesinden (web/haber/sosyal/wiki/wayback/profil/kod) A–I formatlı yönetici raporu üretir. Sadece JSON çıktı verir; uydurma yapmaz, kaynak indekslerine atıfta bulunur.
---

# report-generate

Bir kaynak listesi verildiğinde yapılandırılmış istihbarat raporu üretir.

## Girdi formatı

```json
{
  "target": "string",
  "kind": "auto|person|organization|social|url|keyword",
  "sources": [
    {"source":"...","url":"...","title":"...","snippet":"...","published_at":"YYYY-MM-DD?","confidence":0.0,"kind":"web|news|wiki|archive|social|profile|code"}
  ]
}
```

## Çıktı şeması (yalnızca JSON, ek açıklama yok)

```json
{
  "executive_summary": {
    "overview": "konunun 2–4 cümlelik özeti",
    "top_findings": ["...","...","...","...","..."],
    "confidence": 0.0,
    "risk_level": "low|medium|high"
  },
  "identity": {
    "definition": "...",
    "context": "...",
    "known_links": ["..."],
    "name_collision_risk": "düşük|orta|yüksek + açıklama"
  },
  "digital_footprint": {
    "web": "...","news":"...","social":"...","media":"...","archive":"..."
  },
  "timeline": [
    {"date":"YYYY-MM-DD","event":"...","source_indices":[0,3]}
  ],
  "relations": [
    {"entity":"...","relation":"...","strength":"strong|weak|unverified","source_indices":[1]}
  ],
  "content_analysis": {
    "main_claim":"...","tone":"nesnel|olumlu|olumsuz|propagandavari|reklam",
    "manipulation_risk":"düşük|orta|yüksek","verifiability":0.0
  },
  "risk": {
    "legal":"low|medium|high — açıklama",
    "operational":"low|medium|high — açıklama",
    "commercial":"low|medium|high — açıklama",
    "reputation":"low|medium|high — açıklama"
  },
  "open_questions":["..."],
  "next_steps":["..."],
  "conclusion":"net sonuç, 2–4 cümle"
}
```

## Kurallar

- **YALNIZCA** verilen kaynaklara dayan; yokluğu varlığa dönüştürme.
- Her bulguda mümkünse `source_indices` ile kaynak listesindeki sıraya atıfta bulun.
- Çapraz doğrulama: 2+ bağımsız kaynak yoksa `confidence` < 0.5 ver.
- Tarih bilinmiyorsa `null`, asla tahmin etme.
- Eş isim çakışması ihtimali yüksekse `name_collision_risk` alanında AÇIK olarak belirt.
- Risk skorlamasında: dolandırıcılık/dava/sahte/breach gibi anahtar kelimeler `high` tetikler.

## Çıktı disiplini

- Çıktı **yalnızca geçerli JSON**.
- Markdown, açıklama, kod blok işareti **YOK**.
- Eğer model yanıtı kod bloğuyla saracaksa, çağıran taraf ```json…``` fence'ini soyacaktır;
  yine de yalın JSON tercih edilir.
