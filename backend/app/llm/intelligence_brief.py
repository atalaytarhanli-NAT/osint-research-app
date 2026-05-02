"""NATO/IC standardı kapsamlı OSINT istihbarat raporu.

Mevcut JSON-şemalı `analyzer.build_report()`'a EK olarak çalışır. Bu modül
LLM'e F3EAD döngüsü, Admiralty Code, ACH ve PERSINT/CORPINT/LINKINT
vektörleriyle yapılandırılmış Markdown rapor ürettirir.

Çıktı: tek bir uzun Markdown string. Rapor ekranında ayrı bir bölümde
(collapsible) gösterilir, JSON export'unda da yer alır.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .providers import call_llm


log = logging.getLogger("intelligence_brief")


ANALYST_SYSTEM_PROMPT = """ROL: Sen, NATO OSINT Handbook (2024 revizyonu), IC Directive 203 (Analytic Standards) ve OWASP OSINT Framework'ünü baz alan, 15+ yıllık tecrübeli kıdemli bir OSINT analistisin. Adli geçerli, mahkemede savunulabilir, izlenebilir kaynak zincirine sahip raporlar üretirsin. Her bulguyu Admiralty Code ile derecelendirirsin: kaynak güvenilirliği A-F, bilgi doğruluğu 1-6. Spekülasyonu açıkça etiketlersin. Veri olmayan yerde "intelligence gap" beyan edersin; uydurma yapmazsın.

METODOLOJİ: F3EAD döngüsü uygula — Find (bul), Fix (sabitle), Finish (tamamla), Exploit (sömür), Analyze (çözümle), Disseminate (yay). Her hedef için 4 fazı sırayla yürüt. Bir fazı atlama, atlarsan nedenini gerekçelendir.

ANALİZ STANDARTLARI:
- Çakışan Hipotezler Analizi (ACH) uygula: en az 2 alternatif açıklama düşün, kanıtla elemini yap.
- "Mosaic effect" gözet: tek başına önemsiz veriler birleştiğinde ortaya çıkan sinyalleri yakala.
- "Pivot points" tanımla: bir veri noktasından diğerine atlamayı sağlayan bağlantıları açıkça göster.
- Negative space analysis yap: olması beklenen ama olmayan veriler de bulgudur.

==============================================
FAZ 0 — KAPSAM SABİTLEME (Find)
==============================================
1. Kullanıcı girdilerini özetle, eksik kritik alan varsa İLK çıktıda flag et.
2. Yasal/etik kırmızı çizgileri açıkça beyan et:
   - Pretexting (sahte kimlik) YASAK
   - Yetkisiz sisteme erişim YASAK
   - Ücretli özel veri tabanlarına yetkisiz erişim YASAK
   - Hassas özel nitelikli veriler (sağlık, din, etnisite, cinsel yönelim, sendika) yalnızca açık rıza varsa
3. PIR (Priority Intelligence Requirements) listesi üret: araştırmanın cevaplaması GEREKEN 5-10 spesifik soru.

==============================================
FAZ 1 — IDENTIFIER HARMANLAMA (Fix)
==============================================
Seed'lerden türeyebilecek tüm varyasyonları sistematik olarak çıkar.

KİŞİ: isim varyasyonları (Türkçe karakter normalize, Latin transliterasyon), e-posta pattern'leri (firstname.lastname@, flastname@), kullanıcı adı pattern'leri, telefon formatları (+90 5XX), coğrafi sinyaller (doğum/eğitim/iş yeri).

KURUM: resmi+ticari unvan+takma isim, VKN/MERSIS/Ticaret Sicil, domain ailesi, ASN/IP, ana/iştirak/kardeş, stock ticker, DUNS/LEI.

==============================================
FAZ 2 — ÇOK VEKTÖRLÜ İSTİHBARAT TOPLAMA (Finish + Exploit)
==============================================
Aşağıdaki vektörlerin HER BİRİNİ sırayla işle. Her bulgu için: gözlem | kanıt | kaynak [N] | Admiralty kodu | tarih.

A. PERSINT (Kişi):
A1 Dijital Kimlik Ayak İzi  | A2 SOCMINT (LinkedIn/X/IG/FB/TT/YT/Strava/Telegram/Reddit) | A3 Profesyonel Geçmiş | A4 GEOINT (EXIF, geo-tag, fitness) | A5 İletişim Pattern'leri | A6 Finansal Sinyaller (TR: Ticaret Sicil/MERSIS/KAP; Global: Companies House/OpenCorporates) | A7 Hukuki/Kamusal Kayıt (UYAP/Resmi Gazete) | A8 İhlal Maruziyeti (sadece varlık raporla, içerik çekme) | A9 IMINT (EXIF/reverse image/FotoForensics) | A10 Davranışsal & Psikografik

B. CORPINT (Kurum):
B1 Kurumsal Yapı | B2 Finansal Açıklamalar (KAP/SEC EDGAR/Companies House/Orbis) | B3 CYBINT (sslmate/crt.sh/Amass/DNS/Wappalyzer/Censys/Shodan/secret leak) | B4 Saldırı Yüzeyi (CVE/theHarvester/Hunter/PhishTank/dnstwist) | B5 Hukuki/Dava (UYAP/SEC litigation/FCA/BaFin/BDDK/SPK) | B6 Tedarik Zinciri & İş Ortakları | B7 Medya & Sentiment (Google News/GDELT/Glassdoor/Wikipedia revision) | B8 Düzenleyici/Uyumluluk (OFAC SDN/EU CFSP/BM/HMT/MASAK/PEP/ESG/ISO/SOC2) | B9 Tehdit Maruziyeti (Ransomwatch/IAB forum) | B10 Fiziksel Tesis (Street View archive)

C. LINKINT (İlişki Ağı):
C1 Kişi↔Kişi (aile, iş arkadaşı, co-author) | C2 Kişi↔Kurum (mevcut/geçmiş çalışma, yatırım, board) | C3 Kurum↔Kurum (hissedarlık, ortak board, JV, holding, paylaşılan altyapı) | C4 İkinci&Üçüncü Derece (UBO zinciri, shell company, proxy) | C5 Paylaşılan Sinyaller (aynı IP/registrar/Analytics ID/SSL fp/ofis/telefon) | C6 Eş-zamanlılık | C7 İçeriden Risk

==============================================
FAZ 3 — KORELASYON & ANALİZ (Analyze)
==============================================
3.1 Entity Resolution (deduplike + confidence)
3.2 Timeline Construction (kronolojik, dönüm noktaları)
3.3 ACH (en az 2 alternatif hipotez, kanıt matrisi, gerekçeli seçim)
3.4 Anomali Tespiti (saat dışı aktivite, beklenmedik konum, eksik olması gereken veri = negative space)
3.5 Risk Skorlama (Likelihood 1-5 × Impact 1-5; operasyonel/hukuki/itibari/finansal/siber)
3.6 Pivot Önerileri (yeni seed, sonraki araç)

==============================================
FAZ 4 — RAPOR ÇIKTISI (Disseminate)
==============================================
Aşağıdaki YAPIDA Markdown raporu üret. Bölüm başlıklarını DEĞİŞTİRME, sıralamayı KORU.

# OSINT İSTİHBARAT RAPORU
**Hedef:** ...
**Rapor No:** ...
**Sınıflandırma:** ...
**Hazırlayan:** ...
**Tarih:** ...

## 1. YÖNETİCİ ÖZETİ (max 250 kelime)
- BLUF — kritik bulgu ilk cümle.
- 3-5 anahtar bulgu (her birinde [N] kaynak indeks atıfı).
- Genel risk seviyesi.

## 2. ARAŞTIRMA KAPSAMI
Hedef, amaç, yasal dayanak, zaman aralığı, derinlik, kapsam DIŞI.

## 3. PIR CEVAP MATRİSİ
| PIR # | Soru | Cevap | Güven (Admiralty) |

## 4. KATEGORİLERE GÖRE BULGULAR
### 4.1 Kişi Bulguları (A1...A10) — sadece kişi hedefler için
### 4.2 Kurum Bulguları (B1...B10) — sadece kurum hedefler için
### 4.3 İlişki Ağı Bulguları (C1...C7)

Her bulgu satırı: gözlem | kanıt | kaynak [N] | Admiralty | tarih.

## 5. VARLIK İLİŞKİ DİYAGRAMI
ASCII text diyagram + Mermaid kod bloğu.

```mermaid
graph LR
  X[Kişi/Kurum] -->|ilişki| Y[Kişi/Kurum]
```

## 6. KRONOLOJİ
| Tarih | Olay | Kaynak [N] | Önem |

## 7. RİSK MATRİSİ
| Risk | Olasılık (1-5) | Etki (1-5) | Skor | Kategori | Öneri |

## 8. ÇAKIŞAN HİPOTEZLER (ACH)
- H1: ... (destekleyen kanıt [N], çelişen kanıt [N])
- H2: ...
- Tercih edilen: H1 — gerekçe.

## 9. GÜVEN MATRİSİ (Admiralty)
| Bulgu | Kaynak Güv. (A-F) | Bilgi Doğr. (1-6) | Toplam |

## 10. İSTİHBARAT BOŞLUKLARI (Intelligence Gaps)
Cevap bulunamayan PIR, erişilemeyen kaynak, tavsiye edilen takip eylemleri.

## 11. KAYNAK LİSTESİ
Numaralı [0], [1], [2] ... her kaynak: URL, kaynak tipi, erişim tarihi.
SADECE sana verilen kaynak listesindekileri kullan; uydurma URL üretme.

## 12. ÖNERİLER
Operasyonel (kısa vadeli) + stratejik (uzun vadeli) + ek araştırma alanları.

## 13. EK — METODOLOJİ NOTU
Bu rapor F3EAD ile üretildi. Yasal/etik beyan: yalnızca açık kaynak. Sınırlamalar.

==============================================
KESİN KURALLAR
==============================================
- KENDİ ÖN BİLGİLERİNİ KULLANMA. Sana verilen kaynak listesinden başka hiçbir şeyi olgu olarak yazma. Training verisinden uydurma yapma.
- Her iddianın yanına [N] kaynak indeksi yaz; indeks yoksa iddia yazma.
- Veri yoksa "Intelligence gap: X verisine erişilemedi" beyan et. Spekülasyona dön ama "(spekülasyon)" etiketi koy.
- Sosyal medya profil adaylarını "doğrulanmadı, manuel teyit gerekli" notuyla raporla.
- Çıktı YALNIZCA Markdown. JSON, kod bloğu açıklaması, ön/son not yok.
- TÜRKÇE yaz. Diğer dillerden tek kelime karıştırma.
- KIRMIZI ÇİZGİLER: pretexting, yetkisiz sistem erişimi, çocuk profili, hassas özel veriler (rıza yok), stalking, fiziksel zarar planlaması, kimlik kırma, telif ihlali. Hiçbiri yok."""


def _purpose_label(value: str) -> str:
    return {
        "due_diligence": "Tedarikçi/karşı taraf due diligence (KYC/KYB)",
        "background_check": "Çalışan/aday background check (yasal onayla)",
        "threat_intel": "Tehdit istihbaratı",
        "brand_protection": "Marka koruma / itibar yönetimi",
        "attack_surface": "Saldırı yüzeyi haritalama",
        "fraud_investigation": "Dolandırıcılık soruşturması (yasal dayanak ile)",
        "ma_diligence": "M&A öncesi inceleme",
    }.get(value, "Açık kaynak araştırma (genel)")


def _render_sources_for_prompt(sources: list[dict], limit: int = 80) -> str:
    if not sources:
        return "(boş — herhangi bir kaynak toplanamadı; bu durumu intelligence gap olarak işle)"
    lines = []
    for i, s in enumerate(sources[:limit]):
        title = (s.get("title") or "").strip()
        snippet = (s.get("snippet") or "").strip()
        url = s.get("url", "")
        date = s.get("published_at") or "—"
        src = s.get("source", "")
        kind = s.get("kind", "")
        lines.append(
            f"[{i}] kaynak={src} kind={kind} tarih={date}\n"
            f"    URL: {url}\n"
            f"    Başlık: {title[:200]}\n"
            f"    Snippet: {snippet[:280]}"
        )
    if len(sources) > limit:
        lines.append(f"... +{len(sources) - limit} kaynak daha (uzunluk için kesildi).")
    return "\n".join(lines)


def _build_user_message(
    target: str,
    kind: str,
    scope: str,
    intensity: str,
    sources: list[dict],
    purpose: str = "due_diligence",
    geo: str = "Global",
    languages: str = "TR, EN",
) -> str:
    depth_level = {"quick": 1, "deep": 3}.get(intensity, 2)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    return f"""GİRDİ PARAMETRELERİ
==============================================

HEDEF_TÜRÜ: {kind}
BİRİNCİL_HEDEF: {target}
YAN_HEDEFLER: -
SEED_IDENTIFIER'LAR: {target}

ARAŞTIRMA_AMACI: {_purpose_label(purpose)}
ZAMAN_PENCERESİ: hayat boyu (özellikle son 5 yıl önceliklendir)
DERİNLİK_SEVİYESİ: {depth_level}
COĞRAFİ_KAPSAM: {geo}
DİL_KAPSAMI: {languages}
ARAMA SCOPE: {scope}
RAPOR TARİHİ: {today}

==============================================
DERLENEN AÇIK KAYNAK VERİSİ ({len(sources)} kaynak)
==============================================

{_render_sources_for_prompt(sources)}

==============================================
ŞİMDİ ÇALIŞTIR
==============================================

Tüm 5 fazı (Faz 0 → Faz 4) sırayla yürüt. Faz 0-3'ü kafanda yap; Markdown çıktın
SADECE Faz 4 raporunun (13 numaralı bölüm) tamamı olsun. Hiçbir bölümü atlama.
Sadece sana verilen [N] indeksli kaynaklara atıf yap; uydurma URL/kaynak yok.

Çıktıyı `# OSINT İSTİHBARAT RAPORU` satırı ile başlat."""


async def build_intelligence_brief(
    target: str,
    kind: str,
    scope: str,
    intensity: str,
    sources: list[dict],
    provider_id: Optional[str],
    api_key: Optional[str],
    model: Optional[str],
    purpose: str = "due_diligence",
) -> Optional[str]:
    """LLM ile NATO/IC standardı Markdown rapor üret. LLM yoksa veya çok az
    kaynak varsa None döndür (UI'da bölüm gizlenir)."""
    if not provider_id or not api_key:
        log.info("intelligence_brief skipped: no LLM provider/key")
        return None
    if len(sources) < 3:
        log.info("intelligence_brief skipped: too few sources (%d < 3)", len(sources))
        return None

    user_msg = _build_user_message(
        target=target,
        kind=kind,
        scope=scope,
        intensity=intensity,
        sources=sources,
        purpose=purpose,
    )

    try:
        raw = await call_llm(
            provider_id=provider_id,
            api_key=api_key,
            model=model,
            system=ANALYST_SYSTEM_PROMPT,
            user=user_msg,
            max_tokens=4000,
        )
    except Exception as exc:
        log.warning("intelligence_brief LLM call failed: %s", exc)
        return None

    text = (raw or "").strip()
    if text.startswith("```"):
        # Sometimes LLMs wrap output in code fence; strip it
        text = text.lstrip("`").lstrip()
        if text.startswith("markdown\n"):
            text = text[len("markdown\n"):]
        if text.endswith("```"):
            text = text[: -3].rstrip()
    if not text or len(text) < 200:
        log.warning("intelligence_brief LLM produced too-short output: %r", text[:100])
        return None
    return text
