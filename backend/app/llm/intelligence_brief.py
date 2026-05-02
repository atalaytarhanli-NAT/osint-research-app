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

from ..osint.content_synthesizer import (
    _domain_distribution,
    _extract_locations,
    _extract_roles,
    _extract_years,
    _high_signal_sources,
    _kind_distribution,
    _social_platforms,
    _top_topics,
    synthesize_conclusion,
    synthesize_identity_definition,
    synthesize_overview,
)
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
    """NATO/IC standardı Markdown rapor üret.
    - LLM key varsa: tam analyst-grade brief (prompt-driven, F3EAD + ACH + ...)
    - LLM key yoksa: synthesize_template_brief() ile şablonlu fallback
      (kaynaklardan istatistiksel/yapısal sentez, ham SERP'lere göre çok zengin).
    """
    if len(sources) < 3:
        log.info("intelligence_brief skipped: too few sources (%d < 3)", len(sources))
        return None
    if not provider_id or not api_key:
        log.info("intelligence_brief: no LLM provider/key, using template synthesizer")
        return synthesize_template_brief(target, kind, scope, intensity, sources, purpose)

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
        # LLM çıktısı kötüyse template fallback'i kullan
        return synthesize_template_brief(target, kind, scope, intensity, sources, purpose)
    return text


def _kind_label_tr(kind: str) -> str:
    return {
        "wiki": "Wikipedia/ansiklopedik",
        "news": "haber",
        "web": "genel web araması",
        "code": "açık kaynak kod tabanları",
        "profile": "sosyal medya profili",
        "social": "sosyal medya tartışması",
        "archive": "web arşivi",
        "cybint": "teknik altyapı (DNS/SSL)",
        "sanction": "yaptırım listesi",
        "attack_surface": "saldırı yüzeyi (typo-squat)",
        "financial": "finansal açıklama (SEC EDGAR)",
        "threat_exposure": "siber tehdit (ransomware leak)",
        "corp_registry": "kurumsal kayıt",
        "link_signal": "tracking sinyali",
    }.get(kind, kind)


def synthesize_template_brief(
    target: str, kind: str, scope: str, intensity: str,
    sources: list[dict], purpose: str = "due_diligence",
) -> str:
    """LLM-free şablonlu Markdown brief — kaynaklardan istatistiksel sentez.

    13 bölümlü NATO/IC formatına uyumlu çıktı. LLM kullanmıyor ama düz cümle
    + tablo + Mermaid diyagramı ile çok daha zengin bir rapor üretir."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    n = len(sources)
    overview = synthesize_overview(target, kind, sources)
    identity_def = synthesize_identity_definition(target, kind, sources)
    conclusion = synthesize_conclusion(target, kind, sources)

    kind_dist = _kind_distribution(sources)
    domains = _domain_distribution(sources, k=10)
    roles = _extract_roles(sources)
    locations = _extract_locations(sources)
    min_y, max_y, _ = _extract_years(sources)
    high = _high_signal_sources(sources)
    platforms = _social_platforms(sources)
    topics = _top_topics(sources, target, k=10)

    risk_level = "high" if (high.get("sanction") or high.get("threat_exposure")) else (
        "medium" if (high.get("attack_surface") or len([s for s in sources if s.get("kind") == "profile"]) >= 6)
        else "low"
    )

    # ====== Markdown brief ======
    out: list[str] = []
    out.append(f"# OSINT İSTİHBARAT RAPORU")
    out.append(f"**Hedef:** {target}")
    out.append(f"**Rapor No:** TPL-{today}-{abs(hash(target)) % 10000:04d}")
    out.append(f"**Sınıflandırma:** Kuruma Özel")
    out.append(f"**Hazırlayan:** OSINT Research App (LLM-free template sentezi)")
    out.append(f"**Tarih:** {today}")
    out.append("")

    # ## 1. YÖNETİCİ ÖZETİ
    out.append("## 1. YÖNETİCİ ÖZETİ (BLUF)")
    out.append("")
    out.append(overview)
    out.append("")
    out.append(f"**Genel risk seviyesi:** `{risk_level.upper()}`")
    out.append("")

    # ## 2. KAPSAM
    out.append("## 2. ARAŞTIRMA KAPSAMI")
    out.append(f"- **Hedef:** {target} (tür: {kind})")
    out.append(f"- **Amaç:** {purpose}")
    out.append(f"- **Yasal dayanak:** Yalnızca açık kaynak (OSINT)")
    out.append(f"- **Zaman aralığı:** "
                + (f"{min_y}–{max_y}" if min_y and max_y and min_y != max_y else (str(min_y) if min_y else "tespit edilemedi")))
    out.append(f"- **Derinlik seviyesi:** {intensity} ({scope} scope)")
    out.append(f"- **Kapsam DIŞI:** Kapalı sistem, paywall, sızıntı veri içeriği, ToS ihlali")
    out.append("")

    # ## 3. PIR CEVAP MATRİSİ
    out.append("## 3. PIR CEVAP MATRİSİ")
    out.append("")
    out.append("| PIR # | Soru | Cevap | Güven |")
    out.append("|---|---|---|---|")
    out.append(f"| PIR-1 | '{target}' kim/ne? | {identity_def[:140]} | C3 |")
    if platforms:
        out.append(f"| PIR-2 | Hangi platformlarda? | {len(platforms)} platform: {', '.join(platforms[:8])} | D5 |")
    if locations:
        out.append(f"| PIR-3 | Coğrafi bağlam? | {', '.join(l[0] for l in locations[:3])} | C3 |")
    if roles:
        out.append(f"| PIR-4 | Rol/sıfat? | {', '.join(r[0] for r in roles[:3])} | C3 |")
    if min_y:
        out.append(f"| PIR-5 | Aktif dönem? | {min_y}–{max_y or 'şimdi'} | B3 |")
    out.append("")

    # ## 4. KATEGORİLERE GÖRE BULGULAR
    out.append("## 4. KATEGORİLERE GÖRE BULGULAR")
    out.append("")
    for i, s in enumerate(sources[:30]):
        adm = "B2" if s.get("kind") in ("wiki", "archive", "cybint", "financial", "corp_registry") else \
              "A1" if s.get("kind") == "sanction" else \
              "B3" if s.get("kind") == "news" else \
              "D5" if s.get("kind") == "profile" else "F4"
        title = (s.get("title") or s.get("url") or "?")[:100]
        snippet = (s.get("snippet") or "")[:160]
        domain = s.get("url", "").split("/")[2] if "/" in s.get("url", "") else "?"
        out.append(f"- **[{i}]** *{_kind_label_tr(s.get('kind', 'web'))}* `{adm}` — **{title}** ({domain})")
        if snippet:
            out.append(f"  > {snippet}")
    if len(sources) > 30:
        out.append(f"- *... +{len(sources) - 30} kaynak daha (kısa form için kesildi)*")
    out.append("")

    # ## 5. VARLIK İLİŞKİ DİYAGRAMI (Mermaid)
    out.append("## 5. VARLIK İLİŞKİ DİYAGRAMI")
    out.append("")
    out.append("```mermaid")
    out.append("graph LR")
    safe_target = target.replace('"', "'").replace("[", "(").replace("]", ")")[:30]
    out.append(f'  TARGET["🎯 {safe_target}"]')
    if platforms:
        for p in platforms[:6]:
            out.append(f'  TARGET --> P_{p}["{p}"]')
    for r, _ in roles[:3]:
        rid = r.replace(" ", "_").replace("/", "_")
        out.append(f'  TARGET -.->|rol/sıfat| R_{rid}["{r}"]')
    for l, _ in locations[:3]:
        out.append(f'  TARGET -.->|bağlam| L_{l}["{l}"]')
    if high.get("sanction"):
        out.append(f'  TARGET ===>|⚠ EŞLEŞME| SANC["Yaptırım Listesi"]')
    if high.get("threat_exposure"):
        out.append(f'  TARGET ===>|⚠ KAYIT| RW["Ransomware Leak"]')
    out.append("```")
    out.append("")

    # ## 6. KRONOLOJİ
    timeline_items = [
        (s.get("published_at"), s.get("title", "")[:100], i)
        for i, s in enumerate(sources)
        if s.get("published_at")
    ]
    timeline_items.sort()
    out.append("## 6. KRONOLOJİ")
    out.append("")
    if timeline_items:
        out.append("| Tarih | Olay | Kaynak |")
        out.append("|---|---|---|")
        for date, title, idx in timeline_items[:15]:
            out.append(f"| {date} | {title} | [{idx}] |")
    else:
        out.append("*Tarihli olay tespit edilemedi (kaynaklarda published_at alanı yok).*")
    out.append("")

    # ## 7. RİSK MATRİSİ
    out.append("## 7. RİSK MATRİSİ")
    out.append("")
    out.append("| Risk | Olasılık (1-5) | Etki (1-5) | Skor | Kategori |")
    out.append("|---|---|---|---|---|")
    if high.get("sanction"):
        out.append(f"| Yaptırım/PEP eşleşmesi ({len(high['sanction'])} kayıt) | 5 | 5 | **25** | legal |")
    if high.get("threat_exposure"):
        out.append(f"| Ransomware leak isim eşleşmesi ({len(high['threat_exposure'])} kayıt) | 5 | 5 | **25** | cyber |")
    if high.get("attack_surface"):
        out.append(f"| Typo-squat domain ({len(high['attack_surface'])} canlı) | 4 | 4 | **16** | cyber |")
    profile_cnt = len([s for s in sources if s.get("kind") == "profile"])
    if profile_cnt >= 4:
        out.append(f"| Geniş sosyal medya yüzeyi ({profile_cnt} profil) | 4 | 3 | **12** | operational |")
    if not (high or profile_cnt >= 4):
        out.append(f"| Bilinen yüksek risk yok | 1 | 2 | **2** | operational |")
    out.append("")

    # ## 8. ACH (Çakışan Hipotezler)
    out.append("## 8. ÇAKIŞAN HİPOTEZLER (ACH)")
    out.append("")
    out.append(f"- **H1:** Toplanan {n} kaynak tek bir '{target}' varlığını işaret ediyor. *(destekleyen: kaynakların büyük çoğunluğu)*")
    out.append(f"- **H2:** Eş isim çakışması olabilir, kaynaklar birden fazla farklı varlığı karıştırıyor olabilir. *(zayıf: domain çeşitliliği homojen değilse)*")
    if roles:
        out.append(f"- **Tercih edilen:** H1 — rol/sıfat ({roles[0][0]}) çoğu kaynakta tutarlı.")
    else:
        out.append(f"- **Tercih edilen:** Belirsiz — manuel teyit gerekir.")
    out.append("")

    # ## 9. GÜVEN MATRİSİ (Admiralty)
    out.append("## 9. GÜVEN MATRİSİ (Admiralty Code)")
    out.append("")
    out.append("| Kategori | Sayı | Tipik Kod | Vector |")
    out.append("|---|---|---|---|")
    for k, c in sorted(kind_dist.items(), key=lambda x: -x[1]):
        adm = "A1" if k in ("sanction", "financial", "corp_registry") else \
              "B2" if k in ("wiki", "cybint", "archive") else \
              "B3" if k == "news" else \
              "D5" if k == "profile" else "F4"
        vec = "CORPINT" if k in ("cybint", "sanction", "financial", "corp_registry", "attack_surface", "threat_exposure") else \
              "PERSINT" if k in ("profile", "social", "code") else \
              "LINKINT" if k == "link_signal" else "GENERAL"
        out.append(f"| {_kind_label_tr(k)} | {c} | {adm} | {vec} |")
    out.append("")

    # ## 10. İSTİHBARAT BOŞLUKLARI
    out.append("## 10. İSTİHBARAT BOŞLUKLARI")
    out.append("")
    gaps = []
    if not any(s.get("kind") == "wiki" for s in sources):
        gaps.append("- Ansiklopedik kayıt (Wikipedia/Wikidata) bulunamadı — kimlik teyidi sınırlı")
    if not any(s.get("kind") == "news" for s in sources):
        gaps.append("- Haber kaynağında bahsi yok — kamuoyu izi düşük")
    if min_y and (datetime.now().year - max_y) > 3:
        gaps.append(f"- Son 3 yıl içinde aktivite tespit edilmedi (son kayıt: {max_y}) — güncel durum belirsiz")
    if not gaps:
        gaps.append("- Önemli boşluk tespit edilmedi (mevcut kaynaklar yeterli kapsam sağlıyor)")
    gaps.append("- LLM-free template sentezi: bağlamsal nüans için Settings'ten LLM anahtarı eklenmeli")
    out.extend(gaps)
    out.append("")

    # ## 11. KAYNAK LİSTESİ
    out.append("## 11. KAYNAK LİSTESİ")
    out.append("")
    for i, s in enumerate(sources[:60]):
        title = (s.get("title") or s.get("url") or "?")[:90]
        url = s.get("url", "")
        date = s.get("published_at", "")
        out.append(f"- **[{i}]** [{title}]({url}) — *{s.get('source', '?')}*"
                   + (f" ({date})" if date else ""))
    if len(sources) > 60:
        out.append(f"- *... +{len(sources) - 60} kaynak daha*")
    out.append("")

    # ## 12. ÖNERİLER
    out.append("## 12. ÖNERİLER")
    out.append("")
    out.append("**Operasyonel (kısa vadeli):**")
    if high.get("sanction"):
        out.append("- Yaptırım eşleşmesi nedeniyle hukuki/uyumluluk birimine yönlendir")
    if high.get("threat_exposure"):
        out.append("- Acil incident response başlat, KVKK/GDPR bildirim yükümlülüğünü değerlendir")
    if high.get("attack_surface"):
        out.append("- Typo-squat domainlere takedown talebi, brand monitoring servisi al")
    if profile_cnt >= 6:
        out.append("- Sosyal medya profil ayarlarını sıkılaştır (profile_cnt yüksek = sosyal mühendislik yüzeyi)")
    out.append("- Periyodik tekrar tarama (3 ay) önerilir")
    out.append("")
    out.append("**Stratejik (uzun vadeli):**")
    out.append("- Settings'ten LLM anahtarı ekle (Groq/HuggingFace ücretsiz) — bu rapor LLM ile 10× daha zengin olur")
    out.append("- Google CSE / Tavily / Serper key Settings'e ekle — daha fazla kaynak çeşitliliği")
    if not any(s.get("kind") == "wiki" for s in sources):
        out.append("- Hedefin Wikipedia/Wikidata maddesi yoksa, kurumsal sayfa veya profesyonel CV ile kimlik teyidi yap")
    out.append("")

    # ## 13. METODOLOJİ NOTU
    out.append("## 13. EK — METODOLOJİ NOTU")
    out.append("")
    out.append(f"Bu rapor LLM kullanmadan, **istatistiksel/yapısal sentez** ile üretildi:")
    out.append(f"- {n} kaynak ham SERP/API çıktısından derlendi")
    out.append(f"- Domain frekansı, vektör dağılımı, rol/lokasyon regex eşleşmesi, tarih agregasyonu kullanıldı")
    out.append(f"- En sık temalar: {', '.join(t[0] for t in topics[:5]) if topics else 'çıkarılamadı'}")
    out.append(f"- En çok bahseden {min(5, len(domains))} domain: {', '.join(d[0] for d in domains[:5])}")
    out.append("")
    out.append("**Yasal/etik beyan:** Yalnızca açık kaynak. Pretexting, yetkisiz erişim, "
               "hassas özel veri (rıza yok), stalking pattern'i yoktur.")
    out.append("")
    out.append("---")
    out.append("")
    out.append("## SONUÇ")
    out.append(conclusion)

    return "\n".join(out)
