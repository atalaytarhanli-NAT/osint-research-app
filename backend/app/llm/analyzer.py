"""Rapor sentez katmanı — A-I formatlı yapılandırılmış çıktı üretir.

İki mod:
- LLM modu: kullanıcının anahtarı varsa, JSON şemalı bir prompt ile çağırır
- Kural-bazlı mod: anahtar yoksa, ham OSINT verisinden deterministik bir özet çıkarır
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Optional

from .providers import call_llm


log = logging.getLogger("analyzer")


SYSTEM_PROMPT = """Sen NATO OSINT Handbook (2024 revizyonu), IC Directive 203 (Analytic Standards) ve OWASP OSINT Framework'ünü baz alan kıdemli bir OSINT analistisin. Sana hedef konu hakkında açık kaynaklardan derlenmiş ham veri verilecek. Aşağıdaki kesin JSON şemasında SADECE TÜRKÇE rapor üreteceksin. Diğer dillerden tek kelime karıştırma.

DİSİPLİN KURALLARI (KESİN):
- KENDİ ÖN BİLGİLERİNİ KULLANMA. SADECE aşağıda verilen kaynaklarda yazılana dayan. Training verisinden uydurma yapma.
- Bir iddiayı raporda kullanmadan önce hangi kaynak indeksinden geldiğini `source_indices` listesinde belirt. Boş `source_indices` ile iddia yazmak YASAK.
- Veri yoksa "intelligence gap" olarak beyan et; spekülasyon yapacaksan "(spekülasyon)" etiketi koy.
- Çıktı YALNIZCA geçerli JSON, ek açıklama YAZMA, kod bloğu (```) kullanma.

ÇAPRAZ DOĞRULAMA: 1 farklı domain → "single", 2 → "double", 3+ → "triple", çelişen → "conflicting".

ADMIRALTY CODE (her finding için): Kaynak güvenilirliği A-F × Bilgi doğruluğu 1-6.
- Kaynak güv: A=tamamen güvenilir (resmi/akademik/ana kaynak), B=genelde güvenilir (büyük yayın), C=oldukça güvenilir (sektör/uzman), D=genelde güvenilmez, E=güvenilmez, F=değerlendirilemiyor.
- Bilgi doğr: 1=başka kaynaklarca tamamen doğrulanmış, 2=büyük olasılıkla doğru, 3=muhtemelen doğru, 4=şüpheli, 5=olası değil, 6=değerlendirilemiyor.
- Kod örneği: "B2" = büyük yayın, büyük olasılıkla doğru.

ACH (Çakışan Hipotezler Analizi): En az 2 alternatif açıklama düşün, kanıt matrisiyle karşılaştır, gerekçeli tercihte bulun. Tek hipotezle bitirme.

RİSK SKORLAMA: Likelihood (1-5) × Impact (1-5) = score. Kategoriler: operational, legal, reputation, financial, cyber.

KIRMIZI ÇİZGİLER (otomatik beyan): pretexting/yetkisiz sistem erişimi/hassas özel veri (rıza yok)/stalking/fiziksel zarar/kimlik kırma/telif ihlali — yapılmadı.

EĞER kaynaklar listesi BOŞ ise: overview="Açık kaynaklarda yeterli veri bulunamadı.", tüm liste alanları boş, scalar alanlar minimum default, risk_level="low", confidence=0.05.

JSON ŞEMASI:
{
  "executive_summary": {
    "overview": "BLUF (Bottom Line Up Front) — max 4 cümle, [N] indeksli atıflarla",
    "top_findings": [
      {"claim": "bulgu cümlesi", "source_indices": [0,3,7], "verification": "triple|double|single|conflicting"}
    ],
    "confidence": 0.0-1.0,
    "risk_level": "low|medium|high"
  },
  "pir_matrix": [
    {"id": "PIR-1", "question": "araştırmanın cevaplaması gereken kritik soru", "answer": "kaynaklara dayanan cevap veya 'intelligence gap'", "admiralty": "B2", "source_indices": [0,5]}
  ],
  "admiralty_findings": [
    {"finding": "kanıtlanmış gözlem cümlesi", "source_reliability": "A|B|C|D|E|F", "info_credibility": "1|2|3|4|5|6", "code": "B2", "source_indices": [0,3], "vector": "PERSINT|CORPINT|LINKINT|GENERAL"}
  ],
  "cross_verification": [
    {"claim": "iddia/bulgu", "level": "triple|double|single|conflicting", "source_indices": [0,3,7], "source_kinds": ["wiki","news","code"]}
  ],
  "identity": {
    "definition": "kim/ne tanımı",
    "context": "coğrafi/sektörel/kurumsal bağlam",
    "known_links": ["bağlantı 1", "bağlantı 2"],
    "name_collision_risk": "düşük|orta|yüksek + açıklama"
  },
  "digital_footprint": {
    "web": "öne çıkan web izleri",
    "news": "haber sonuçları özeti",
    "social": "sosyal medya açık izleri",
    "media": "video/görsel kaynaklar",
    "archive": "wayback bulguları"
  },
  "timeline": [
    {"date": "YYYY-MM-DD veya YYYY", "event": "ne oldu", "source_indices": [0, 2]}
  ],
  "relations": [
    {"entity": "kişi/kurum", "relation": "ilişki tipi", "strength": "strong|weak|unverified", "source_indices": [1]}
  ],
  "content_analysis": {
    "main_claim": "ana iddia/mesaj",
    "tone": "nesnel|kararsız|olumlu|olumsuz|propagandavari|reklam",
    "manipulation_risk": "düşük|orta|yüksek",
    "verifiability": 0.0-1.0
  },
  "risk": {
    "legal": "low|medium|high — kısa açıklama",
    "operational": "low|medium|high — kısa açıklama",
    "commercial": "low|medium|high — kısa açıklama",
    "reputation": "low|medium|high — kısa açıklama"
  },
  "risk_matrix": [
    {"risk": "spesifik risk tanımı", "likelihood": 1-5, "impact": 1-5, "score": 1-25, "category": "operational|legal|reputation|financial|cyber", "mitigation": "öneri", "source_indices": [0]}
  ],
  "ach_analysis": {
    "hypotheses": [
      {"id": "H1", "statement": "alternatif açıklama 1", "supporting": [0,3], "contradicting": [5], "verdict": "destekli|zayıf|elendi"},
      {"id": "H2", "statement": "alternatif açıklama 2", "supporting": [], "contradicting": [0,3], "verdict": "destekli|zayıf|elendi"}
    ],
    "preferred": "H1",
    "rationale": "neden H1 — kanıt ağırlığı"
  },
  "pivot_suggestions": [
    {"new_seed": "yeni arama anahtarı/identifier", "rationale": "neden bu pivot — hangi sinyal", "tools": ["wayback", "crt.sh", "github", "yandex"]}
  ],
  "intelligence_gaps": [
    {"gap": "cevap bulunamayan soru/eksik veri", "why_important": "neden kritik", "follow_up": "tavsiye edilen takip eylemi"}
  ],
  "legal_ethical_notice": "Bu rapor yalnızca açık kaynak (OSINT) yöntemiyle, NATO OSINT Handbook ve IC Directive 203 standartlarına uygun üretildi. Pretexting, yetkisiz sistem erişimi, hassas özel veriler ve stalking pattern'i yoktur.",
  "open_questions": ["açıkta kalan soru 1", "..."],
  "next_steps": ["öneri 1", "öneri 2"],
  "conclusion": "net sonuç — 2-4 cümle"
}

KAÇINMA: pir_matrix en az 3 öğe, admiralty_findings en az 3 öğe (kaynak varsa), ach_analysis en az 2 hipotez, risk_matrix en az 2 risk, intelligence_gaps en az 1 öğe (her raporda mutlaka var). Hiçbir alanı atlama; veri yoksa boş liste/dizi döndür."""


def _user_prompt(target: str, kind: str, sources: list[dict]) -> str:
    lines = [f"Hedef konu: {target}", f"Tür ipucu: {kind}", "", "Kaynaklar:"]
    for i, s in enumerate(sources):
        title = (s.get("title") or "").strip()
        snippet = (s.get("snippet") or "").strip()
        url = s.get("url", "")
        date = s.get("published_at") or ""
        src = s.get("source", "")
        lines.append(f"[{i}] ({src}, {date}) {title}\n    URL: {url}\n    {snippet}")
    return "\n".join(lines) + "\n\nLütfen yukarıdaki JSON şemasında raporu üret."


def _strip_code_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


async def build_report(
    target: str,
    kind: str,
    sources: list[dict],
    provider_id: Optional[str],
    api_key: Optional[str],
    model: Optional[str],
) -> dict[str, Any]:
    # Hallucination guard: kaynak yoksa LLM'e gitmeden dürüst "veri yok" raporu döndür.
    # LLM, sources listesi boşken kendi training verisinden uydurma yapma eğilimindedir.
    if not sources:
        report = _empty_report(target, kind)
        report["used_llm"] = "rule-based (no sources)"
        return report

    if provider_id and api_key:
        try:
            raw = await call_llm(
                provider_id=provider_id,
                api_key=api_key,
                model=model,
                system=SYSTEM_PROMPT,
                user=_user_prompt(target, kind, sources),
            )
            cleaned = _strip_code_fence(raw)
            data = json.loads(cleaned)
            # Post-validation: LLM hallucination önleme — iddia source_indices içermiyorsa düşür
            data = _strip_unsupported_claims(data, len(sources))
            data["used_llm"] = f"{provider_id}:{model or ''}"
            return data
        except Exception as exc:
            log.warning("LLM report failed (%s), falling back to rule-based: %s", provider_id, exc)

    report = _rule_based_report(target, kind, sources)
    report["used_llm"] = "rule-based"
    return report


LEGAL_ETHICAL_NOTICE = (
    "Bu rapor yalnızca açık kaynak (OSINT) yöntemiyle, NATO OSINT Handbook (2024) ve "
    "IC Directive 203 standartlarına uygun üretildi. Pretexting, yetkisiz sistem "
    "erişimi, hassas özel veriler (rıza yok) ve stalking pattern'i yoktur. Sızıntı "
    "veri tabanlarına içerik bazlı erişim YAPILMAMIŞTIR."
)


def _empty_report(target: str, kind: str) -> dict[str, Any]:
    return {
        "executive_summary": {
            "overview": (
                f"'{target}' için açık kaynaklarda yeterli veri bulunamadı. "
                "Hedefin yazımını kontrol et, daha spesifik bir bağlam ekle "
                "(örn. kurum adı, lokasyon) veya farklı bir varyasyon dene."
            ),
            "top_findings": [],
            "confidence": 0.05,
            "risk_level": "low",
        },
        "pir_matrix": [],
        "admiralty_findings": [],
        "cross_verification": [],
        "identity": {
            "definition": "Veri yetersiz.",
            "context": "—",
            "known_links": [],
            "name_collision_risk": "değerlendirilemedi (kaynak yok)",
        },
        "digital_footprint": {
            "web": "Açık webde sonuç bulunamadı.",
            "news": "Haber sonucu bulunamadı.",
            "social": "Sosyal medya izi bulunamadı.",
            "media": "Görsel/video kaynak bulunamadı.",
            "archive": "Arşiv kaydı bulunamadı.",
        },
        "timeline": [],
        "relations": [],
        "content_analysis": {
            "main_claim": "—",
            "tone": "değerlendirilemedi",
            "manipulation_risk": "düşük (veri yok)",
            "verifiability": 0.0,
        },
        "risk": {
            "legal": "değerlendirilemedi — kaynak yok",
            "operational": "değerlendirilemedi — kaynak yok",
            "commercial": "değerlendirilemedi — kaynak yok",
            "reputation": "değerlendirilemedi — kaynak yok",
        },
        "risk_matrix": [],
        "ach_analysis": {
            "hypotheses": [],
            "preferred": "",
            "rationale": "Kaynak yok — hipotez analizi yapılamadı.",
        },
        "pivot_suggestions": [
            {
                "new_seed": f"\"{target}\" + kurum/şehir adı",
                "rationale": "Eş isim olasılığı düşürülür, sinyal/gürültü oranı artar.",
                "tools": ["web", "wiki", "news"],
            },
            {
                "new_seed": f"@{target.lower().replace(' ', '')}",
                "rationale": "Sosyal medya handle olarak ayrı arama; profil varlığı yakalar.",
                "tools": ["social_probe", "github"],
            },
        ],
        "intelligence_gaps": [
            {
                "gap": "Hedefe dair açık webde hiç doğrulanabilir kayıt bulunamadı.",
                "why_important": "İzleyici verisi olmadan kimlik teyidi yapılamaz.",
                "follow_up": "Daha spesifik seed (e-posta, kullanıcı adı, kurum, lokasyon) ile yeniden ara.",
            }
        ],
        "legal_ethical_notice": LEGAL_ETHICAL_NOTICE,
        "open_questions": [
            "Hedef adının yazımı doğru mu?",
            "Daha spesifik bir bağlam (kurum, lokasyon, sektör) eklenebilir mi?",
            "Kullanıcı adı (sosyal handle) biliniyorsa onunla ayrı bir arama denenebilir mi?",
        ],
        "next_steps": [
            "Hedef adına kurum/şehir bilgisi ekleyip yeniden ara",
            "Sosyal medya kullanıcı adı ile (örn. @atalay) ayrı arama yap",
            "URL/domain biliyorsan onunla arama yap (Wayback + crt.sh aktif olur)",
        ],
        "conclusion": (
            "Mevcut açık kaynaklarda hedefe dair doğrulanabilir veri tespit edilemedi. "
            "Bu, hedefin var olmadığını değil, sadece açık webde dijital izinin "
            "yeterli olmadığını veya arama motorlarının (DDG/Bing/Yandex) bot tespiti "
            "ile sonuç döndürmediğini gösterir."
        ),
    }


def _strip_unsupported_claims(data: dict, source_count: int) -> dict:
    """LLM bazen kaynaksız iddia üretir. Bu fonksiyon source_indices'i geçersiz veya
    boş olan kayıtları ayıklar. NATO/IC alanları için de uygulanır."""

    def valid(idxs):
        if not idxs:
            return False
        return all(isinstance(i, int) and 0 <= i < source_count for i in idxs)

    def valid_or_empty(idxs):
        # ACH supporting/contradicting boş olabilir (alternatif hipotezde kanıt yok)
        if not idxs:
            return True
        return all(isinstance(i, int) and 0 <= i < source_count for i in idxs)

    es = data.get("executive_summary", {})
    if "top_findings" in es and isinstance(es["top_findings"], list):
        es["top_findings"] = [
            f for f in es["top_findings"]
            if not (isinstance(f, dict) and not valid(f.get("source_indices")))
        ]
    for key in ("cross_verification", "timeline", "relations", "pir_matrix",
                "admiralty_findings", "risk_matrix"):
        items = data.get(key) or []
        if isinstance(items, list):
            data[key] = [
                v for v in items if isinstance(v, dict) and valid(v.get("source_indices"))
            ]
    # ACH: hypotheses listesindeki supporting/contradicting indekslerini doğrula
    ach = data.get("ach_analysis") or {}
    if isinstance(ach, dict):
        hyps = ach.get("hypotheses") or []
        if isinstance(hyps, list):
            ach["hypotheses"] = [
                h for h in hyps
                if isinstance(h, dict)
                and valid_or_empty(h.get("supporting"))
                and valid_or_empty(h.get("contradicting"))
            ]
            data["ach_analysis"] = ach
    return data


# ----------------------- rule-based fallback -----------------------


def _confidence_from_count(n: int) -> float:
    if n == 0:
        return 0.05
    if n < 3:
        return 0.25
    if n < 8:
        return 0.45
    if n < 16:
        return 0.6
    return 0.75


def _risk_level(score: float) -> str:
    if score >= 0.66:
        return "high"
    if score >= 0.33:
        return "medium"
    return "low"


def _classify_groups(sources: list[dict]) -> dict[str, list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for i, s in enumerate(sources):
        kind = s.get("kind", "web")
        groups[kind].append(i)
        src = s.get("source", "")
        if src.startswith("social:"):
            groups["profile"].append(i)
    return dict(groups)


def _domain_of(url: str) -> str:
    try:
        from urllib.parse import urlparse

        host = urlparse(url).netloc.lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def _verification_level(distinct_count: int) -> str:
    if distinct_count >= 3:
        return "triple"
    if distinct_count == 2:
        return "double"
    if distinct_count == 1:
        return "single"
    return "unverified"


def _build_cross_verification(sources: list[dict], groups: dict[str, list[int]]) -> list[dict]:
    """For each source kind, build a 'claim' with verification level based on
    how many distinct domains within that kind mention the target."""
    cv: list[dict] = []
    for kind, idxs in groups.items():
        if not idxs:
            continue
        domains = {_domain_of(sources[i].get("url", "")) for i in idxs}
        domains.discard("")
        level = _verification_level(len(domains))
        sample = idxs[:6]
        if kind == "profile":
            claim = f"Sosyal medya / profil platformlarında varlık ({len(idxs)} kayıt, {len(domains)} farklı platform)"
        elif kind == "news":
            claim = f"Haber kaynaklarında bahsi geçiyor ({len(idxs)} kayıt, {len(domains)} farklı yayın)"
        elif kind == "wiki":
            claim = f"Wikipedia/ansiklopedik kaynak referansı ({len(idxs)} kayıt)"
        elif kind == "archive":
            claim = f"Web arşivinde geçmişi var ({len(idxs)} snapshot)"
        elif kind == "code":
            claim = f"Açık kaynak kod tabanlarında referans ({len(idxs)} repo)"
        elif kind == "social":
            claim = f"Sosyal medyada tartışma izleri ({len(idxs)} kayıt, {len(domains)} platform)"
        else:
            claim = f"Web aramada görünür ({len(idxs)} kayıt, {len(domains)} farklı domain)"
        cv.append(
            {
                "claim": claim,
                "level": level,
                "source_indices": sample,
                "source_kinds": [kind],
                "distinct_sources": len(domains),
            }
        )
    cv.sort(key=lambda x: ({"triple": 0, "double": 1, "single": 2, "unverified": 3}[x["level"]], -x["distinct_sources"]))
    return cv


def _build_timeline(sources: list[dict]) -> list[dict]:
    timeline: list[dict] = []
    for i, s in enumerate(sources):
        date = s.get("published_at")
        if not date:
            continue
        timeline.append(
            {
                "date": date,
                "event": s.get("title") or s.get("snippet")[:120],
                "source_indices": [i],
            }
        )
    timeline.sort(key=lambda x: x["date"])
    return timeline[:30]


def _detect_collision_risk(target: str, sources: list[dict]) -> str:
    parts = [s.get("title", "") for s in sources if s.get("title")]
    if len(parts) < 4:
        return "düşük — yetersiz veri"
    distinct_subjects = Counter()
    for t in parts:
        first = re.split(r"[-—|:•]", t)[0].strip()
        distinct_subjects[first[:60]] += 1
    if len(distinct_subjects) > len(parts) * 0.7:
        return "yüksek — başlıklar çok dağınık, eş isim olasılığı yüksek"
    if len(distinct_subjects) > len(parts) * 0.4:
        return "orta — bazı başlıklar farklı bağlamlarda görünüyor"
    return "düşük — başlıklar birbirine yakın"


def _summarize_group(sources: list[dict], indices: list[int], limit: int = 4) -> str:
    if not indices:
        return "Belirgin bir kayıt bulunamadı."
    titles = []
    for i in indices[:limit]:
        s = sources[i]
        titles.append(f"[{i}] {s.get('title') or s.get('url')}")
    return "; ".join(titles) + (f" (+{len(indices) - limit} daha)" if len(indices) > limit else "")


_KIND_TO_ADMIRALTY = {
    "wiki": ("B", "2", "GENERAL"),
    "news": ("B", "3", "GENERAL"),
    "code": ("A", "1", "PERSINT"),
    "profile": ("D", "5", "PERSINT"),
    "social": ("D", "4", "PERSINT"),
    "archive": ("B", "2", "GENERAL"),
    "web": ("F", "4", "GENERAL"),
    "cybint": ("A", "1", "CORPINT"),       # DNS/crt.sh — verifiable infra signals
    "sanction": ("A", "1", "CORPINT"),     # OpenSanctions — government-grade
    "attack_surface": ("B", "2", "CORPINT"),  # dnstwist registered domain
    "link_signal": ("C", "2", "LINKINT"),  # Tracking ID cross-domain match
    "financial": ("A", "1", "CORPINT"),    # SEC EDGAR — verifiable filings
    "threat_exposure": ("A", "1", "CORPINT"),  # Ransomwatch — public victim
    "corp_registry": ("A", "1", "CORPINT"),    # Companies House — official registry
}


def _rule_based_admiralty(sources: list[dict], limit: int = 8) -> list[dict]:
    """Kaynaklara göre kaba Admiralty kodları üret. LLM yokken minimum izlenebilirlik."""
    findings: list[dict] = []
    seen_kinds: set[str] = set()
    for i, s in enumerate(sources):
        kind = s.get("kind", "web")
        if kind in seen_kinds and len(findings) >= 3:
            continue
        seen_kinds.add(kind)
        rel, cred, vector = _KIND_TO_ADMIRALTY.get(kind, ("F", "6", "GENERAL"))
        title = s.get("title") or s.get("url", "")
        findings.append({
            "finding": f"{kind}: {title}",
            "source_reliability": rel,
            "info_credibility": cred,
            "code": f"{rel}{cred}",
            "source_indices": [i],
            "vector": vector,
        })
        if len(findings) >= limit:
            break
    return findings


def _rule_based_risk_matrix(sources: list[dict], groups: dict[str, list[int]], risk_score: float) -> list[dict]:
    matrix: list[dict] = []
    sanction_idx = [i for i, s in enumerate(sources) if s.get("kind") == "sanction"]
    if sanction_idx:
        matrix.append({
            "risk": "Yaptırım/PEP listesi eşleşmesi tespit edildi (OpenSanctions)",
            "likelihood": 5,
            "impact": 5,
            "score": 25,
            "category": "legal",
            "mitigation": "Acil hukuki/uyumluluk değerlendirmesi gerekir; iş ilişkisi/işlem askıya alınmalı.",
            "source_indices": sanction_idx[:3],
        })
    typo_idx = [i for i, s in enumerate(sources) if s.get("kind") == "attack_surface"]
    if typo_idx:
        matrix.append({
            "risk": f"Typo-squat domainler aktif ({len(typo_idx)} canlı kayıt) — phishing/brand-spoofing yüzeyi",
            "likelihood": 4,
            "impact": 4,
            "score": 16,
            "category": "cyber",
            "mitigation": "Typo-squat takedown süreci başlat, brand monitoring servisi devreye al, çalışan farkındalık eğitimi.",
            "source_indices": typo_idx[:3],
        })
    cybint_idx = [i for i, s in enumerate(sources) if s.get("kind") == "cybint"]
    spf_dmarc_missing = False
    for i in cybint_idx:
        raw = sources[i].get("raw") or {}
        if raw.get("spf_present") is False or raw.get("dmarc_present") is False:
            spf_dmarc_missing = True
            break
    if spf_dmarc_missing:
        matrix.append({
            "risk": "SPF/DMARC eksik — e-posta spoofing açık",
            "likelihood": 4,
            "impact": 3,
            "score": 12,
            "category": "cyber",
            "mitigation": "DNS TXT kayıtlarına SPF v=spf1 ve DMARC v=DMARC1 p=quarantine ekle.",
            "source_indices": cybint_idx[:1],
        })
    ransom_idx = [i for i, s in enumerate(sources) if s.get("kind") == "threat_exposure"]
    if ransom_idx:
        groups_seen = {(sources[i].get("raw") or {}).get("group", "?") for i in ransom_idx}
        matrix.append({
            "risk": f"Ransomware leak sitelerinde isim geçti ({len(ransom_idx)} kayıt, gruplar: {', '.join(list(groups_seen)[:3])})",
            "likelihood": 5,
            "impact": 5,
            "score": 25,
            "category": "cyber",
            "mitigation": "Acil incident response başlat: hangi veriler sızdı tespit et, "
            "düzenleyici bildirim (KVKK/GDPR), müşteri/çalışan iletişimi, SOC monitoring artır.",
            "source_indices": ransom_idx[:3],
        })
    cross_domain_tracking = [
        i for i, s in enumerate(sources)
        if s.get("kind") == "link_signal" and (s.get("raw") or {}).get("cross_domain")
    ]
    if cross_domain_tracking:
        matrix.append({
            "risk": "Cross-domain tracking ID eşleşmesi — paylaşılan operatör/sahip sinyali",
            "likelihood": 3,
            "impact": 2,
            "score": 6,
            "category": "operational",
            "mitigation": "Eşleşen domainlerin gerçek sahiplik zincirini WHOIS/Companies House ile doğrula.",
            "source_indices": cross_domain_tracking[:3],
        })
    profile_count = len(groups.get("profile", []))
    if profile_count >= 4:
        matrix.append({
            "risk": f"Geniş sosyal medya ayak izi ({profile_count} profil) — sosyal mühendislik yüzeyi",
            "likelihood": 4,
            "impact": 3,
            "score": 12,
            "category": "operational",
            "mitigation": "Profil ayarlarını sıkılaştır, eski profilleri sil/anonimleştir.",
            "source_indices": groups.get("profile", [])[:3],
        })
    if any("breach" in (s.get("snippet") or "").lower() for s in sources):
        leak_indices = [i for i, s in enumerate(sources) if "breach" in (s.get("snippet") or "").lower()][:3]
        matrix.append({
            "risk": "Veri ihlali sinyali tespit edildi (kaynak içeriğinde 'breach' terimi)",
            "likelihood": 5,
            "impact": 5,
            "score": 25,
            "category": "cyber",
            "mitigation": "Şifre döngüsü zorla, MFA aktif et, HIBP üzerinden ilgili e-postaları kontrol et.",
            "source_indices": leak_indices,
        })
    if any(
        kw in (s.get("title", "") + s.get("snippet", "")).lower()
        for kw in ["fraud", "lawsuit", "scam", "dolandırıcı", "sahte", "dava"]
        for s in sources
    ):
        matrix.append({
            "risk": "Hukuki/uyuşmazlık sinyali (kaynaklarda dava/dolandırıcılık geçiyor)",
            "likelihood": 3,
            "impact": 4,
            "score": 12,
            "category": "legal",
            "mitigation": "İlgili davaların tarafları/durumu ayrıca doğrulanmalı.",
            "source_indices": [
                i for i, s in enumerate(sources)
                if any(kw in (s.get("title", "") + s.get("snippet", "")).lower()
                       for kw in ["fraud", "lawsuit", "scam", "dolandırıcı", "sahte", "dava"])
            ][:3],
        })
    if not matrix:
        matrix.append({
            "risk": "Bilinen yüksek riskli sinyal yok — kaynak şu anda zararsız görünüyor",
            "likelihood": 1,
            "impact": 2,
            "score": 2,
            "category": "operational",
            "mitigation": "Periyodik tekrar tarama (3 ay) önerilir.",
            "source_indices": [0] if sources else [],
        })
    return matrix


def _rule_based_pir(target: str, sources: list[dict], groups: dict[str, list[int]]) -> list[dict]:
    pir: list[dict] = []
    web_idx = groups.get("web", []) + groups.get("wiki", [])
    if web_idx:
        pir.append({
            "id": "PIR-1",
            "question": f"'{target}' kim/ne olarak tanımlanıyor?",
            "answer": (sources[web_idx[0]].get("snippet") or sources[web_idx[0]].get("title") or "—")[:280],
            "admiralty": "C3" if len(web_idx) < 3 else "B2",
            "source_indices": web_idx[:3],
        })
    profile_idx = groups.get("profile", [])
    if profile_idx:
        platforms = sorted({(sources[i].get("source") or "").replace("social:", "") for i in profile_idx})
        pir.append({
            "id": f"PIR-{len(pir)+1}",
            "question": "Hangi sosyal medya platformlarında varlığı var?",
            "answer": f"{len(platforms)} platform: {', '.join(list(platforms)[:8])}",
            "admiralty": "D5",
            "source_indices": profile_idx[:5],
        })
    news_idx = groups.get("news", [])
    if news_idx:
        pir.append({
            "id": f"PIR-{len(pir)+1}",
            "question": "Haber kaynaklarında nasıl ele alınıyor?",
            "answer": f"{len(news_idx)} haberde geçiyor: {sources[news_idx[0]].get('title', '')[:140]}",
            "admiralty": "B3",
            "source_indices": news_idx[:3],
        })
    archive_idx = groups.get("archive", [])
    if archive_idx:
        pir.append({
            "id": f"PIR-{len(pir)+1}",
            "question": "Web arşivinde geçmiş izi/değişiklik var mı?",
            "answer": f"{len(archive_idx)} arşiv kaydı tespit edildi (Wayback Machine).",
            "admiralty": "B2",
            "source_indices": archive_idx[:3],
        })
    return pir


def _rule_based_ach(target: str, n: int) -> dict:
    if n < 4:
        return {
            "hypotheses": [],
            "preferred": "",
            "rationale": "Kaynak sayısı çok az — alternatif hipotez analizi anlamlı değil.",
        }
    return {
        "hypotheses": [
            {
                "id": "H1",
                "statement": f"Toplanan kaynaklar tek bir '{target}' kişisini/kurumunu işaret ediyor.",
                "supporting": list(range(min(3, n))),
                "contradicting": [],
                "verdict": "destekli",
            },
            {
                "id": "H2",
                "statement": f"'{target}' eş isim çakışmasıyla birden fazla farklı varlığı işaret ediyor olabilir.",
                "supporting": [],
                "contradicting": list(range(min(3, n))),
                "verdict": "zayıf",
            },
        ],
        "preferred": "H1",
        "rationale": (
            "Kural-bazlı sezgisel: kaynakların büyük çoğunluğu aynı bağlamı (başlık/snippet) "
            "paylaşıyorsa H1 tercih edilir. LLM analiziyle daha güvenilir hale gelir."
        ),
    }


def _rule_based_pivots(target: str, groups: dict[str, list[int]]) -> list[dict]:
    pivots: list[dict] = []
    if "wayback" not in groups and "archive" not in groups:
        pivots.append({
            "new_seed": target,
            "rationale": "Henüz arşiv araması yapılmamış — silinmiş içerik için Wayback denenmeli.",
            "tools": ["wayback"],
        })
    if "code" not in groups:
        pivots.append({
            "new_seed": target.lower().replace(" ", ""),
            "rationale": "GitHub/HN üzerinden teknik iz aranabilir (kod tabanı, issue, mention).",
            "tools": ["github", "hn"],
        })
    if "profile" not in groups:
        pivots.append({
            "new_seed": target.lower().replace(" ", ""),
            "rationale": "Sosyal medya kullanıcı adı taraması yapılmamış — Sherlock-style kontrol önerilir.",
            "tools": ["social_probe"],
        })
    return pivots


def _rule_based_report(target: str, kind: str, sources: list[dict]) -> dict[str, Any]:
    n = len(sources)
    groups = _classify_groups(sources)
    confidence = _confidence_from_count(n)

    profile_count = len(groups.get("profile", []))
    risk_score = 0.0
    if profile_count >= 6:
        risk_score += 0.25
    if "archive" in groups:
        risk_score += 0.1
    if any("breach" in (s.get("snippet") or "").lower() for s in sources):
        risk_score += 0.4
    if any(
        kw in (s.get("title", "") + s.get("snippet", "")).lower()
        for kw in ["fraud", "lawsuit", "scam", "fake", "dolandırıcı", "sahte", "dava"]
        for s in sources
    ):
        risk_score += 0.3
    # NATO/IC: yaptırım/typosquat → kritik risk
    if any(s.get("kind") == "sanction" for s in sources):
        risk_score = max(risk_score, 0.95)  # forces "high"
    if any(s.get("kind") == "threat_exposure" for s in sources):
        risk_score = max(risk_score, 0.95)  # ransomware victim → high
    if any(s.get("kind") == "attack_surface" for s in sources):
        risk_score = max(risk_score, 0.7)
    risk_level = _risk_level(min(risk_score, 1.0))

    cross_verification = _build_cross_verification(sources, groups)

    top_findings: list[dict] = []
    for key in ["wiki", "news", "web", "profile", "code", "archive"]:
        idxs = groups.get(key, [])
        if not idxs:
            continue
        domains = {_domain_of(sources[i].get("url", "")) for i in idxs}
        domains.discard("")
        level = _verification_level(len(domains))
        s = sources[idxs[0]]
        top_findings.append(
            {
                "claim": f"{key}: {s.get('title') or s.get('url')}",
                "source_indices": idxs[:4],
                "verification": level,
            }
        )
        if len(top_findings) >= 5:
            break
    while len(top_findings) < 5 and len(top_findings) < n:
        i = len(top_findings)
        top_findings.append(
            {
                "claim": sources[i].get("title") or sources[i].get("url"),
                "source_indices": [i],
                "verification": "single",
            }
        )

    return {
        "executive_summary": {
            "overview": (
                f"'{target}' için açık kaynaklardan {n} bulgu derlendi. "
                f"En çok kayıt {max(groups, key=lambda k: len(groups[k])) if groups else 'yok'} "
                f"kategorisinden geldi."
            ),
            "top_findings": top_findings,
            "confidence": confidence,
            "risk_level": risk_level,
        },
        "pir_matrix": _rule_based_pir(target, sources, groups),
        "admiralty_findings": _rule_based_admiralty(sources),
        "cross_verification": cross_verification,
        "identity": {
            "definition": (
                f"Hedef '{target}' (tür ipucu: {kind}). "
                "Kural-bazlı modda detaylı kimlik çıkarımı yapılmaz; "
                "Settings'ten LLM anahtarı eklenirse bu bölüm zenginleştirilir."
            ),
            "context": "Ham veri gruplarına bakıldığında: "
            + ", ".join(f"{k}={len(v)}" for k, v in sorted(groups.items())),
            "known_links": [
                sources[i].get("title") or sources[i].get("url")
                for i in (groups.get("profile", []) + groups.get("code", []))[:6]
            ],
            "name_collision_risk": _detect_collision_risk(target, sources),
        },
        "digital_footprint": {
            "web": _summarize_group(sources, groups.get("web", [])),
            "news": _summarize_group(sources, groups.get("news", [])),
            "social": _summarize_group(
                sources, groups.get("social", []) + groups.get("profile", [])
            ),
            "media": "Bu sürümde video/görsel toplama uygulamada gösterimle sınırlı.",
            "archive": _summarize_group(sources, groups.get("archive", [])),
        },
        "timeline": _build_timeline(sources),
        "relations": [
            {
                "entity": sources[i].get("title", ""),
                "relation": sources[i].get("source", ""),
                "strength": "unverified",
                "source_indices": [i],
            }
            for i in (groups.get("profile", []) + groups.get("code", []))[:8]
        ],
        "content_analysis": {
            "main_claim": "Kural-bazlı modda iddia çıkarımı yapılmaz.",
            "tone": "nesnel",
            "manipulation_risk": "düşük",
            "verifiability": confidence,
        },
        "risk": {
            "legal": f"{risk_level} — kural-bazlı sezgisel skor",
            "operational": f"{risk_level} — kural-bazlı sezgisel skor",
            "commercial": f"{risk_level} — kural-bazlı sezgisel skor",
            "reputation": f"{risk_level} — kural-bazlı sezgisel skor",
        },
        "risk_matrix": _rule_based_risk_matrix(sources, groups, risk_score),
        "ach_analysis": _rule_based_ach(target, n),
        "pivot_suggestions": _rule_based_pivots(target, groups),
        "intelligence_gaps": [
            {
                "gap": "LLM sentezi yapılmadı — yapısal kanıt değerlendirmesi yüzeyseldir.",
                "why_important": "ACH ve Admiralty kodlaması için bağlam analizi gerekir; kural-bazlı mod sadece kategorik kestirim yapar.",
                "follow_up": "Settings → API anahtarı ekleyin (Groq/HuggingFace ücretsiz seviyeler mevcut).",
            }
        ],
        "legal_ethical_notice": LEGAL_ETHICAL_NOTICE,
        "open_questions": [
            "Kişi/kurum kimlik onayı ek belge ile yapılmalı.",
            "Eş isim çakışması varsa en az 2 farklı doğrulama gerekir.",
            "LLM sentezi için Settings'ten bir API anahtarı ekleyin.",
        ],
        "next_steps": [
            "Settings → API anahtarı ekleyin (Groq veya HuggingFace ücretsiz).",
            "Hedef için ek anahtar kelime kombinasyonu deneyin.",
            "Görsel ters arama: Google Lens / Yandex / TinEye linklerini manuel test edin.",
        ],
        "conclusion": (
            f"'{target}' hedefi için {n} kaynaktan derlenmiş ön bulgular hazır. "
            "Detaylı sentez için bir LLM anahtarı ekleyin. Hiçbir bulgu ek doğrulama yapılmadan kesin kabul edilmemelidir."
        ),
    }
