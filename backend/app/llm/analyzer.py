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


SYSTEM_PROMPT = """Sen bir OSINT analistisin. Sana hedef konu hakkında açık kaynaklardan derlenmiş ham veri verilecek. Aşağıdaki kesin JSON şemasında Türkçe rapor üreteceksin. Şu kurallara uyacaksın:

- Yalnızca verilen kaynaklara dayan; uydurma yapma
- Doğrulanmış / iddia / söylenti / yorum ayrımına dikkat et
- Her bulguya kaynak indeksi (sources listesindeki sıra numarası) ver
- Belirsizse "uncertain": true belirt
- Çıktı YALNIZCA geçerli JSON, ek açıklama YAZMA

JSON şeması:
{
  "executive_summary": {
    "overview": "konu kısa özeti (max 4 cümle)",
    "top_findings": ["bulgu 1", "bulgu 2", "bulgu 3", "bulgu 4", "bulgu 5"],
    "confidence": 0.0-1.0,
    "risk_level": "low|medium|high"
  },
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
  "open_questions": ["açıkta kalan soru 1", "..."],
  "next_steps": ["öneri 1", "öneri 2"],
  "conclusion": "net sonuç — 2-4 cümle"
}"""


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
            data["used_llm"] = f"{provider_id}:{model or ''}"
            return data
        except Exception as exc:
            log.warning("LLM report failed (%s), falling back to rule-based: %s", provider_id, exc)

    report = _rule_based_report(target, kind, sources)
    report["used_llm"] = "rule-based"
    return report


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
    risk_level = _risk_level(min(risk_score, 1.0))

    top_findings: list[str] = []
    for key in ["wiki", "news", "web", "profile", "code", "archive"]:
        idxs = groups.get(key, [])
        if not idxs:
            continue
        s = sources[idxs[0]]
        top_findings.append(f"[{idxs[0]}] {key}: {s.get('title') or s.get('url')}")
        if len(top_findings) >= 5:
            break
    while len(top_findings) < 5 and len(top_findings) < n:
        i = len(top_findings)
        top_findings.append(f"[{i}] {sources[i].get('title') or sources[i].get('url')}")

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
