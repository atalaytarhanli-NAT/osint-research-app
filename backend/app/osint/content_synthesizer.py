"""LLM-free içerik sentezi — ham SERP sonuçlarını anlamlı paragrafa çevirir.

Mevcut rule-based mod sadece "N kaynak bulundu" gibi yüzeysel cümleler
döndürüyordu. Bu modül kaynaklardan istatistiksel + yapısal analiz ile akıcı
bir hikaye üretir:

- Domain frequency analysis: hangi siteler hedefi en çok konu ediyor
- Vector dağılımı: PERSINT/CORPINT/LINKINT kategorize sentence
- Entity & rol pattern (CEO, founder, professor, ...)
- Lokasyon çıkarımı (şehir/ülke regex eşleşmesi)
- Tarih dağılımı (aktif dönem, ilk/son iz)
- Topic cluster (TextRank-lite: tekrar eden anahtar kelimeler)
- Risk sinyali (sanction/threat/breach kaynaklarını öne çıkar)

Hiç dış kütüphane yok — collections/re/datetime/urllib stdlib'i ile.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import urlparse


log = logging.getLogger("osint.synthesizer")


# Pattern bankası — Türkçe + İngilizce
_ROLE_PATTERNS = [
    (r"\b(CEO|Chief Executive)\b", "CEO"),
    (r"\b(CTO|Chief Technology)\b", "CTO"),
    (r"\b(CFO|Chief Financial)\b", "CFO"),
    (r"\b(COO|Chief Operating)\b", "COO"),
    (r"\b(founder|kurucu|co-founder|kurucu ortak)\b", "kurucu"),
    (r"\b(president|başkan|chairman|yönetim kurulu başkanı)\b", "başkan"),
    (r"\b(professor|prof\.|dr\.|profesör|doçent)\b", "akademisyen"),
    (r"\b(engineer|mühendis|developer|geliştirici|software)\b", "mühendis/geliştirici"),
    (r"\b(researcher|araştırmacı|scientist|bilim insanı)\b", "araştırmacı"),
    (r"\b(director|müdür|manager|yönetici|head of)\b", "yönetici"),
    (r"\b(consultant|danışman|advisor)\b", "danışman"),
    (r"\b(journalist|gazeteci|reporter|muhabir|editör|editor)\b", "gazeteci"),
    (r"\b(lawyer|avukat|attorney|hukukçu)\b", "hukukçu"),
    (r"\b(doctor|doktor|physician|hekim|cerrah)\b", "hekim"),
    (r"\b(artist|sanatçı|musician|müzisyen|writer|yazar)\b", "sanatçı/yazar"),
    (r"\b(politician|siyasetçi|deputy|milletvekili|minister|bakan)\b", "siyasetçi"),
    (r"\b(athlete|sporcu|player|oyuncu|coach|antrenör)\b", "sporcu"),
    (r"\b(student|öğrenci|graduate|mezun)\b", "öğrenci"),
]

_LOCATION_TR = re.compile(
    r"\b(İstanbul|Ankara|İzmir|Bursa|Antalya|Konya|Adana|Gaziantep|Trabzon|Kayseri|"
    r"Eskişehir|Diyarbakır|Mersin|Samsun|Şanlıurfa|Malatya|Denizli|Erzurum|Van|Sakarya|"
    r"Manisa|Aydın|Hatay|Balıkesir|Kahramanmaraş|Tekirdağ|Çanakkale|Ordu|Edirne|"
    r"Türkiye|Turkey|Turkish)\b",
    re.I,
)
_LOCATION_GLOBAL = re.compile(
    r"\b(London|New York|San Francisco|Los Angeles|Washington|Boston|Chicago|"
    r"Paris|Berlin|Munich|Amsterdam|Brussels|Madrid|Barcelona|Rome|Milan|Vienna|"
    r"Zurich|Stockholm|Moscow|Tokyo|Seoul|Beijing|Shanghai|Singapore|Hong Kong|"
    r"Dubai|Tel Aviv|Doha|Riyadh|Cairo|Sydney|Toronto)\b",
    re.I,
)
_DATE_RE = re.compile(r"\b(19|20)\d{2}\b")
_YEAR_RANGE_RE = re.compile(r"\b(19|20)\d{2}\s*[-–]\s*(19|20)\d{2}\b")

_STOPWORDS = {
    "the","a","an","of","and","or","to","in","on","is","are","was","were","be","by","for","with",
    "as","at","that","this","it","from","but","not","you","we","they","he","she","his","her","our",
    "their","its","have","has","had","will","would","can","could","should","than","into","about",
    "ile","ve","de","da","bir","bu","şu","o","mı","mi","mu","mü","için","gibi","ama","fakat","veya",
    "olarak","kadar","göre","sonra","önce","çok","var","yok","yıl","yılı","gün","ay","ben","sen",
    "biz","siz","onlar","ki","ne","kim","nasıl","nerede","when","where","who","what","why","how",
    "yer","alan","olan","olarak","olup","olduğu","yapılan","yapılır","page","sayfa","website","site",
}

# Kategori adı → açıklama map
_KIND_LABELS_TR = {
    "wiki": "Wikipedia/ansiklopedik",
    "news": "haber",
    "web": "genel web",
    "code": "açık kaynak kod tabanları",
    "profile": "sosyal medya profili",
    "social": "sosyal medya tartışması",
    "archive": "web arşivi",
    "cybint": "teknik altyapı (DNS/SSL)",
    "sanction": "yaptırım listesi",
    "attack_surface": "saldırı yüzeyi (typo-squat)",
    "financial": "finansal açıklama (SEC)",
    "threat_exposure": "siber tehdit (ransomware)",
    "corp_registry": "kurumsal kayıt",
    "link_signal": "tracking sinyali",
}


def _domain_of(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def _significant_tokens(text: str, min_len: int = 4) -> list[str]:
    words = re.findall(r"[A-Za-zÇĞİÖŞÜçğıöşü0-9]{%d,}" % min_len, text or "")
    return [w.lower() for w in words if w.lower() not in _STOPWORDS]


def _extract_roles(sources: list[dict]) -> list[tuple[str, int]]:
    role_counter: Counter[str] = Counter()
    for s in sources:
        text = (s.get("title") or "") + " " + (s.get("snippet") or "")
        for rx, label in _ROLE_PATTERNS:
            if re.search(rx, text, re.I):
                role_counter[label] += 1
    return role_counter.most_common(5)


def _extract_locations(sources: list[dict]) -> list[tuple[str, int]]:
    loc_counter: Counter[str] = Counter()
    for s in sources:
        text = (s.get("title") or "") + " " + (s.get("snippet") or "")
        for m in _LOCATION_TR.findall(text):
            loc_counter[m.title()] += 1
        for m in _LOCATION_GLOBAL.findall(text):
            loc_counter[m.title()] += 1
    return loc_counter.most_common(5)


def _extract_years(sources: list[dict]) -> tuple[int | None, int | None, list[int]]:
    """En erken/geç yıl + tüm yıllar listesi (dağılım için)."""
    years: list[int] = []
    for s in sources:
        date = s.get("published_at") or ""
        text = (s.get("title") or "") + " " + (s.get("snippet") or "")
        for m in _DATE_RE.findall(date):
            try:
                y = int(date[:4]) if date[:4].isdigit() else None
                if y and 1990 <= y <= datetime.now().year + 1:
                    years.append(y)
                    break  # Sadece ilk eşleşme published_at için
            except (ValueError, TypeError):
                pass
        for m in _DATE_RE.finditer(text):
            try:
                y = int(m.group())
                if 1990 <= y <= datetime.now().year + 1:
                    years.append(y)
            except ValueError:
                pass
    if not years:
        return None, None, []
    return min(years), max(years), years


def _top_topics(sources: list[dict], target: str, k: int = 8) -> list[tuple[str, int]]:
    """En sık tekrar eden anahtar kelimeler (hedef ve domain'leri hariç)."""
    target_words = set(_significant_tokens(target, min_len=3))
    counter: Counter[str] = Counter()
    for s in sources:
        text = (s.get("title") or "") + " " + (s.get("snippet") or "")
        for tok in _significant_tokens(text):
            if tok in target_words:
                continue
            # Domain'lerden gelen kelimeler de elenmeli
            if len(tok) < 4 or tok.isdigit():
                continue
            counter[tok] += 1
    # Sadece >= 2 kez geçenler anlamlı
    return [(w, c) for w, c in counter.most_common(k * 3) if c >= 2][:k]


def _domain_distribution(sources: list[dict], k: int = 8) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for s in sources:
        d = _domain_of(s.get("url", ""))
        if d:
            counter[d] += 1
    return counter.most_common(k)


def _kind_distribution(sources: list[dict]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for s in sources:
        counter[s.get("kind", "web")] += 1
    return dict(counter)


def _social_platforms(sources: list[dict]) -> list[str]:
    plats = set()
    for s in sources:
        src = s.get("source", "") or ""
        if src.startswith("social:"):
            plats.add(src.replace("social:", ""))
    return sorted(plats)


def _high_signal_sources(sources: list[dict]) -> dict[str, list[dict]]:
    """Risk/yüksek-sinyal kaynaklarını grupla — rapor başına çıkacak."""
    high: dict[str, list[dict]] = defaultdict(list)
    for s in sources:
        kind = s.get("kind", "")
        if kind in ("sanction", "threat_exposure", "attack_surface", "financial",
                    "corp_registry", "cybint"):
            high[kind].append(s)
    return dict(high)


# ============================================================
# Sentez fonksiyonları
# ============================================================


_TR_FOLD_TABLE = str.maketrans({
    "ç": "c", "Ç": "c", "ğ": "g", "Ğ": "g", "ı": "i", "I": "i",
    "İ": "i", "ö": "o", "Ö": "o", "ş": "s", "Ş": "s", "ü": "u", "Ü": "u",
})


def _check_name_collision(target: str, sources: list[dict]) -> tuple[int, int, list[str]]:
    """Kaynaklarda hedef adının tam eşleşme sayısını + alternatif isimleri tespit et.

    Returns: (full_match_count, total_non_social, alternative_names)
    """
    target_fold = target.translate(_TR_FOLD_TABLE).lower()
    parts = [p for p in target_fold.split() if len(p) >= 3]
    if not parts:
        return (0, 0, [])

    full = 0
    total = 0
    alt_names: Counter[str] = Counter()
    for s in sources:
        if (s.get("source") or "").startswith("social:"):
            continue
        total += 1
        text = (s.get("title", "") + " " + s.get("snippet", "")).translate(_TR_FOLD_TABLE).lower()
        if all(p in text for p in parts):
            full += 1
            continue
        # Hangi alternatif isim öne çıkıyor? Title'dan çıkar (ilk 2-3 word)
        title_words = re.findall(r"[A-Za-zÇĞİÖŞÜçğıöşü]+", s.get("title", ""))[:3]
        if title_words:
            cand = " ".join(title_words[:2])
            if len(cand) >= 6 and cand.lower() != target.lower():
                alt_names[cand.title()] += 1
    return (full, total, [name for name, _ in alt_names.most_common(3)])


def synthesize_overview(target: str, kind: str, sources: list[dict]) -> str:
    """Ana özet paragrafı — kaynaklara dayalı akıcı 3-5 cümle."""
    n = len(sources)
    if n == 0:
        return f"'{target}' için açık kaynaklarda yeterli veri bulunamadı."

    # KRİTİK: Eş isim çakışması kontrolü
    if kind in ("person", "organization"):
        full_match, total_web, alt_names = _check_name_collision(target, sources)
        if total_web >= 3 and full_match == 0:
            # Hedef adı hiç geçmiyor — kaynakların tümü farklı kişiler
            alt_str = f" Görünen alternatif isimler: {', '.join(alt_names)}." if alt_names else ""
            return (
                f"⚠ Hedef '{target}' için doğrulanabilir veri bulunamadı. {total_web} web kaynağı "
                f"toplandı ancak HİÇBİRİNDE hedef adı tam olarak geçmiyor — bu kaynaklar farklı "
                f"kişilere/kurumlara ait (eş isim çakışması).{alt_str} "
                f"Daha spesifik seed (kurum, lokasyon, kullanıcı adı) ile yeniden arama önerilir."
            )

    parts: list[str] = []
    kind_dist = _kind_distribution(sources)
    domains = _domain_distribution(sources, k=5)
    roles = _extract_roles(sources)
    locations = _extract_locations(sources)
    min_y, max_y, _ = _extract_years(sources)
    high = _high_signal_sources(sources)
    platforms = _social_platforms(sources)
    topics = _top_topics(sources, target, k=5)

    # Cümle 1 — kaç kaynak, kaç farklı kategori
    top_kinds = sorted(kind_dist.items(), key=lambda x: -x[1])[:3]
    kind_phrase = ", ".join(f"{_KIND_LABELS_TR.get(k, k)} ({c})" for k, c in top_kinds)
    parts.append(f"'{target}' için {n} açık kaynak derlendi; ağırlıklı kategori: {kind_phrase}.")

    # Cümle 2 — rol/title varsa
    if roles:
        role_str = ", ".join(r[0] for r in roles[:3])
        parts.append(f"Bağlamsal rol/title sinyalleri: {role_str}.")

    # Cümle 3 — lokasyon varsa
    if locations:
        loc_str = ", ".join(l[0] for l in locations[:3])
        parts.append(f"Coğrafi sinyaller: {loc_str}.")

    # Cümle 4 — sosyal medya
    if platforms:
        plat_str = ", ".join(platforms[:6])
        parts.append(f"Sosyal medya varlığı: {len(platforms)} platform ({plat_str}).")

    # Cümle 5 — tarih aralığı
    if min_y and max_y and min_y != max_y:
        parts.append(f"Aktif dönem: {min_y}–{max_y}.")
    elif min_y:
        parts.append(f"İlk iz: {min_y}.")

    # Cümle 6 — kritik risk sinyali
    risk_phrases = []
    if high.get("sanction"):
        risk_phrases.append(f"yaptırım/PEP listesi eşleşmesi ({len(high['sanction'])} kayıt)")
    if high.get("threat_exposure"):
        risk_phrases.append(f"ransomware leak sitesinde isim tespit edildi ({len(high['threat_exposure'])})")
    if high.get("attack_surface"):
        risk_phrases.append(f"{len(high['attack_surface'])} canlı typo-squat domain")
    if risk_phrases:
        parts.append("KRİTİK: " + "; ".join(risk_phrases) + ".")

    # Cümle 7 — domain özeti
    if domains and not high:  # Risk yoksa nötr domain özeti
        dom_str = ", ".join(d[0] for d in domains[:3])
        parts.append(f"En çok bahseden kaynaklar: {dom_str}.")

    # Cümle 8 — tematik anahtar
    if topics:
        topic_str = ", ".join(t[0] for t in topics[:4])
        parts.append(f"Tekrar eden temalar: {topic_str}.")

    return " ".join(parts[:6])  # max 6 cümle


def synthesize_top_findings(target: str, kind: str, sources: list[dict], k: int = 6) -> list[dict]:
    """Top N bulgu — domain çeşitliliği + içerik kalitesine göre."""
    findings: list[dict] = []

    # 1. Risk sinyalleri öncelikli
    high = _high_signal_sources(sources)
    for kind_key in ("sanction", "threat_exposure", "attack_surface", "corp_registry", "financial", "cybint"):
        for s in high.get(kind_key, []):
            idx = next((i for i, src in enumerate(sources) if src.get("url") == s.get("url")), -1)
            if idx == -1:
                continue
            findings.append({
                "claim": s.get("title", "").lstrip("⚠ "),
                "source_indices": [idx],
                "verification": "single",
            })
            if len(findings) >= 3:
                break
        if len(findings) >= 3:
            break

    # 2. Wikipedia/wikidata varsa
    wiki = [(i, s) for i, s in enumerate(sources) if s.get("kind") == "wiki"]
    if wiki and len(findings) < k:
        i, s = wiki[0]
        findings.append({
            "claim": f"Ansiklopedik kayıt: {s.get('title', '')}",
            "source_indices": [i],
            "verification": "single",
        })

    # 3. Yüksek-confidence haber kaynakları
    news = [(i, s) for i, s in enumerate(sources)
            if s.get("kind") == "news" and s.get("confidence", 0) >= 0.6]
    if news and len(findings) < k:
        i, s = news[0]
        findings.append({
            "claim": f"Haber kaynağında bahsediliyor: {s.get('title', '')}",
            "source_indices": [i],
            "verification": "single",
        })

    # 4. Sosyal medya yaygınlığı
    profile_count = sum(1 for s in sources if s.get("kind") == "profile")
    if profile_count >= 3 and len(findings) < k:
        prof_idx = [i for i, s in enumerate(sources) if s.get("kind") == "profile"][:5]
        platforms = sorted({(sources[i].get("source") or "").replace("social:", "") for i in prof_idx})
        findings.append({
            "claim": f"{profile_count} sosyal medya platformunda varlık tespit edildi: {', '.join(platforms[:5])}",
            "source_indices": prof_idx,
            "verification": "triple" if profile_count >= 5 else "double",
        })

    # 5. Domain çeşitliliği — aynı bulgu birden fazla farklı domain'de varsa "triple"
    domain_groups: dict[str, list[int]] = defaultdict(list)
    for i, s in enumerate(sources):
        d = _domain_of(s.get("url", ""))
        if d:
            domain_groups[d].append(i)

    # 6. En çok bahseden domain'lerden top finding
    top_domains = sorted(domain_groups.items(), key=lambda x: -len(x[1]))[:3]
    for dom, idxs in top_domains:
        if len(findings) >= k:
            break
        if any(idx in (f.get("source_indices") or []) for f in findings for idx in idxs):
            continue  # Zaten başka findings'te kullanılmış
        sample = sources[idxs[0]]
        findings.append({
            "claim": f"{dom} → {sample.get('title', '')[:120]}",
            "source_indices": idxs[:3],
            "verification": "triple" if len(idxs) >= 3 else "double" if len(idxs) == 2 else "single",
        })

    return findings[:k]


def synthesize_identity_definition(target: str, kind: str, sources: list[dict]) -> str:
    """'X kim/ne' cümlesi — wiki/wikidata varsa ondan, yoksa role+location'dan."""
    # Wiki tercih
    for s in sources:
        if s.get("kind") == "wiki" and s.get("snippet"):
            return f"{target} — {s.get('snippet', '')[:280]}"

    roles = _extract_roles(sources)
    locations = _extract_locations(sources)

    if roles and locations:
        return f"{target}, kaynaklarda {roles[0][0]} sıfatıyla, {locations[0][0]} bağlamında geçiyor (rule-based çıkarım, manuel teyit gerekir)."
    if roles:
        return f"{target}, kaynaklarda ağırlıklı olarak {roles[0][0]} sıfatıyla geçiyor (manuel teyit gerekir)."
    if locations:
        return f"{target}, kaynaklarda {locations[0][0]} bağlamında geçiyor."
    if kind == "person":
        return f"{target} hakkında kişi bağlamı kaynaklardan netleşmiyor; daha spesifik seed (kurum, lokasyon) önerilir."
    if kind == "organization":
        return f"{target} hakkında kurumsal bağlam kaynaklarda kısıtlı; KAP/MERSIS/Companies House gibi resmi kayıtlara yönelmek önerilir."
    return f"{target} için kaynaklarda net bir tanım çıkarılamadı."


def synthesize_relations(target: str, sources: list[dict], k: int = 6) -> list[dict]:
    """Domain'ler ve sosyal platformlar üzerinden ilişki çıkar."""
    rels: list[dict] = []
    profile_idx = [i for i, s in enumerate(sources) if s.get("kind") == "profile"]
    code_idx = [i for i, s in enumerate(sources) if s.get("kind") == "code"]

    for i in profile_idx[:3]:
        s = sources[i]
        plat = (s.get("source") or "").replace("social:", "")
        rels.append({
            "entity": f"{plat} hesabı",
            "relation": "varlık tespit edildi (manuel teyit gerekir)",
            "strength": "weak",
            "source_indices": [i],
        })
    for i in code_idx[:2]:
        s = sources[i]
        rels.append({
            "entity": s.get("title", "")[:80],
            "relation": "açık kaynak kod tabanında referans",
            "strength": "weak",
            "source_indices": [i],
        })
    # Yaptırım/threat ilişkileri
    for i, s in enumerate(sources):
        if s.get("kind") == "sanction":
            rels.append({
                "entity": s.get("title", "Yaptırım listesi"),
                "relation": "yaptırım/PEP liste eşleşmesi",
                "strength": "strong",
                "source_indices": [i],
            })
            if len(rels) >= k:
                break
        if s.get("kind") == "threat_exposure":
            group = (s.get("raw") or {}).get("group", "?")
            rels.append({
                "entity": f"Ransomware: {group}",
                "relation": "leak sitesinde isim tespit edildi",
                "strength": "strong",
                "source_indices": [i],
            })
    return rels[:k]


def synthesize_conclusion(target: str, kind: str, sources: list[dict]) -> str:
    n = len(sources)
    if n == 0:
        return f"'{target}' için doğrulanabilir açık kaynak izi tespit edilemedi."

    high = _high_signal_sources(sources)
    parts = []

    if high:
        risk_items = []
        if high.get("sanction"):
            risk_items.append(f"{len(high['sanction'])} yaptırım eşleşmesi")
        if high.get("threat_exposure"):
            risk_items.append(f"{len(high['threat_exposure'])} ransomware kaydı")
        if high.get("attack_surface"):
            risk_items.append(f"{len(high['attack_surface'])} typo-squat")
        parts.append(
            f"'{target}' için {n} kaynak içinde KRİTİK sinyaller tespit edildi: "
            f"{', '.join(risk_items)}. Acil hukuki/uyumluluk değerlendirmesi gerekir."
        )
    else:
        parts.append(
            f"'{target}' için {n} açık kaynaktan derlenmiş profil bulguları hazır. "
            f"Kritik risk sinyali tespit edilmedi."
        )

    profile_count = sum(1 for s in sources if s.get("kind") == "profile")
    if profile_count >= 5:
        parts.append(
            f"{profile_count} sosyal medya platformunda varlık var — "
            f"sosyal mühendislik yüzeyi geniş, gizlilik ayarları gözden geçirilmeli."
        )

    if not any(s.get("kind") == "wiki" for s in sources):
        parts.append("Ansiklopedik kayıt bulunamadı — kimlik teyidi sınırlı, ek doğrulama önerilir.")

    parts.append(
        "Bu rapor LLM-free istatistiksel sentez ile üretildi; bağlamsal nüans için "
        "Settings'ten bir LLM anahtarı ekleyip raporu yeniden çalıştırın."
    )

    return " ".join(parts)
