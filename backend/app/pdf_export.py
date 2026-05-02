"""Server-side PDF rendering — Markdown brief'ten veya JSON report'tan
yapılandırılmış, text-search'lü, sayfa-uyumlu profesyonel PDF üretir.

xhtml2pdf (pure Python) kullanır — Render Linux'ta sorunsuz kurulur.
Türkçe karakterler için "DejaVu Sans" font ailesi öncelikli (sistem fontu
yoksa Arial/Helvetica fallback).
"""

from __future__ import annotations

import html as html_lib
import io
import logging
import re
from datetime import datetime, timezone
from typing import Optional


log = logging.getLogger("pdf_export")


PDF_CSS = """
@page {
  size: A4;
  margin: 1.5cm;
  @frame footer_frame {
    -pdf-frame-content: footer_content;
    left: 1.5cm; width: 18cm; bottom: 0.8cm; height: 0.5cm;
  }
}
body {
  font-family: "DejaVu Sans", Arial, Helvetica, sans-serif;
  font-size: 10pt; line-height: 1.5; color: #1e293b;
}
h1 {
  font-size: 18pt; color: #312e81;
  border-bottom: 2pt solid #4f46e5; padding-bottom: 4pt;
  margin-top: 20pt; -pdf-keep-with-next: true;
}
h2 {
  font-size: 14pt; color: #4338ca;
  margin-top: 16pt; -pdf-keep-with-next: true;
  border-bottom: 0.5pt solid #c7d2fe; padding-bottom: 2pt;
}
h3 { font-size: 12pt; color: #4f46e5; margin-top: 10pt; -pdf-keep-with-next: true; }
h4 { font-size: 11pt; color: #6366f1; margin-top: 8pt; }
p { margin: 4pt 0; }
table { width: 100%; border-collapse: collapse; margin: 8pt 0; font-size: 9pt; }
th, td {
  border: 0.5pt solid #cbd5e1; padding: 4pt 6pt;
  text-align: left; vertical-align: top;
}
th { background: #e0e7ff; font-weight: bold; color: #312e81; }
tr:nth-child(even) td { background: #f8fafc; }
code {
  font-family: "Courier New", monospace; background: #f1f5f9;
  padding: 1pt 3pt; font-size: 9pt; color: #be185d;
}
pre { background: #f1f5f9; padding: 6pt; font-size: 9pt; }
ul, ol { margin: 6pt 0; padding-left: 18pt; }
li { margin: 2pt 0; }
blockquote {
  border-left: 2pt solid #6366f1; padding-left: 8pt;
  color: #475569; font-style: italic; margin: 6pt 0;
}
.cover { text-align: center; padding-top: 4cm; }
.cover h1 { font-size: 28pt; border: none; margin-top: 0.5cm; }
.cover .subtitle { font-size: 13pt; color: #6366f1; font-weight: bold; letter-spacing: 1pt; }
.cover .meta { font-size: 11pt; color: #64748b; margin-top: 0.4cm; }
.cover .stats { margin-top: 1.5cm; padding: 0.6cm; background: #f1f5f9; border: 1pt solid #cbd5e1; }
.warning {
  background: #fef3c7; border-left: 3pt solid #f59e0b;
  padding: 6pt 8pt; margin: 8pt 0;
}
.risk-high { color: #b91c1c; font-weight: bold; }
.risk-medium { color: #b45309; font-weight: bold; }
.risk-low { color: #047857; font-weight: bold; }
.adm-A1, .adm-A2, .adm-B1, .adm-B2 { background: #d1fae5; color: #065f46; padding: 1pt 4pt; }
.adm-B3, .adm-C2, .adm-C3 { background: #dbeafe; color: #1e40af; padding: 1pt 4pt; }
.adm-D4, .adm-D5 { background: #fef3c7; color: #92400e; padding: 1pt 4pt; }
.adm-E4, .adm-F4, .adm-F5 { background: #fee2e2; color: #991b1b; padding: 1pt 4pt; }
.section-divider { page-break-before: always; }
"""


def _escape(s: str) -> str:
    return html_lib.escape(s or "", quote=True)


def _risk_class(level: str) -> str:
    return f"risk-{(level or 'low').lower()}"


def _strip_mermaid(md: str) -> str:
    """xhtml2pdf Mermaid render edemez — code block'u placeholder ile değiştir."""
    return re.sub(
        r"```mermaid\s*\n.*?\n```",
        "*[İlişki diyagramı — PDF formatında render edilemez. Web sürümünde Mermaid render'ı görünür.]*",
        md,
        flags=re.DOTALL,
    )


def _render_cover(target: str, kind: str, report: dict, sources: list[dict],
                  used_llm: str) -> str:
    es = report.get("executive_summary", {}) or {}
    risk = (es.get("risk_level") or "low").lower()
    confidence = (es.get("confidence", 0) or 0) * 100
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n_sources = len(sources)
    n_findings = len(report.get("admiralty_findings") or [])

    return f"""
<div class="cover">
  <div class="subtitle">OSINT İSTİHBARAT RAPORU</div>
  <h1>{_escape(target)}</h1>
  <div class="meta">Hedef türü: <b>{_escape(kind or 'auto')}</b></div>
  <div class="meta">NATO OSINT Handbook + IC Directive 203 standartları</div>
  <div class="stats">
    <table style="border:none;">
      <tr style="border:none;">
        <td style="border:none; text-align:center;">
          <b style="font-size:14pt;" class="{_risk_class(risk)}">{risk.upper()}</b><br/>
          <span style="font-size:9pt;color:#64748b;">Risk Seviyesi</span>
        </td>
        <td style="border:none; text-align:center;">
          <b style="font-size:14pt;color:#4338ca;">{confidence:.0f}%</b><br/>
          <span style="font-size:9pt;color:#64748b;">Güven</span>
        </td>
        <td style="border:none; text-align:center;">
          <b style="font-size:14pt;color:#4338ca;">{n_sources}</b><br/>
          <span style="font-size:9pt;color:#64748b;">Kaynak</span>
        </td>
        <td style="border:none; text-align:center;">
          <b style="font-size:14pt;color:#4338ca;">{n_findings}</b><br/>
          <span style="font-size:9pt;color:#64748b;">Admiralty Bulgu</span>
        </td>
      </tr>
    </table>
  </div>
  <div class="meta" style="margin-top:1cm;">Tarih: {today}</div>
  <div class="meta" style="font-family:monospace;font-size:8pt;color:#94a3b8;">{_escape(used_llm or 'rule-based')}</div>
</div>
<pdf:nextpage />
"""


def _render_structured_html(target: str, report: dict, sources: list[dict]) -> str:
    """Brief Markdown yoksa JSON report'tan structured HTML üret."""
    parts: list[str] = []
    es = report.get("executive_summary", {}) or {}

    # 1. Yönetici Özeti
    parts.append("<h2>1. Yönetici Özeti (BLUF)</h2>")
    parts.append(f"<p>{_escape(es.get('overview', ''))}</p>")

    findings = es.get("top_findings") or []
    if findings:
        parts.append("<h3>Top Bulgular</h3><ul>")
        for f in findings:
            claim = _escape(f.get("claim", ""))
            v = f.get("verification", "")
            srcs = f.get("source_indices", [])
            src_str = ", ".join(f"[{i}]" for i in srcs)
            parts.append(f"<li>{claim} <em>({_escape(v)})</em> <code>{src_str}</code></li>")
        parts.append("</ul>")

    # 2. PIR Matrisi
    pir = report.get("pir_matrix") or []
    if pir:
        parts.append("<h2>2. PIR Cevap Matrisi</h2>")
        parts.append("<table><tr><th>PIR</th><th>Soru</th><th>Cevap</th><th>Güven</th></tr>")
        for p in pir:
            adm = _escape(p.get("admiralty", ""))
            adm_cls = f"adm-{adm}" if adm else ""
            parts.append(
                f"<tr><td><b>{_escape(p.get('id', ''))}</b></td>"
                f"<td>{_escape(p.get('question', ''))}</td>"
                f"<td>{_escape(p.get('answer', '') or '')[:300]}</td>"
                f"<td><span class=\"{adm_cls}\">{adm}</span></td></tr>"
            )
        parts.append("</table>")

    # 3. Admiralty bulgular
    adm_findings = report.get("admiralty_findings") or []
    if adm_findings:
        parts.append("<h2>3. Admiralty Kodlu Bulgular (NATO Standardı)</h2>")
        parts.append("<table><tr><th>Bulgu</th><th>Kod</th><th>Vector</th><th>Kaynak</th></tr>")
        for a in adm_findings:
            code = _escape(a.get("code", ""))
            srcs = a.get("source_indices", [])
            src_str = ", ".join(f"[{i}]" for i in srcs)
            parts.append(
                f"<tr><td>{_escape(a.get('finding', ''))[:300]}</td>"
                f"<td><span class=\"adm-{code}\"><b>{code}</b></span></td>"
                f"<td><b>{_escape(a.get('vector', 'GENERAL'))}</b></td>"
                f"<td><code>{src_str}</code></td></tr>"
            )
        parts.append("</table>")

    # 4. Çapraz Doğrulama
    cv = report.get("cross_verification") or []
    if cv:
        parts.append("<h2>4. Çapraz Doğrulama</h2>")
        parts.append("<table><tr><th>İddia</th><th>Seviye</th><th>Kaynak Türleri</th></tr>")
        for v in cv:
            parts.append(
                f"<tr><td>{_escape(v.get('claim', ''))[:300]}</td>"
                f"<td><b>{_escape(v.get('level', ''))}</b></td>"
                f"<td>{_escape(', '.join(v.get('source_kinds', [])))}</td></tr>"
            )
        parts.append("</table>")

    # 5. Kimlik
    ident = report.get("identity") or {}
    if ident:
        parts.append("<h2>5. Kimlik (Kim/Ne)</h2>")
        parts.append(f"<p>{_escape(ident.get('definition', ''))}</p>")
        parts.append(f"<p><b>Bağlam:</b> {_escape(ident.get('context', ''))}</p>")
        parts.append(f"<p><b>Eş isim riski:</b> {_escape(ident.get('name_collision_risk', ''))}</p>")

    # 6. Dijital İz
    df = report.get("digital_footprint") or {}
    if df:
        parts.append("<h2>6. Dijital Ayak İzi</h2>")
        parts.append("<table>")
        for k, v in df.items():
            parts.append(f"<tr><th style='width:18%;'>{_escape(k)}</th><td>{_escape(str(v))[:400]}</td></tr>")
        parts.append("</table>")

    # 7. Zaman Çizelgesi
    timeline = report.get("timeline") or []
    if timeline:
        parts.append("<h2>7. Zaman Çizelgesi</h2>")
        parts.append("<table><tr><th style='width:14%;'>Tarih</th><th>Olay</th><th>Kaynak</th></tr>")
        for t in timeline:
            srcs = t.get("source_indices", [])
            parts.append(
                f"<tr><td><code>{_escape(t.get('date', ''))}</code></td>"
                f"<td>{_escape(t.get('event', ''))[:300]}</td>"
                f"<td><code>{_escape(', '.join(f'[{i}]' for i in srcs))}</code></td></tr>"
            )
        parts.append("</table>")

    # 8. Risk Matrisi
    rm = report.get("risk_matrix") or []
    if rm:
        parts.append("<h2>8. Risk Matrisi (Likelihood × Impact)</h2>")
        parts.append("<table><tr><th>Risk</th><th>Kategori</th><th>L</th><th>I</th><th>Skor</th><th>Mitigation</th></tr>")
        for r in rm:
            score = r.get("score", 0)
            score_cls = "risk-high" if score >= 15 else ("risk-medium" if score >= 8 else "risk-low")
            parts.append(
                f"<tr><td>{_escape(r.get('risk', ''))[:200]}</td>"
                f"<td><b>{_escape(r.get('category', ''))}</b></td>"
                f"<td>{r.get('likelihood', '')}</td>"
                f"<td>{r.get('impact', '')}</td>"
                f"<td><b class=\"{score_cls}\">{score}</b></td>"
                f"<td>{_escape(r.get('mitigation', ''))[:200]}</td></tr>"
            )
        parts.append("</table>")

    # 9. ACH
    ach = report.get("ach_analysis") or {}
    hyps = ach.get("hypotheses") or []
    if hyps:
        parts.append("<h2>9. Çakışan Hipotezler (ACH)</h2>")
        for h in hyps:
            verdict = _escape(h.get("verdict", "?"))
            verdict_emoji = "✓" if verdict == "destekli" else ("⚠" if verdict == "zayıf" else "✗")
            parts.append(
                f"<h4>{_escape(h.get('id', ''))}: {verdict_emoji} <em>({verdict})</em></h4>"
                f"<p>{_escape(h.get('statement', ''))}</p>"
            )
            sup = h.get("supporting", []) or []
            con = h.get("contradicting", []) or []
            if sup:
                parts.append(f"<p><b>Destekleyen:</b> <code>{', '.join(f'[{i}]' for i in sup)}</code></p>")
            if con:
                parts.append(f"<p><b>Çelişen:</b> <code>{', '.join(f'[{i}]' for i in con)}</code></p>")
        if ach.get("rationale"):
            parts.append(f"<p><b>Tercih:</b> {_escape(ach.get('preferred', '?'))} — <em>{_escape(ach['rationale'])}</em></p>")

    # 10. Pivot önerileri
    pivots = report.get("pivot_suggestions") or []
    if pivots:
        parts.append("<h2>10. Pivot Önerileri</h2><ul>")
        for p in pivots:
            tools = ", ".join(p.get("tools", []))
            parts.append(
                f"<li><b><code>{_escape(p.get('new_seed', ''))}</code></b> "
                f"— {_escape(p.get('rationale', ''))} "
                f"<em>(araçlar: {_escape(tools)})</em></li>"
            )
        parts.append("</ul>")

    # 11. İstihbarat Boşlukları
    gaps = report.get("intelligence_gaps") or []
    if gaps:
        parts.append("<h2>11. İstihbarat Boşlukları</h2>")
        for g in gaps:
            parts.append(
                "<div class=\"warning\">"
                f"<b>⚠ {_escape(g.get('gap', ''))}</b><br/>"
                f"<b>Önem:</b> {_escape(g.get('why_important', ''))}<br/>"
                f"<b>Takip:</b> {_escape(g.get('follow_up', ''))}"
                "</div>"
            )

    # 12. Sonuç
    parts.append(f"<h2>12. Sonuç</h2><p>{_escape(report.get('conclusion', ''))}</p>")

    # 13. Kaynaklar
    if sources:
        parts.append(f"<div class=\"section-divider\"></div>")
        parts.append(f"<h2>13. Kaynak Listesi ({len(sources)})</h2>")
        parts.append("<table><tr><th style='width:5%;'>#</th><th style='width:14%;'>Kaynak</th><th style='width:10%;'>Tür</th><th>Başlık</th><th style='width:12%;'>Tarih</th></tr>")
        for i, s in enumerate(sources[:120]):
            url = (s.get("url") or "").strip()
            title = (s.get("title") or url)[:90]
            date = s.get("published_at") or "—"
            parts.append(
                f"<tr><td>{i}</td>"
                f"<td><code>{_escape(s.get('source', ''))}</code></td>"
                f"<td>{_escape(s.get('kind', ''))}</td>"
                f"<td>{_escape(title)}<br/><code style='font-size:7pt;color:#94a3b8;'>{_escape(url[:80])}</code></td>"
                f"<td><code>{_escape(date)}</code></td></tr>"
            )
        if len(sources) > 120:
            parts.append(f"<tr><td colspan=5><em>... +{len(sources) - 120} kaynak daha (PDF için kesildi)</em></td></tr>")
        parts.append("</table>")

    # 14. Yasal
    notice = report.get("legal_ethical_notice")
    if notice:
        parts.append(f"<h2>14. Yasal / Etik Beyan</h2><p style='font-size:9pt;color:#64748b;'>{_escape(notice)}</p>")

    return "".join(parts)


def render_pdf(
    target: str,
    kind: str,
    report: dict,
    sources: list[dict],
    brief_md: Optional[str] = None,
    used_llm: str = "",
) -> bytes:
    """Generate PDF bytes from research result. Returns raw bytes."""
    from xhtml2pdf import pisa  # lazy import (large dep)
    import markdown as md_lib

    cover_html = _render_cover(target, kind, report, sources, used_llm)

    if brief_md and len(brief_md.strip()) > 200:
        # Brief MD varsa öncelikli — Markdown'ı HTML'e çevir
        clean_md = _strip_mermaid(brief_md)
        body_html = md_lib.markdown(
            clean_md,
            extensions=["tables", "fenced_code", "nl2br"],
            output_format="html",
        )
        # Kaynak listesi de ekle (brief'te kısaltılmış olabilir)
        if sources:
            body_html += '<div class="section-divider"></div>'
            body_html += f"<h2>EK — Tam Kaynak Listesi ({len(sources)})</h2>"
            body_html += "<table><tr><th>#</th><th>Kaynak</th><th>Başlık</th><th>URL</th></tr>"
            for i, s in enumerate(sources[:120]):
                url = (s.get("url") or "")[:90]
                title = (s.get("title") or url)[:90]
                body_html += (
                    f"<tr><td>{i}</td>"
                    f"<td><code>{_escape(s.get('source', ''))}</code></td>"
                    f"<td>{_escape(title)}</td>"
                    f"<td><code style='font-size:7pt;color:#94a3b8;'>{_escape(url)}</code></td></tr>"
                )
            body_html += "</table>"
    else:
        body_html = _render_structured_html(target, report, sources)

    full_html = (
        f"<html><head><meta charset='utf-8'><style>{PDF_CSS}</style></head>"
        f"<body>{cover_html}{body_html}"
        f"<div id=\"footer_content\" style=\"font-size:8pt;color:#94a3b8;text-align:center;\">"
        f"OSINT Research App — {_escape(target)} — Sayfa <pdf:pagenumber/> / <pdf:pagecount/></div>"
        f"</body></html>"
    )

    buf = io.BytesIO()
    result = pisa.CreatePDF(full_html, dest=buf, encoding="utf-8")
    if result.err:
        log.error("PDF generation errors: %s", result.err)
        raise RuntimeError(f"PDF üretimi başarısız (xhtml2pdf {result.err} hata)")
    buf.seek(0)
    return buf.read()
