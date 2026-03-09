from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

import os
import json

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from sqlalchemy import text

import app.db.tables          # noqa: F401
import app.db.enriched_tables # noqa: F401
import app.db.mitre_tables    # noqa: F401

from app.db.database import SessionLocal
from app.db.enriched_tables import EnrichedItem, EnrichedCVE, EnrichedIOC, EnrichedRef
from app.db.mitre_tables import MitreMatch

# ── Palette ──────────────────────────────────────────────────────────────────
C_CRITICAL  = colors.HexColor("#B91C1C")  # red-700
C_HIGH      = colors.HexColor("#C2410C")  # orange-700
C_MEDIUM    = colors.HexColor("#1D4ED8")  # blue-700
C_LOW       = colors.HexColor("#374151")  # gray-700
C_BRAND     = colors.HexColor("#0F172A")  # slate-900  (header/cover bg)
C_BRAND2    = colors.HexColor("#1E293B")  # slate-800
C_ACCENT    = colors.HexColor("#38BDF8")  # sky-400
C_WHITE     = colors.white
C_LIGHT_BG  = colors.HexColor("#F8FAFC")  # slate-50
C_BORDER    = colors.HexColor("#CBD5E1")  # slate-300
C_ROW_ALT   = colors.HexColor("#F1F5F9")  # slate-100
C_ROW_CRIT  = colors.HexColor("#FEF2F2")  # red-50
C_ROW_HIGH  = colors.HexColor("#FFF7ED")  # orange-50
C_MUTED     = colors.HexColor("#64748B")  # slate-500
C_TAG_BG    = colors.HexColor("#E0F2FE")  # sky-100
C_TAG_TEXT  = colors.HexColor("#0369A1")  # sky-700

PAGE_W, PAGE_H = A4
MARGIN_L = MARGIN_R = 2.0 * cm
MARGIN_T = MARGIN_B = 2.0 * cm
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R


# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()

    def ps(name, parent_name="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent_name], **kw)

    cover_title = ps("CoverTitle",
        fontName="Helvetica-Bold", fontSize=28, leading=34,
        textColor=C_WHITE, spaceAfter=6, alignment=TA_LEFT)

    cover_sub = ps("CoverSub",
        fontName="Helvetica", fontSize=12, leading=16,
        textColor=C_ACCENT, spaceAfter=4)

    cover_meta = ps("CoverMeta",
        fontName="Helvetica", fontSize=10, leading=14,
        textColor=colors.HexColor("#94A3B8"), spaceAfter=2)

    h1 = ps("H1",
        fontName="Helvetica-Bold", fontSize=13, leading=17,
        spaceBefore=14, spaceAfter=6, textColor=C_BRAND)

    h2 = ps("H2",
        fontName="Helvetica-Bold", fontSize=11, leading=15,
        spaceBefore=10, spaceAfter=4, textColor=C_BRAND2)

    h3 = ps("H3",
        fontName="Helvetica-Bold", fontSize=10, leading=13,
        spaceBefore=6, spaceAfter=3, textColor=C_BRAND2)

    body = ps("Body", "BodyText",
        fontName="Helvetica", fontSize=10, leading=13, spaceAfter=2)

    small = ps("Small", "BodyText",
        fontName="Helvetica", fontSize=9, leading=12,
        textColor=colors.HexColor("#374151"))

    muted = ps("Muted", "BodyText",
        fontName="Helvetica", fontSize=8.5, leading=11,
        textColor=C_MUTED)

    label = ps("Label", "BodyText",
        fontName="Helvetica-Bold", fontSize=8.5, leading=11,
        textColor=C_BRAND2)

    badge_crit = ps("BadgeCrit", "BodyText",
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=C_WHITE, backColor=C_CRITICAL, alignment=TA_CENTER)

    badge_high = ps("BadgeHigh", "BodyText",
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=C_WHITE, backColor=C_HIGH, alignment=TA_CENTER)

    badge_med = ps("BadgeMed", "BodyText",
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=C_WHITE, backColor=C_MEDIUM, alignment=TA_CENTER)

    badge_low = ps("BadgeLow", "BodyText",
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=C_WHITE, backColor=C_LOW, alignment=TA_CENTER)

    tbl_hdr = ps("TblHdr", "BodyText",
        fontName="Helvetica-Bold", fontSize=8.5, leading=11,
        textColor=C_BRAND2)

    tbl_cell = ps("TblCell", "BodyText",
        fontName="Helvetica", fontSize=8.5, leading=11,
        textColor=colors.HexColor("#1E293B"))

    mono = ps("Mono", "BodyText",
        fontName="Courier", fontSize=8, leading=10,
        textColor=colors.HexColor("#0F172A"))

    return {
        "cover_title": cover_title, "cover_sub": cover_sub, "cover_meta": cover_meta,
        "h1": h1, "h2": h2, "h3": h3,
        "body": body, "small": small, "muted": muted,
        "label": label, "mono": mono,
        "badge_crit": badge_crit, "badge_high": badge_high,
        "badge_med": badge_med, "badge_low": badge_low,
        "tbl_hdr": tbl_hdr, "tbl_cell": tbl_cell,
    }


# ── Utility helpers ───────────────────────────────────────────────────────────
def san(s) -> str:
    if s is None: return ""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def short(s: str, n: int) -> str:
    t = (s or "").strip()
    return t if len(t) <= n else t[:n-1] + "…"

def fmt_dt(dt) -> str:
    if not dt: return "—"
    try: return dt.strftime("%Y-%m-%d %H:%M")
    except: return str(dt)

def fmt_date(dt) -> str:
    if not dt: return "—"
    try: return dt.strftime("%d %b %Y")
    except: return str(dt)

def clean_url(u: str) -> str:
    return (u or "").strip().rstrip("\\,")

def parse_json_list(s: Optional[str]) -> list[str]:
    if not s: return []
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
        return []
    except: return []

def wrap_url(url: str, max_line: int = 72) -> str:
    if not url: return ""
    u = clean_url(url)
    seps = ["/", "?", "&", "=", "-", "_", "."]
    lines, cur = [], ""
    for ch in u:
        cur += ch
        if len(cur) >= max_line and any(cur.endswith(s) for s in seps):
            lines.append(cur); cur = ""
    if cur: lines.append(cur)
    if len(lines) == 1 and len(lines[0]) > max_line:
        s = lines[0]
        lines = [s[i:i+max_line] for i in range(0, len(s), max_line)]
    return "<br/>".join(san(x) for x in lines)

def severity_color(sev: str) -> colors.Color:
    s = (sev or "").lower()
    if s == "critical": return C_CRITICAL
    if s == "high":     return C_HIGH
    if s == "medium":   return C_MEDIUM
    return C_LOW

def severity_row_color(sev: str) -> colors.Color:
    s = (sev or "").lower()
    if s == "critical": return C_ROW_CRIT
    if s == "high":     return C_ROW_HIGH
    return C_WHITE

def sev_badge_style(sev: str, styles) -> ParagraphStyle:
    s = (sev or "").lower()
    if s == "critical": return styles["badge_crit"]
    if s == "high":     return styles["badge_high"]
    if s == "medium":   return styles["badge_med"]
    return styles["badge_low"]

def cap(lst, n): return lst[:n]


# ── DB queries ─────────────────────────────────────────────────────────────────
def get_iocs(db, raw_item_id: int):
    rows = db.query(EnrichedIOC).filter(EnrichedIOC.raw_item_id == raw_item_id).all()
    out = {"ip": [], "domain": [], "url": [], "hash": []}
    for r in rows:
        if r.ioc_type in out: out[r.ioc_type].append(r.value)
    for k in out: out[k] = sorted(set(out[k]))
    return out

def get_refs(db, raw_item_id: int):
    rows = db.query(EnrichedRef).filter(EnrichedRef.raw_item_id == raw_item_id).all()
    out: dict = {}
    for r in rows: out.setdefault(r.ref_type, []).append(r.value)
    return out

def get_cves(db, raw_item_id: int):
    rows = db.query(EnrichedCVE).filter(EnrichedCVE.raw_item_id == raw_item_id).all()
    return sorted(set(r.cve for r in rows))

def get_cve_context(db, cves: list[str]) -> dict:
    """Fetch CVSS/EPSS from cve_context table."""
    if not cves: return {}
    placeholders = ",".join(f"'{c}'" for c in cves)
    try:
        rows = db.execute(text(
            f"SELECT cve, cvss, epss, cwe, kev FROM cve_context WHERE cve IN ({placeholders})"
        )).fetchall()
        return {r[0]: {"cvss": r[1], "epss": r[2], "cwe": r[3], "kev": r[4]} for r in rows}
    except: return {}

def get_mitre(db, raw_item_id: int):
    rows = db.query(MitreMatch).filter(MitreMatch.raw_item_id == raw_item_id).all()
    uniq = {}
    for r in rows:
        uniq[r.technique_id] = (r.technique_id, r.technique_name, r.tactic or "—",
                                 int(r.confidence or 0), (r.evidence or "").strip())
    return sorted(uniq.values(), key=lambda x: (-x[3], x[0]))

def top_techniques(db, limit=8):
    rows = db.query(MitreMatch).all()
    counter, name_map, tactic_map = {}, {}, {}
    for r in rows:
        counter[r.technique_id] = counter.get(r.technique_id, 0) + 1
        name_map[r.technique_id] = r.technique_name
        tactic_map[r.technique_id] = r.tactic or "—"
    items = sorted(counter.items(), key=lambda x: -x[1])[:limit]
    return [(tid, name_map.get(tid,""), tactic_map.get(tid,""), n) for tid, n in items]

def top_vendors(db, limit=8):
    rows = db.query(EnrichedItem.vendor).filter(EnrichedItem.vendor.isnot(None)).all()
    counter = {}
    for (v,) in rows:
        v = (v or "").strip()
        if v: counter[v] = counter.get(v, 0) + 1
    return sorted(counter.items(), key=lambda x: -x[1])[:limit]

def top_sources(db, limit=8):
    rows = db.execute(text("""
        SELECT COALESCE(source_name,'(unknown)') AS s, COUNT(*) n
        FROM enriched_items GROUP BY s ORDER BY n DESC LIMIT :lim
    """), {"lim": limit}).fetchall()
    return [(r[0], int(r[1])) for r in rows]

def severity_counts_last_days(db, days=30):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = db.execute(text("""
        SELECT severity, COUNT(*) n FROM enriched_items
        WHERE published_at >= :cutoff GROUP BY severity
    """), {"cutoff": cutoff}).fetchall()
    counts = {"critical":0, "high":0, "medium":0, "low":0}
    for sev, n in rows:
        if sev in counts: counts[sev] = n
    return counts

def weekly_trend(db, weeks=6):
    """Returns list of (week_label, count) for last N weeks."""
    results = []
    now = datetime.now()
    for i in range(weeks-1, -1, -1):
        start = now - timedelta(weeks=i+1)
        end   = now - timedelta(weeks=i)
        row = db.execute(text("""
            SELECT COUNT(*) FROM enriched_items
            WHERE published_at >= :s AND published_at < :e
              AND severity IN ('high','critical')
        """), {"s": start.strftime("%Y-%m-%d"), "e": end.strftime("%Y-%m-%d")}).fetchone()
        label = start.strftime("S%W")
        results.append((label, int(row[0]) if row else 0))
    return results

def fetch_patch_rows(db, limit=20):
    try:
        rows = db.execute(text("""
            SELECT t.cve, COALESCE(t.vendor,'') vendor, COALESCE(t.product,'') product,
                   t.status, t.last_seen,
                   (SELECT e.raw_item_id FROM enriched_cves c
                    JOIN enriched_items e ON e.raw_item_id=c.raw_item_id
                    WHERE c.cve=t.cve ORDER BY e.score DESC LIMIT 1) raw_item_id
            FROM todo_patch t WHERE t.status='todo'
            ORDER BY t.last_seen DESC LIMIT :lim
        """), {"lim": limit}).fetchall()
        return rows
    except: return []

def dedup_items(items, max_items: int):
    seen, out = set(), []
    for it in items:
        key = (it.source_name or "", (it.url or "").strip()) if (it.url or "").strip() \
              else (it.source_name or "", (it.title or "").strip().lower(), fmt_dt(it.published_at)[:10])
        if key in seen: continue
        seen.add(key)
        out.append(it)
        if len(out) >= max_items: break
    return out

def executive_summary(it: EnrichedItem) -> str:
    title = (it.title or "").lower()
    text  = (it.content_text or "").lower()
    if "known exploited vulnerabilities" in title + text:
        return "Exploitation confirmée (KEV). Appliquer les patches en priorité immédiate sur les CVEs listées."
    if "ongoing exploitation" in title + text or "actively exploited" in title + text:
        return "Exploitation active signalée. Vérifier l'exposition, patcher en urgence, surveiller les logs."
    if "authentication bypass" in text or "bypass authentication" in text:
        return "Contournement d'authentification possible. Prioriser le patch et réduire l'exposition réseau."
    if "remote code execution" in text or " rce " in text:
        return "Exécution de code à distance possible. Priorité élevée si le service est exposé."
    if "ransomware" in text:
        return "Ransomware mentionné. Vérifier la segmentation réseau, isoler les systèmes vulnérables."
    if "zero-day" in text or "0-day" in text:
        return "Zero-day — pas de patch disponible. Appliquer les mitigations temporaires (WAF, segmentation)."
    return "Avis de sécurité. Vérifier l'impact selon produits/versions affectées et appliquer les correctifs."


# ── Page header/footer ────────────────────────────────────────────────────────
def draw_header_footer(canvas, doc, report_title: str, generated_at: str):
    canvas.saveState()

    # Top rule
    canvas.setStrokeColor(C_BRAND)
    canvas.setLineWidth(2)
    canvas.line(MARGIN_L, PAGE_H - MARGIN_T + 4*mm, PAGE_W - MARGIN_R, PAGE_H - MARGIN_T + 4*mm)

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_BRAND)
    canvas.drawString(MARGIN_L, PAGE_H - MARGIN_T + 5.5*mm, report_title.upper())
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(C_MUTED)
    canvas.drawRightString(PAGE_W - MARGIN_R, PAGE_H - MARGIN_T + 5.5*mm, f"Généré le {generated_at}")

    # Bottom rule
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN_L, MARGIN_B - 4*mm, PAGE_W - MARGIN_R, MARGIN_B - 4*mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(MARGIN_L, MARGIN_B - 7*mm, "cti-watch — Confidentiel")
    canvas.drawRightString(PAGE_W - MARGIN_R, MARGIN_B - 7*mm, f"Page {doc.page}")

    canvas.restoreState()


# ── Cover page (drawn directly on canvas) ─────────────────────────────────────
def draw_cover(canvas, doc, generated_at: str, stats: dict):
    canvas.saveState()

    # Full dark background header band (top 40% of page)
    band_h = PAGE_H * 0.42
    canvas.setFillColor(C_BRAND)
    canvas.rect(0, PAGE_H - band_h, PAGE_W, band_h, fill=1, stroke=0)

    # Accent bar (left edge)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, PAGE_H - band_h, 6, band_h, fill=1, stroke=0)

    # Title
    canvas.setFont("Helvetica-Bold", 30)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(MARGIN_L + 8, PAGE_H - 4.5*cm, "CTI DAILY REPORT")

    canvas.setFont("Helvetica", 14)
    canvas.setFillColor(C_ACCENT)
    canvas.drawString(MARGIN_L + 8, PAGE_H - 5.5*cm, "Cyber Threat Intelligence — Synthèse automatisée")

    canvas.setFont("Helvetica", 11)
    canvas.setFillColor(colors.HexColor("#94A3B8"))
    canvas.drawString(MARGIN_L + 8, PAGE_H - 6.5*cm, f"Généré le {generated_at}")

    # Stats boxes (4 KPI cards)
    card_w = (CONTENT_W - 3*0.4*cm) / 4
    card_h = 2.4 * cm
    card_y = PAGE_H - band_h - card_h - 1.2*cm
    card_x_start = MARGIN_L

    kpis = [
        ("CRITICAL", str(stats.get("critical", 0)), C_CRITICAL),
        ("HIGH",     str(stats.get("high", 0)),     C_HIGH),
        ("TOTAL",    str(stats.get("total", 0)),     C_BRAND2),
        ("SOURCES",  str(stats.get("sources", 0)),   colors.HexColor("#0369A1")),
    ]
    for i, (label, value, col) in enumerate(kpis):
        x = card_x_start + i * (card_w + 0.4*cm)
        # Card background
        canvas.setFillColor(C_LIGHT_BG)
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.roundRect(x, card_y, card_w, card_h, 4, fill=1, stroke=1)
        # Top accent
        canvas.setFillColor(col)
        canvas.roundRect(x, card_y + card_h - 4, card_w, 4, 2, fill=1, stroke=0)
        # Value
        canvas.setFont("Helvetica-Bold", 22)
        canvas.setFillColor(col)
        canvas.drawCentredString(x + card_w/2, card_y + 0.6*cm, value)
        # Label
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C_MUTED)
        canvas.drawCentredString(x + card_w/2, card_y + 0.22*cm, label)

    # Bottom meta
    meta_y = card_y - 1.2*cm
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(MARGIN_L, meta_y,
        "Sources : CISA Alerts · CERT-FR · CISA KEV · Project Zero  |  "
        "Enrichissement : CVE · IOCs · MITRE ATT&CK")

    canvas.restoreState()


# ── Mini bar chart (text-based, using Table) ──────────────────────────────────
def mini_bar_table(data: list[tuple], max_val: int, styles, bar_color=C_ACCENT):
    """data = list of (label, value). Renders as a simple table with text bars."""
    if not data: return None
    rows = []
    for label, val in data:
        pct = val / max_val if max_val else 0
        bar_len = max(1, int(pct * 30))
        bar = "█" * bar_len
        rows.append([
            Paragraph(san(short(label, 28)), styles["tbl_cell"]),
            Paragraph(f"<font color='#{bar_color.hexval()[2:]}'>{bar}</font>", styles["mono"]),
            Paragraph(f"<b>{val}</b>", styles["tbl_hdr"]),
        ])
    t = Table(rows, colWidths=[4.5*cm, 9.5*cm, 1.2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_LIGHT_BG),
        ("GRID", (0,0), (-1,-1), 0.3, C_BORDER),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_WHITE, C_ROW_ALT]),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    return t


# ── Section header helper ─────────────────────────────────────────────────────
def section_header(title: str, styles, number: str = "") -> list:
    """Returns a list of flowables forming a styled section header."""
    txt = f"{number}  {title}" if number else title
    return [
        HRFlowable(width="100%", thickness=2, color=C_BRAND, spaceAfter=4, spaceBefore=8),
        Paragraph(txt.upper(), styles["h1"]),
        Spacer(1, 4),
    ]


# ── Severity badge as paragraph ───────────────────────────────────────────────
def sev_para(sev: str, styles) -> Paragraph:
    s = (sev or "").lower()
    colors_map = {"critical": "#B91C1C", "high": "#C2410C", "medium": "#1D4ED8", "low": "#374151"}
    c = colors_map.get(s, "#374151")
    return Paragraph(
        f'<font color="white"><b> {sev.upper()} </b></font>',
        ParagraphStyle("_b", fontName="Helvetica-Bold", fontSize=8.5,
                       leading=12, textColor=colors.white,
                       backColor=colors.HexColor(c), alignment=TA_CENTER)
    )


# ── Main PDF builder ──────────────────────────────────────────────────────────
def build_pdf(output_path: Optional[str] = None, max_items: int = 20):
    styles = make_styles()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    report_title = "CTI Daily Report"

    if not output_path:
        base = os.path.join(os.getcwd(), "reports")
        os.makedirs(base, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H%M")
        output_path = os.path.join(base, f"cti_report_{ts}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN_L, rightMargin=MARGIN_R,
        topMargin=MARGIN_T, bottomMargin=MARGIN_B,
        title=report_title, author="cti-watch",
    )

    story = []

    with SessionLocal() as db:
        # ── Stats ──────────────────────────────────────────────────────────────
        total_enriched = db.query(EnrichedItem).count()
        total_critical = db.query(EnrichedItem).filter(EnrichedItem.severity=="critical").count()
        total_high     = db.query(EnrichedItem).filter(EnrichedItem.severity=="high").count()
        total_medium   = db.query(EnrichedItem).filter(EnrichedItem.severity=="medium").count()
        total_sources  = len(top_sources(db, limit=50))
        sev_30d        = severity_counts_last_days(db, days=30)
        trend          = weekly_trend(db, weeks=6)

        cover_stats = {
            "critical": total_critical, "high": total_high,
            "total": total_enriched, "sources": total_sources
        }

        # Items to report
        raw_items = (
            db.query(EnrichedItem)
            .filter(EnrichedItem.severity.in_(["high", "critical"]))
            .order_by(EnrichedItem.score.desc(), EnrichedItem.published_at.desc())
            .limit(max_items * 5)
            .all()
        )
        items = dedup_items(raw_items, max_items=max_items)

        # ── Cover page ─────────────────────────────────────────────────────────
        # We use a first-page callback to draw the cover
        story.append(Spacer(1, 8.5*cm))  # push content below cover band
        story.append(PageBreak())

        # ── Page 2 : Vue d'ensemble ─────────────────────────────────────────────
        story += section_header("Vue d'ensemble", styles, "01")

        # Summary stats table
        overview_data = [
            ["Indicateur", "30 derniers jours", "Total cumulé"],
            ["🔴 Critical",    str(sev_30d.get("critical",0)), str(total_critical)],
            ["🟠 High",        str(sev_30d.get("high",0)),     str(total_high)],
            ["🔵 Medium",      str(sev_30d.get("medium",0)),   str(total_medium)],
            ["Total enrichis", str(sum(sev_30d.values())),     str(total_enriched)],
            ["Sources actives","—",                             str(total_sources)],
        ]
        ov_t = Table(overview_data, colWidths=[6*cm, 4.5*cm, 4.5*cm])
        ov_t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_BRAND),
            ("TEXTCOLOR",  (0,0), (-1,0), C_WHITE),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("GRID",       (0,0), (-1,-1), 0.4, C_BORDER),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",(0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE, C_ROW_ALT]),
            ("FONTNAME",   (0,1), (-1,-1), "Helvetica"),
            # Critical row highlight
            ("BACKGROUND", (0,1), (-1,1), C_ROW_CRIT),
            # High row highlight
            ("BACKGROUND", (0,2), (-1,2), C_ROW_HIGH),
        ]))
        story.append(ov_t)
        story.append(Spacer(1, 10))

        # Weekly trend text bar
        if any(v > 0 for _, v in trend):
            story.append(Paragraph("Tendance hebdomadaire — items high/critical", styles["h2"]))
            story.append(Spacer(1, 4))
            max_trend = max(v for _, v in trend) or 1
            t = mini_bar_table(trend, max_val=max_trend, styles=styles, bar_color=C_HIGH)
            if t: story.append(t)
            story.append(Spacer(1, 10))

        # ── Patch Backlog ───────────────────────────────────────────────────────
        story += section_header("Patch Backlog", styles, "02")
        story.append(Paragraph(
            "CVEs issus de sources KEV ou d'items à exploitation active — à patcher en priorité.",
            styles["small"]))
        story.append(Spacer(1, 6))

        patch_rows = fetch_patch_rows(db, limit=20)
        if not patch_rows:
            story.append(Paragraph("Aucun élément dans le backlog.", styles["body"]))
        else:
            all_patch_cves = [r[0] for r in patch_rows]
            cve_ctx = get_cve_context(db, all_patch_cves)

            hdr = [
                Paragraph("CVE",     styles["tbl_hdr"]),
                Paragraph("CVSS",    styles["tbl_hdr"]),
                Paragraph("EPSS",    styles["tbl_hdr"]),
                Paragraph("Vendor",  styles["tbl_hdr"]),
                Paragraph("Produit", styles["tbl_hdr"]),
                Paragraph("Vu le",   styles["tbl_hdr"]),
            ]
            patch_data = [hdr]
            for cve, vendor, product, status, last_seen, raw_item_id in patch_rows:
                ctx = cve_ctx.get(cve, {})
                cvss_str = f"{ctx['cvss']:.1f}" if ctx.get("cvss") else "—"
                epss_str = f"{ctx['epss']*100:.1f}%" if ctx.get("epss") else "—"
                cvss_val = ctx.get("cvss") or 0
                cvss_color = C_CRITICAL if cvss_val >= 9 else (C_HIGH if cvss_val >= 7 else C_MEDIUM)
                patch_data.append([
                    Paragraph(f"<b>{san(cve)}</b>", styles["tbl_cell"]),
                    Paragraph(f'<font color="#{cvss_color.hexval()[2:]}"><b>{cvss_str}</b></font>', styles["tbl_cell"]),
                    Paragraph(epss_str, styles["tbl_cell"]),
                    Paragraph(san(short(vendor or "—", 18)), styles["tbl_cell"]),
                    Paragraph(san(short(product or "—", 22)), styles["tbl_cell"]),
                    Paragraph(str(last_seen)[:10] if last_seen else "—", styles["muted"]),
                ])
            pt = Table(patch_data, colWidths=[3.0*cm, 1.5*cm, 1.5*cm, 3.0*cm, 4.0*cm, 2.0*cm])
            pt.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), C_BRAND),
                ("TEXTCOLOR",  (0,0), (-1,0), C_WHITE),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 8.5),
                ("GRID",       (0,0), (-1,-1), 0.4, C_BORDER),
                ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE, C_ROW_ALT]),
            ]))
            story.append(pt)

        story.append(Spacer(1, 10))

        # ── Trends (MITRE + Vendors + Sources) ─────────────────────────────────
        story += section_header("Tendances & Statistiques", styles, "03")

        # MITRE
        story.append(Paragraph("Top techniques MITRE ATT&CK", styles["h2"]))
        tt = top_techniques(db, limit=8)
        if tt:
            max_n = max(n for *_, n in tt) or 1
            mitre_bar_data = [(f"{tid} — {short(name,30)}", n) for tid, name, tactic, n in tt]
            t = mini_bar_table(mitre_bar_data, max_val=max_n, styles=styles, bar_color=C_BRAND2)
            if t:
                story.append(t)
        else:
            story.append(Paragraph("Aucune technique MITRE trouvée.", styles["muted"]))
        story.append(Spacer(1, 8))

        # Vendors
        story.append(Paragraph("Vendors les plus impactés", styles["h2"]))
        tv = top_vendors(db, limit=8)
        if tv:
            max_n = max(n for _, n in tv) or 1
            t = mini_bar_table(tv, max_val=max_n, styles=styles, bar_color=C_HIGH)
            if t: story.append(t)
        else:
            story.append(Paragraph("Aucun vendor détecté.", styles["muted"]))
        story.append(Spacer(1, 8))

        # Sources
        story.append(Paragraph("Volume par source", styles["h2"]))
        tsrc = top_sources(db, limit=8)
        if tsrc:
            max_n = max(n for _, n in tsrc) or 1
            t = mini_bar_table(tsrc, max_val=max_n, styles=styles, bar_color=C_ACCENT)
            if t: story.append(t)
        story.append(Spacer(1, 8))

        story.append(PageBreak())

        # ── Quick overview table ────────────────────────────────────────────────
        story += section_header("Top Items — Vue rapide", styles, "04")
        story.append(Paragraph(
            f"{len(items)} items high/critical (dédupliqués, triés par score décroissant).",
            styles["small"]))
        story.append(Spacer(1, 6))

        quick_hdr = [
            Paragraph("#",       styles["tbl_hdr"]),
            Paragraph("Sév.",    styles["tbl_hdr"]),
            Paragraph("Score",   styles["tbl_hdr"]),
            Paragraph("Date",    styles["tbl_hdr"]),
            Paragraph("Source",  styles["tbl_hdr"]),
            Paragraph("Titre",   styles["tbl_hdr"]),
        ]
        quick_data = [quick_hdr]
        for it in items[:15]:
            quick_data.append([
                Paragraph(str(it.raw_item_id), styles["muted"]),
                sev_para(it.severity, styles),
                Paragraph(f"<b>{it.score:.1f}</b>", styles["tbl_cell"]),
                Paragraph(fmt_date(it.published_at), styles["muted"]),
                Paragraph(san(short(it.source_name or "—", 14)), styles["tbl_cell"]),
                Paragraph(san(short(it.title or "—", 70)), styles["tbl_cell"]),
            ])
        qt = Table(quick_data, colWidths=[1.0*cm, 1.8*cm, 1.4*cm, 2.3*cm, 2.5*cm, 6.5*cm])
        qt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_BRAND),
            ("TEXTCOLOR",  (0,0), (-1,0), C_WHITE),
            ("FONTSIZE",   (0,0), (-1,-1), 8.5),
            ("GRID",       (0,0), (-1,-1), 0.4, C_BORDER),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE, C_ROW_ALT]),
        ] + [
            ("BACKGROUND", (0, i+1), (-1, i+1), severity_row_color(it.severity))
            for i, it in enumerate(items[:15])
        ]))
        story.append(qt)
        story.append(PageBreak())

        # ── Detailed item pages ─────────────────────────────────────────────────
        story += section_header("Fiches détaillées", styles, "05")
        story.append(Paragraph(
            "Chaque fiche présente les IOCs actionnables, CVEs, mapping MITRE et recommandations.",
            styles["small"]))
        story.append(Spacer(1, 10))

        for idx, it in enumerate(items):
            sev = (it.severity or "low").lower()
            sev_col = severity_color(sev)
            sc = it.score or 0.0

            cves    = get_cves(db, it.raw_item_id)
            iocs    = get_iocs(db, it.raw_item_id)
            refs    = get_refs(db, it.raw_item_id)
            mitre   = get_mitre(db, it.raw_item_id)
            cve_ctx = get_cve_context(db, cves[:8])

            versions = parse_json_list(getattr(it,"versions",None))
            malware  = parse_json_list(getattr(it,"malware",None))
            actors   = parse_json_list(getattr(it,"threat_actors",None))

            ips      = cap(iocs["ip"],     10)
            domains  = cap(iocs["domain"], 10)
            ioc_urls = cap([clean_url(u) for u in iocs["url"]], 10)
            hashes   = cap(iocs["hash"],    6)
            ref_urls = cap(refs.get("url",[]), 8)
            cves_cap = cap(cves, 12)

            summary = executive_summary(it)

            block = []

            # ── Item header bar ──────────────────────────────────────────────
            header_color_hex = sev_col.hexval()[2:]
            item_hdr = Table([[
                Paragraph(f'<font color="white"><b>#{it.raw_item_id}</b></font>', styles["tbl_hdr"]),
                Paragraph(f'<font color="white"><b>{sev.upper()}</b></font>', styles["tbl_hdr"]),
                Paragraph(f'<font color="white">Score : {sc:.1f}</font>', styles["tbl_hdr"]),
                Paragraph(f'<font color="white">{san(it.source_name or "—")}</font>', styles["tbl_hdr"]),
                Paragraph(f'<font color="white">{fmt_date(it.published_at)}</font>', styles["tbl_hdr"]),
            ]], colWidths=[1.4*cm, 2.0*cm, 2.4*cm, 4.5*cm, 2.5*cm + (CONTENT_W - 12.8*cm)])
            item_hdr.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), sev_col),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1), 5),
                ("LEFTPADDING",(0,0), (-1,-1), 6),
                ("GRID",       (0,0), (-1,-1), 0, C_WHITE),
            ]))
            block.append(item_hdr)

            # Title
            block.append(Spacer(1, 6))
            block.append(Paragraph(san(it.title or "Sans titre"), styles["h2"]))

            # Meta line
            vendor  = san(getattr(it,"vendor","") or "")
            product = san(getattr(it,"product","") or "")
            meta_parts = []
            if vendor:   meta_parts.append(f"<b>Vendor :</b> {vendor}")
            if product:  meta_parts.append(f"<b>Produit :</b> {product}")
            if versions: meta_parts.append(f"<b>Versions :</b> {san(', '.join(versions[:6]))}")
            if meta_parts:
                block.append(Paragraph("  ·  ".join(meta_parts), styles["small"]))

            if actors:
                block.append(Paragraph(
                    f'<font color="#B91C1C"><b>Threat actors :</b></font> {san(", ".join(actors[:5]))}',
                    styles["small"]))
            if malware:
                block.append(Paragraph(
                    f'<font color="#C2410C"><b>Malware :</b></font> {san(", ".join(malware[:5]))}',
                    styles["small"]))

            # URL
            if it.url:
                block.append(Paragraph(
                    f'<font color="#64748B">🔗 {wrap_url(it.url, 90)}</font>',
                    styles["muted"]))

            # Summary box
            block.append(Spacer(1, 6))
            summ_tbl = Table([[Paragraph(f"<b>🔍 Analyse :</b> {san(summary)}", styles["body"])]],
                             colWidths=[CONTENT_W])
            summ_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), C_TAG_BG),
                ("LEFTPADDING",(0,0),(-1,-1), 10),
                ("RIGHTPADDING",(0,0),(-1,-1), 10),
                ("TOPPADDING", (0,0),(-1,-1), 7),
                ("BOTTOMPADDING",(0,0),(-1,-1), 7),
                ("LINECOLOR",  (0,0),(-1,-1), C_ACCENT),
                ("LINEBEFORE", (0,0),(0,-1), 3, C_ACCENT),
            ]))
            block.append(summ_tbl)
            block.append(Spacer(1, 6))

            # CVEs with CVSS
            if cves_cap:
                cve_parts = []
                for cve in cves_cap:
                    ctx = cve_ctx.get(cve, {})
                    cvss_v = ctx.get("cvss")
                    epss_v = ctx.get("epss")
                    if cvss_v is not None:
                        c = "#B91C1C" if cvss_v >= 9 else ("#C2410C" if cvss_v >= 7 else "#1D4ED8")
                        tag = f'<font color="{c}"><b>{cvss_v:.1f}</b></font>'
                        if epss_v: tag += f' <font color="#64748B">EPSS:{epss_v*100:.0f}%</font>'
                        cve_parts.append(f"<b>{san(cve)}</b> ({tag})")
                    else:
                        cve_parts.append(f"<b>{san(cve)}</b>")
                extra = f" <font color='#6B7280'>(+{len(cves)-len(cves_cap)} autres)</font>" if len(cves) > len(cves_cap) else ""
                block.append(Paragraph(
                    f"<b>CVEs :</b> " + "  ·  ".join(cve_parts) + extra, styles["small"]))
                block.append(Spacer(1, 4))

            # MITRE table
            if mitre:
                from app.mitre_rules import MITRE_DEFENSES
                mitre_hdr = [
                    Paragraph("ID", styles["tbl_hdr"]),
                    Paragraph("Technique", styles["tbl_hdr"]),
                    Paragraph("Tactique", styles["tbl_hdr"]),
                    Paragraph("Conf.", styles["tbl_hdr"]),
                    Paragraph("Recommandation défensive", styles["tbl_hdr"]),
                ]
                mitre_data = [mitre_hdr]
                for tid, name, tactic, conf, evidence in mitre[:6]:
                    defense = MITRE_DEFENSES.get(tid, "Appliquer les mitigations MITRE ATT&CK.")
                    mitre_data.append([
                        Paragraph(f"<b>{san(tid)}</b>", styles["mono"]),
                        Paragraph(san(short(name, 36)), styles["tbl_cell"]),
                        Paragraph(san(tactic), styles["muted"]),
                        Paragraph(f"{conf}%", styles["tbl_cell"]),
                        Paragraph(san(short(defense, 80)), styles["muted"]),
                    ])
                mt = Table(mitre_data, colWidths=[2.2*cm, 4.0*cm, 2.5*cm, 1.2*cm, 5.6*cm])
                mt.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), C_BRAND2),
                    ("TEXTCOLOR",  (0,0), (-1,0), C_WHITE),
                    ("FONTSIZE",   (0,0), (-1,-1), 8),
                    ("GRID",       (0,0), (-1,-1), 0.3, C_BORDER),
                    ("VALIGN",     (0,0), (-1,-1), "TOP"),
                    ("TOPPADDING", (0,0), (-1,-1), 3),
                    ("BOTTOMPADDING",(0,0),(-1,-1), 3),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE, C_ROW_ALT]),
                ]))
                block.append(mt)
                block.append(Spacer(1, 6))

            # IOCs
            has_iocs = any([ips, domains, ioc_urls, hashes])
            if has_iocs:
                ioc_data = []
                if ips:      ioc_data.append([Paragraph("<b>IPs</b>",     styles["label"]),
                                               Paragraph(san(", ".join(ips)), styles["mono"])])
                if domains:  ioc_data.append([Paragraph("<b>Domaines</b>",styles["label"]),
                                               Paragraph(san(", ".join(domains)), styles["mono"])])
                if hashes:   ioc_data.append([Paragraph("<b>Hashes</b>",  styles["label"]),
                                               Paragraph("<br/>".join(san(h) for h in hashes), styles["mono"])])
                if ioc_urls: ioc_data.append([
                    Paragraph("<b>URLs IOC</b>", styles["label"]),
                    Paragraph("<br/>".join(wrap_url(u) for u in ioc_urls), styles["mono"])
                ])
                ioc_t = Table(ioc_data, colWidths=[2.2*cm, CONTENT_W - 2.2*cm])
                ioc_t.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (0,-1), C_LIGHT_BG),
                    ("BACKGROUND", (1,0), (1,-1), C_WHITE),
                    ("GRID", (0,0), (-1,-1), 0.4, C_BORDER),
                    ("VALIGN", (0,0), (-1,-1), "TOP"),
                    ("TOPPADDING", (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                    ("LEFTPADDING", (0,0), (-1,-1), 6),
                ]))
                block.append(ioc_t)
                block.append(Spacer(1, 4))

            # References
            if ref_urls:
                ref_lines = "<br/>".join(
                    f'<font color="#0369A1">{wrap_url(clean_url(u))}</font>'
                    for u in ref_urls
                )
                block.append(Paragraph(f"<b>Références :</b><br/>{ref_lines}", styles["muted"]))
                block.append(Spacer(1, 4))

            # Excerpt
            excerpt = short(" ".join((it.content_text or "").split()), 500)
            if excerpt:
                block.append(Paragraph(
                    f'<font color="#64748B"><i>{san(excerpt)}</i></font>', styles["muted"]))

            # Separator
            block.append(Spacer(1, 12))
            block.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER,
                                     spaceBefore=2, spaceAfter=10))

            story.append(KeepTogether(block))

    # ── Build ──────────────────────────────────────────────────────────────────
    def on_first_page(canvas, doc):
        draw_cover(canvas, doc, generated_at, cover_stats)
        # No header/footer on cover

    def on_later_pages(canvas, doc):
        draw_header_footer(canvas, doc, report_title, generated_at)

    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f"[OK] PDF generated: {output_path}")
    return output_path


if __name__ == "__main__":
    build_pdf(output_path=None, max_items=20)
