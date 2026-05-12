"""
report_generator.py — Compliance Report PDF Generator
Uses ReportLab Platypus for structured, multi-page PDF output.
Place in: server/services/report_generator.py
"""
from __future__ import annotations
import io
from datetime import datetime
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.platypus import Flowable
import json as _json
import os as _os

def _load_plain_lookup():
    here  = _os.path.dirname(_os.path.abspath(__file__))
    paths = [
        _os.path.normpath(_os.path.join(here, "..", "..", "rules", "controls.json")),
        _os.path.normpath(_os.path.join(here, "..", "rules", "controls.json")),
        _os.path.normpath(_os.path.join(here, "..", "..", "..", "rules", "controls.json")),
    ]
    for path in paths:
        if _os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                data = _json.load(f)
            return {
                c["control_id"]: {
                    "plain_reason":         c.get("plain_reason", {}),
                    "plain_recommendation": c.get("plain_recommendation", {}),
                }
                for c in data.get("controls", []) if c.get("control_id")
            }
    return {}

_PLAIN_LOOKUP = _load_plain_lookup()

def _plain_rec(control_id, status):
    return _PLAIN_LOOKUP.get(control_id, {}).get("plain_recommendation", {}).get(status)

def _plain_rsn(control_id, status):
    return _PLAIN_LOOKUP.get(control_id, {}).get("plain_reason", {}).get(status)

# ── Colour palette (matches dashboard) ───────────────────────────────────────
_BLUE       = colors.HexColor("#2563eb")
_BLUE_LIGHT = colors.HexColor("#eff6ff")
_GREEN      = colors.HexColor("#16a34a")
_GREEN_LIGHT= colors.HexColor("#f0fdf4")
_AMBER      = colors.HexColor("#ca8a04")
_AMBER_LIGHT= colors.HexColor("#fefce8")
_RED        = colors.HexColor("#dc2626")
_RED_LIGHT  = colors.HexColor("#fef2f2")
_ORANGE     = colors.HexColor("#ea580c")
_PURPLE     = colors.HexColor("#7c3aed")
_GREY       = colors.HexColor("#6b7280")
_GREY_LIGHT = colors.HexColor("#f9fafb")
_BORDER     = colors.HexColor("#e5e9f2")
_TEXT       = colors.HexColor("#374151")
_TEXT_DARK  = colors.HexColor("#111827")
_WHITE      = colors.white

# ── Risk palette ──────────────────────────────────────────────────────────────
_RISK_COLORS = {
    "severe":   (_RED,    _RED_LIGHT),
    "critical": (_ORANGE, colors.HexColor("#fff7ed")),
    "high":     (_AMBER,  _AMBER_LIGHT),
    "moderate": (_PURPLE, colors.HexColor("#f5f3ff")),
    "low":      (_GREEN,  _GREEN_LIGHT),
    "unknown":  (_GREY,   _GREY_LIGHT),
}

# ── Page dimensions ───────────────────────────────────────────────────────────
W, H = A4
MARGIN = 18 * mm


# ── Styles ────────────────────────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    s = {}

    def add(name, **kwargs):
        s[name] = ParagraphStyle(name, **kwargs)

    add("ReportTitle",
        fontSize=22, fontName="Helvetica-Bold", textColor=_TEXT_DARK,
        spaceAfter=4, leading=26)

    add("ReportSubtitle",
        fontSize=10, fontName="Helvetica", textColor=_GREY,
        spaceAfter=2, leading=14)

    add("SectionHeader",
        fontSize=12, fontName="Helvetica-Bold", textColor=_BLUE,
        spaceBefore=12, spaceAfter=6, leading=16)

    add("BodyText",
        fontSize=9, fontName="Helvetica", textColor=_TEXT,
        spaceAfter=4, leading=13)

    add("SmallText",
        fontSize=8, fontName="Helvetica", textColor=_GREY,
        spaceAfter=2, leading=11)

    add("BoldText",
        fontSize=9, fontName="Helvetica-Bold", textColor=_TEXT_DARK,
        spaceAfter=4, leading=13)

    add("RiskReason",
        fontSize=8, fontName="Helvetica", textColor=_TEXT,
        spaceAfter=3, leading=12)

    add("Recommendation",
        fontSize=8, fontName="Helvetica-Oblique", textColor=_GREEN.clone(),
        spaceAfter=3, leading=12)

    add("MetaLabel",
        fontSize=8, fontName="Helvetica-Bold", textColor=_GREY,
        spaceAfter=1, leading=11)

    add("MetaValue",
        fontSize=9, fontName="Helvetica", textColor=_TEXT_DARK,
        spaceAfter=1, leading=13)

    return s


# ── Helper: coloured text in a table cell ─────────────────────────────────────
def _p(text: str, style, color=None) -> Paragraph:
    if color:
        text = f'<font color="{color.hexval() if hasattr(color,"hexval") else color}">{text}</font>'
    return Paragraph(str(text), style)


def _risk_color(rk: str):
    return _RISK_COLORS.get((rk or "").lower(), _RISK_COLORS["unknown"])


def _score_rk(score) -> str:
    try:
        s = float(score)
    except Exception:
        return "unknown"
    if s >= 80: return "severe"
    if s >= 60: return "critical"
    if s >= 40: return "high"
    if s >= 20: return "moderate"
    return "low"


def _compliance_rk(comp) -> str:
    try:
        c = float(comp)
    except Exception:
        return "unknown"
    if c < 20:  return "severe"
    if c < 40:  return "critical"
    if c < 70:  return "high"
    if c < 90:  return "moderate"
    return "low"


# ── Coloured accent bar (horizontal rule) ─────────────────────────────────────
class _ColorBar(Flowable):
    def __init__(self, width, height, color):
        super().__init__()
        self.width  = width
        self.height = height
        self._color = color

    def draw(self):
        self.canv.setFillColor(self._color)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


# ── Page header / footer callback ─────────────────────────────────────────────
def _make_page_template(hostname: str, generated_at: str):
    def on_page(canvas, doc):
        canvas.saveState()
        # Top accent bar
        canvas.setFillColor(_BLUE)
        canvas.rect(0, H - 8 * mm, W, 8 * mm, fill=1, stroke=0)
        # Header text
        canvas.setFillColor(_WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(MARGIN, H - 5.5 * mm, "Compliance Audit Report")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(W - MARGIN, H - 5.5 * mm, hostname)
        # Footer line
        canvas.setStrokeColor(_BORDER)
        canvas.line(MARGIN, 12 * mm, W - MARGIN, 12 * mm)
        canvas.setFillColor(_GREY)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(MARGIN, 8 * mm, f"Generated: {generated_at}")
        canvas.drawRightString(W - MARGIN, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()
    return on_page


# ── Main generator ────────────────────────────────────────────────────────────
def generate_report(ev: dict) -> bytes:
    """
    Generate a compliance report PDF for one host evaluation.
    Returns PDF bytes.
    """
    S = _build_styles()
    buf = io.BytesIO()

    hostname   = ev.get("hostname", "Unknown Host")
    ip         = ev.get("ip_address", "—")
    os_ver     = ev.get("os_version", ev.get("os_type", "—"))
    platform   = ev.get("platform", "—")
    audit_id   = ev.get("audit_id", "—")
    received   = ev.get("received_at", "")
    generated  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Format received_at
    try:
        dt = datetime.fromisoformat(str(received).replace("Z", "+00:00"))
        received_fmt = dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        received_fmt = str(received)

    scores      = ev.get("scores", {})
    summary     = scores.get("summary", {})
    compliance  = scores.get("compliance", {})
    domain_data = scores.get("domains", {})
    top_risks   = ev.get("top_risks") or scores.get("top_risks", [])
    results     = ev.get("results", [])

    comp_score  = summary.get("compliance_score")
    risk_score  = summary.get("risk_score")
    risk_level  = summary.get("risk_level", "Unknown")
    earned      = compliance.get("earned_points", "—")
    max_pts     = compliance.get("max_points", "—")

    comp_rk  = _compliance_rk(comp_score)
    risk_rk  = _score_rk(risk_score)
    comp_color, comp_bg = _risk_color(comp_rk)
    risk_color, risk_bg = _risk_color(risk_rk)

    on_page = _make_page_template(hostname, generated)

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=22 * mm, bottomMargin=20 * mm,
        title=f"Compliance Report — {hostname}",
        author="Automated Compliance System",
    )

    story = []

    # ── Cover section ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 4 * mm))
    story.append(_ColorBar(W - 2 * MARGIN, 3, _BLUE))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("ISO/IEC 27001 &amp; PDPA Compliance Audit Report", S["ReportTitle"]))
    story.append(Paragraph(f"Host: {hostname}  ·  Audit #{audit_id}  ·  {received_fmt}", S["ReportSubtitle"]))
    story.append(Spacer(1, 4 * mm))

    # Host identity table
    host_data = [
        ["Hostname",    hostname,    "IP Address",   ip],
        ["Platform",    platform,    "OS Version",   os_ver[:60]],
        ["Audit ID",    str(audit_id), "Received",   received_fmt],
    ]
    host_tbl = Table(host_data, colWidths=[28*mm, 52*mm, 28*mm, 52*mm])
    host_tbl.setStyle(TableStyle([
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (2,0), (2,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (0,0), (0,-1), _GREY),
        ("TEXTCOLOR",   (2,0), (2,-1), _GREY),
        ("TEXTCOLOR",   (1,0), (1,-1), _TEXT_DARK),
        ("TEXTCOLOR",   (3,0), (3,-1), _TEXT_DARK),
        ("BACKGROUND",  (0,0), (-1,-1), _GREY_LIGHT),
        ("GRID",        (0,0), (-1,-1), 0.5, _BORDER),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [_GREY_LIGHT, _WHITE]),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(host_tbl)
    story.append(Spacer(1, 6 * mm))

    # ── Score summary cards ───────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 3 * mm))

    comp_val  = f"{comp_score:.0f}%" if comp_score is not None else "—"
    risk_val  = f"{risk_score:.1f}"  if risk_score  is not None else "—"
    pts_val   = f"{earned} / {max_pts}"

    # Row 0 = bold black labels (top), Row 1 = coloured values (bottom)
    score_data = [
        [
            Paragraph("<b>Compliance Score</b>", S["BoldText"]),
            Paragraph("<b>Risk Score</b>",       S["BoldText"]),
            Paragraph("<b>Points Earned</b>",    S["BoldText"]),
            Paragraph("<b>Risk Level</b>",       S["BoldText"]),
        ],
        [
            Paragraph(f'<font size="18"><b><font color="{comp_color.hexval()}">{comp_val}</font></b></font>', S["BodyText"]),
            Paragraph(f'<font size="18"><b><font color="{risk_color.hexval()}">{risk_val}</font></b></font>', S["BodyText"]),
            Paragraph(f'<font size="18"><b><font color="{_BLUE.hexval()}">{pts_val}</font></b></font>', S["BodyText"]),
            Paragraph(f'<font size="12"><b><font color="{risk_color.hexval()}">{risk_level}</font></b></font>', S["BodyText"]),
        ],
    ]
    score_tbl = Table(score_data, colWidths=[(W - 2*MARGIN)/4]*4)
    score_tbl.setStyle(TableStyle([
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND",    (0,0), (-1,0),  _WHITE),
        ("BACKGROUND",    (0,1), (-1,1),  _BLUE_LIGHT),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, _BORDER),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0),  9),
        ("TEXTCOLOR",     (0,0), (-1,0),  _TEXT_DARK),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 6 * mm))

    # ── Domain breakdown ──────────────────────────────────────────────────────
    DOMAIN_ORDER = [
        "Access Control",
        "Logging & Monitoring",
        "Asset & Configuration Management",
        "Cryptography",
        "Backup & Recovery",
    ]

    if domain_data:
        story.append(Paragraph("Domain Compliance Breakdown", S["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
        story.append(Spacer(1, 2 * mm))

        _white_hdr = ParagraphStyle("WhiteHdr", fontSize=8, fontName="Helvetica-Bold",
                                    textColor=_WHITE, leading=11)
        dom_header = [
            Paragraph("Domain",      _white_hdr),
            Paragraph("Compliance",  _white_hdr),
            Paragraph("Risk Score",  _white_hdr),
            Paragraph("Risk Level",  _white_hdr),
            Paragraph("Controls",    _white_hdr),
            Paragraph("High Fails",  _white_hdr),
        ]
        dom_rows = [dom_header]

        for dname in DOMAIN_ORDER:
            if dname not in domain_data:
                continue
            info      = domain_data[dname]
            d_comp    = info.get("compliance_score")
            d_risk    = info.get("risk_score", 0)
            d_level   = info.get("risk_level", "—")
            d_count   = info.get("control_count", "—")
            d_hfail   = info.get("high_fail_count", 0)
            d_esc     = info.get("domain_escalated", False)

            crk = _compliance_rk(d_comp)
            cc, _ = _risk_color(crk)
            rrk = _score_rk(d_risk)
            rc, _ = _risk_color(rrk)

            comp_str = f"{d_comp:.0f}%" if d_comp is not None else "—"
            esc_note = " [ESCALATED]" if d_esc else ""
            dom_rows.append([
                Paragraph(dname, S["BodyText"]),
                Paragraph(f'<font color="{cc.hexval()}"><b>{comp_str}</b></font>', S["BodyText"]),
                Paragraph(f'<font color="{rc.hexval()}"><b>{d_risk:.1f}</b></font>', S["BodyText"]),
                Paragraph(f'<font color="{rc.hexval()}">{d_level}{esc_note}</font>', S["BodyText"]),
                Paragraph(str(d_count), S["BodyText"]),
                Paragraph(
                    f'<font color="{_RED.hexval()}"><b>{d_hfail}</b></font>'
                    if d_hfail > 0 else str(d_hfail),
                    S["BodyText"]
                ),
            ])

        col_w = [55*mm, 25*mm, 25*mm, 30*mm, 18*mm, 18*mm]
        dom_tbl = Table(dom_rows, colWidths=col_w, repeatRows=1)
        dom_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), _BLUE),
            ("TEXTCOLOR",   (0,0), (-1,0), _WHITE),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.5, _BORDER),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [_WHITE, _GREY_LIGHT]),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",  (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("ALIGN",       (1,0), (-1,-1), "CENTER"),
        ]))
        story.append(dom_tbl)
        story.append(Spacer(1, 6 * mm))

    # ── Top risks ─────────────────────────────────────────────────────────────
    top_risks_sorted = sorted(top_risks, key=lambda x: x.get("residual_risk", 0), reverse=True)[:5]

    if top_risks_sorted:
        story.append(Paragraph("Top 5 Priority Risks", S["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
        story.append(Spacer(1, 2 * mm))

        for i, r in enumerate(top_risks_sorted):
            sev    = (r.get("severity") or "").lower()
            rk     = sev if sev in _RISK_COLORS else "unknown"
            rc, rb = _risk_color(rk)
            res_risk = r.get("residual_risk", 0)
            title    = r.get("title", r.get("control_id", ""))
            cid      = r.get("control_id", "")
            domain   = r.get("domain", "")
            reason   = r.get("reason", "")
            rec      = r.get("recommendation", "")

            risk_block = [
                [
                    Paragraph(
                        f'<font color="{rc.hexval()}"><b>#{i+1}  {cid}</b></font>',
                        S["BodyText"]
                    ),
                    Paragraph(title, S["BoldText"]),
                    Paragraph(
                        f'<font color="{rc.hexval()}"><b>Risk: {res_risk:.1f}</b></font>',
                        S["BodyText"]
                    ),
                ],
                [
                    Paragraph(domain, S["SmallText"]),
                    Paragraph(reason, S["RiskReason"]),
                    Paragraph(
                        f'<font color="{_GREY.hexval()}">{sev.capitalize()} severity</font>',
                        S["SmallText"]
                    ),
                ],
                [
                    Paragraph("Recommendation:", S["MetaLabel"]),
                    Paragraph(rec, S["Recommendation"]),
                    Paragraph("", S["SmallText"]),
                ],
            ]

            col_w = [30*mm, 95*mm, 30*mm]
            risk_tbl = Table(risk_block, colWidths=col_w)
            risk_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), rb),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("RIGHTPADDING",  (0,0), (-1,-1), 6),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
                ("LINEAFTER",     (0,0), (0,-1), 1, rc),
                ("SPAN",          (1,0), (1,0)),
            ]))
            story.append(KeepTogether([risk_tbl, Spacer(1, 3*mm)]))

        story.append(Spacer(1, 4 * mm))

    # ── Control results table ─────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Control Evaluation Results", S["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 2 * mm))

    STATUS_COLORS = {
        "PASS":    (_GREEN, _GREEN_LIGHT),
        "FAIL":    (_RED,   _RED_LIGHT),
        "PARTIAL": (_AMBER, _AMBER_LIGHT),
        "UNKNOWN": (_GREY,  _GREY_LIGHT),
    }

    _white_hdr2 = ParagraphStyle("WhiteHdr2", fontSize=8, fontName="Helvetica-Bold",
                                textColor=_WHITE, leading=11)
    ctrl_header = [
        Paragraph("ID",            _white_hdr2),
        Paragraph("Title",         _white_hdr2),
        Paragraph("Domain",        _white_hdr2),
        Paragraph("Status",        _white_hdr2),
        Paragraph("Severity",      _white_hdr2),
        Paragraph("Residual Risk", _white_hdr2),
        Paragraph("Recommendation",_white_hdr2),
    ]
    ctrl_rows = [ctrl_header]

    results_sorted = sorted(
        results,
        key=lambda r: (
            -{"high": 3, "medium": 2, "low": 1}.get((r.get("severity") or "").lower(), 0),
            -(r.get("risk", {}).get("calculation", {}).get("residual_risk_final", 0)),
        )
    )

    for r in results_sorted:
        cid    = r.get("control_id", "")
        title  = r.get("title", "")
        domain = r.get("domain", "")
        status = (r.get("status") or "").upper()
        sev    = (r.get("severity") or "").capitalize()
        res    = r.get("risk", {}).get("calculation", {}).get("residual_risk_final", 0)
        rec    = r.get("recommendation", "")
        sc, sb = STATUS_COLORS.get(status, STATUS_COLORS["UNKNOWN"])

        _rec_text = _plain_rec(cid, status) or rec
        ctrl_rows.append([
            Paragraph(f'<font size="7"><b><font color="{_BLUE.hexval()}">{cid}</font></b></font>', S["BodyText"]),
            Paragraph(title, S["BodyText"]),
            Paragraph(domain, S["SmallText"]),
            Paragraph(f'<font color="{sc.hexval()}"><b>{status}</b></font>', S["BodyText"]),
            Paragraph(sev, S["SmallText"]),
            Paragraph(
                f'<font color="{_RED.hexval() if res > 15 else _AMBER.hexval() if res > 5 else _GREEN.hexval()}"><b>{res:.1f}</b></font>',
                S["BodyText"]
            ),
            Paragraph(_rec_text, S["SmallText"]),
        ])

    ctrl_col_w = [18*mm, 30*mm, 25*mm, 13*mm, 13*mm, 14*mm, 55*mm]
    ctrl_tbl = Table(ctrl_rows, colWidths=ctrl_col_w, repeatRows=1)
    ctrl_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), _BLUE),
        ("TEXTCOLOR",    (0,0), (-1,0), _WHITE),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 7.5),
        ("GRID",         (0,0), (-1,-1), 0.4, _BORDER),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [_WHITE, _GREY_LIGHT]),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",   (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",(0,0), (-1,-1), 3),
        ("LEFTPADDING",  (0,0), (-1,-1), 4),
        ("ALIGN",        (3,0), (5,-1), "CENTER"),
    ]))
    story.append(ctrl_tbl)
    story.append(Spacer(1, 6 * mm))

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        f"This report was automatically generated by the ISO/IEC 27001 &amp; PDPA Compliance "
        f"Monitoring System on {generated}. Results are based on automated evidence collection "
        f"and should be reviewed by a qualified security professional.",
        S["SmallText"]
    ))

    # Build PDF
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf.read()