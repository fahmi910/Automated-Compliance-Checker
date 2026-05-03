"""helpers.py — API wrappers, data utilities, reusable Dash components (light theme)."""
from __future__ import annotations
import os
import requests
from datetime import datetime
from dash import html
import plotly.graph_objects as go

# ── API ───────────────────────────────────────────────────────────────────────

def get_base_url(store_val=None):
    return (store_val or os.environ.get("AUDIT_API_BASE_URL","http://127.0.0.1:8000")).rstrip("/")

def api_get(path, base, params=None):
    r = requests.get(f"{base}{path}", params=params, timeout=8)
    r.raise_for_status()
    return r.json()

def health(base):                    return api_get("/health", base)
def list_hosts(base):                return api_get("/hosts", base)
def latest_evaluated(base, host):    return api_get("/audits/latest/evaluated", base, {"hostname": host})
def list_audits(base, host, limit=20): return api_get("/audits", base, {"hostname": host, "limit": limit})
def evaluated_audit(base, audit_id): return api_get(f"/audits/{audit_id}/evaluated", base)

# ── Data helpers ──────────────────────────────────────────────────────────────

def fmt_dt(s):
    if not s: return "—"
    try:
        dt = datetime.fromisoformat(str(s).replace("Z","+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except: return str(s)

def severity_rank(sev):
    return {"high":3,"medium":2,"low":1}.get((sev or "").lower(), 0)

# Light-theme risk palette
RISK_MAP = {
    "severe":   {"color":"#dc2626","bg":"#fef2f2","border":"#fca5a5","row":"#fff5f5","text":"#991b1b","icon":"🔴"},
    "critical": {"color":"#ea580c","bg":"#fff7ed","border":"#fdba74","row":"#fffbf5","text":"#9a3412","icon":"🟠"},
    "high":     {"color":"#ca8a04","bg":"#fefce8","border":"#fde047","row":"#fffef5","text":"#854d0e","icon":"🟡"},
    "moderate": {"color":"#7c3aed","bg":"#f5f3ff","border":"#c4b5fd","row":"#faf8ff","text":"#5b21b6","icon":"🟣"},
    "low":      {"color":"#16a34a","bg":"#f0fdf4","border":"#86efac","row":"#f7fff9","text":"#166534","icon":"🟢"},
    "unknown":  {"color":"#6b7280","bg":"#f9fafb","border":"#d1d5db","row":"#fafafa","text":"#374151","icon":"⚪"},
}

def risk_key(score_val) -> str:
    try: s = float(score_val)
    except: return "unknown"
    if s >= 80: return "severe"
    if s >= 60: return "critical"
    if s >= 40: return "high"
    if s >= 20: return "moderate"
    return "low"

def sev_key(sev: str) -> str:
    return {"high":"high","medium":"high","low":"low"}.get((sev or "").lower(), "unknown")

def get_score_summary(ev: dict) -> dict:
    if not ev: return {}
    scores     = ev.get("scores", {})
    summary    = scores.get("summary", {})
    compliance = scores.get("compliance", {})
    domains    = scores.get("domains", {})
    return {
        "compliance_score": summary.get("compliance_score"),
        "risk_score":       summary.get("risk_score"),
        "risk_level":       summary.get("risk_level"),
        "earned_points":    compliance.get("earned_points"),
        "max_points":       compliance.get("max_points"),
        "domain_scores":    domains,
        "top_risks":        ev.get("top_risks") or scores.get("top_risks", []),
    }

def normalize_controls(results: list) -> list[dict]:
    if not results: return []
    out = []
    for r in results:
        def rr(row=r):
            try: return row.get("risk",{}).get("calculation",{}).get("residual_risk_final",0.0)
            except: return 0.0
        ds  = r.get("decision_source")
        pri = r.get("primary_evidence") or {}
        sec = r.get("secondary_evidence") or {}
        ev  = pri if ds=="primary" else sec if ds=="secondary" else pri or sec
        parts = []
        if r.get("reason"): parts.append(str(r["reason"]))
        if ev.get("value") is not None: parts.append(f"Value: {ev['value']}")
        if ev.get("source"): parts.append(f"Source: {ev['source']}")
        if ev.get("raw_snippet"): parts.append(f"Evidence: {ev['raw_snippet']}")
        out.append({
            "control_id":    r.get("control_id",""),
            "title":         r.get("title",""),
            "domain":        r.get("domain",""),
            "status":        (r.get("status") or "").upper(),
            "severity":      (r.get("severity") or "").lower(),
            "residual_risk": rr(),
            "evidence":      " | ".join(parts),
            "recommendation":r.get("recommendation",""),
        })
    return out


# ── Reusable UI components ─────────────────────────────────────────────────────

def kpi_card(label: str, value, accent: str = "#3b82f6", subtitle: str = ""):
    return html.Div([
        html.Div(className="kpi-bar", style={"background": accent}),
        html.Div(str(value), className="kpi-value"),
        html.Div(label, className="kpi-label"),
        html.Div(subtitle, className="kpi-subtitle") if subtitle else None,
    ], className="kpi-card")


def risk_badge(key: str):
    m = RISK_MAP.get(key, RISK_MAP["unknown"])
    return html.Span(
        f"{m['icon']}  {key.capitalize()}",
        style={
            "background":   m["bg"],
            "color":        m["text"],
            "border":       f"1px solid {m['border']}",
            "borderRadius": "999px",
            "padding":      "3px 11px",
            "fontSize":     "0.72rem",
            "fontWeight":   "700",
            "letterSpacing":"0.03em",
            "whiteSpace":   "nowrap",
            "display":      "inline-flex",
            "alignItems":   "center",
            "gap":          "5px",
        }
    )


def sev_badge(sev: str):
    return risk_badge(sev_key(sev))


def status_badge(status: str):
    s  = (status or "").upper()
    ok = s == "PASS"
    return html.Span(s or "—", style={
        "background":   "#f0fdf4" if ok else "#fef2f2",
        "color":        "#166534" if ok else "#991b1b",
        "border":       "1px solid #86efac" if ok else "1px solid #fca5a5",
        "borderRadius": "999px",
        "padding":      "3px 10px",
        "fontSize":     "0.72rem",
        "fontWeight":   "700",
        "letterSpacing":"0.03em",
    })


def section_header(text: str, icon: str = ""):
    return html.Div([
        html.Span(icon + "  " if icon else "", style={"opacity":"0.6"}),
        html.Span(text),
        html.Div(className="sh-line"),
    ], className="section-header")


def data_table(columns: list[str], rows: list[dict],
               row_risk_key_col: str = None,
               wrap_cols: set = None) -> html.Div:
    wrap_cols = wrap_cols or set()
    header = html.Tr([html.Th(c, className="dt-th") for c in columns], className="dt-header-row")
    body_rows = []
    for row in rows:
        rk  = row.get(row_risk_key_col, "unknown") if row_risk_key_col else None
        bg  = RISK_MAP.get(rk, RISK_MAP["unknown"])["row"] if rk else "#ffffff"
        lbr = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"] if rk else "transparent"
        tds = []
        for c in columns:
            val = row.get(c, "—")
            td_style = {"maxWidth":"280px","whiteSpace":"normal","wordBreak":"break-word"} \
                       if c in wrap_cols else {}
            tds.append(html.Td(val if val is not None else "—", className="dt-td", style=td_style))
        body_rows.append(html.Tr(tds, className="dt-row", style={
            "background": bg,
            "borderLeft": f"3px solid {lbr}" if rk else "3px solid transparent",
        }))
    return html.Div(
        html.Table([html.Thead(header), html.Tbody(body_rows)], className="data-table"),
        className="data-table-wrap",
    )


def empty_state(msg="No data available."):
    return html.Div([
        html.Div("📭", style={"fontSize":"2.5rem","marginBottom":"0.5rem"}),
        html.Div(msg, style={"color":"#9ca3af","fontSize":"0.9rem"}),
    ], style={"textAlign":"center","padding":"3rem 1rem"})


def error_banner(msg: str):
    return html.Div([html.Span("⚠  "), msg], style={
        "background":"#fef2f2","border":"1px solid #fca5a5","color":"#991b1b",
        "borderRadius":"8px","padding":"0.85rem 1.2rem",
        "fontSize":"0.875rem","marginBottom":"1rem",
    })


# ── Charts ─────────────────────────────────────────────────────────────────────

def make_gauge(score, risk_k: str) -> go.Figure:
    m = RISK_MAP.get(risk_k, RISK_MAP["unknown"])
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score if score is not None else 0,
        number={"suffix":"%","font":{"size":38,"color":m["color"],"family":"DM Sans, sans-serif"}},
        gauge={
            "axis":      {"range":[0,100],"tickcolor":"#d1d5db","tickfont":{"color":"#9ca3af","size":10}},
            "bar":       {"color":m["color"],"thickness":0.22},
            "bgcolor":   "#f9fafb",
            "borderwidth":0,
            "steps":[
                {"range":[0, 20], "color":"rgba(22,163,74,0.08)"},
                {"range":[20,40], "color":"rgba(124,58,237,0.08)"},
                {"range":[40,60], "color":"rgba(202,138,4,0.08)"},
                {"range":[60,80], "color":"rgba(234,88,12,0.08)"},
                {"range":[80,100],"color":"rgba(220,38,38,0.08)"},
            ],
            "threshold":{"line":{"color":m["color"],"width":3},"thickness":0.8,"value":score or 0},
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=20,r=20,t=20,b=10), height=200,
        font={"family":"DM Sans, sans-serif"},
    )
    return fig


def make_bar_chart(labels, values, colors=None) -> go.Figure:
    bar_colors = colors or [RISK_MAP.get(risk_key(v), RISK_MAP["unknown"])["color"] for v in values]
    fig = go.Figure(go.Bar(
        x=labels, y=values, marker_color=bar_colors, marker_line_width=0,
        hovertemplate="<b>%{x}</b><br>Score: %{y:.1f}<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10,r=10,t=10,b=80), height=260,
        xaxis=dict(tickfont={"color":"#6b7280","size":11},gridcolor="rgba(0,0,0,0)",tickangle=-30),
        yaxis=dict(tickfont={"color":"#6b7280","size":11},gridcolor="#f3f4f6",range=[0,100]),
        bargap=0.35, font={"family":"DM Sans, sans-serif"},
    )
    return fig


def make_line_chart(x, y, name="", color="#3b82f6") -> go.Figure:
    fig = go.Figure()
    rgb = f"{int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)}"
    fig.add_trace(go.Scatter(
        x=x, y=y, name=name, mode="lines+markers",
        line=dict(color=color, width=2.5, shape="spline"),
        marker=dict(size=6, color=color, line=dict(color="white", width=2)),
        fill="tozeroy", fillcolor=f"rgba({rgb},0.07)",
        hovertemplate="%{x}<br><b>%{y:.1f}</b><extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#ffffff",
        margin=dict(l=10,r=10,t=10,b=10), height=240,
        xaxis=dict(tickfont={"color":"#9ca3af","size":10},showgrid=False,linecolor="#e5e7eb"),
        yaxis=dict(tickfont={"color":"#9ca3af","size":10},gridcolor="#f3f4f6",linecolor="#e5e7eb"),
        showlegend=False, font={"family":"DM Sans, sans-serif"},
        hovermode="x unified",
    )
    return fig
