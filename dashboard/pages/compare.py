import dash
from dash import html, dcc, callback, Input, Output, State
from helpers import (
    get_base_url, list_hosts, list_audits, evaluated_audit, get_score_summary,
    normalize_controls, fmt_dt, risk_key,
    kpi_card, section_header, data_table, risk_badge, status_badge, sev_badge,
    empty_state, error_banner,
)

dash.register_page(__name__, path="/compare", name="Compare")

layout = html.Div([
    html.Div([
        html.H1("Compare Audits"),
        html.P("Diff two snapshots to identify improvements and regressions.", className="page-subtitle"),
    ], className="page-header"),

    html.Div([
        html.Div([
            html.Label("Host", className="filter-label"),
            dcc.Dropdown(id="cmp-host", placeholder="Loading…", className="dash-dropdown"),
        ], style={"flex":"1","maxWidth":"300px"}),
        html.Div([
            html.Label("Audit A (baseline)", className="filter-label"),
            dcc.Dropdown(id="cmp-a", placeholder="—", className="dash-dropdown"),
        ], style={"flex":"1","maxWidth":"220px"}),
        html.Div([
            html.Label("Audit B (comparison)", className="filter-label"),
            dcc.Dropdown(id="cmp-b", placeholder="—", className="dash-dropdown"),
        ], style={"flex":"1","maxWidth":"220px"}),
    ], className="filter-row"),

    html.Div(id="compare-body"),
], className="page")


@callback(
    Output("cmp-host","options"), Output("cmp-host","value"),
    Input("global-refresh","n_intervals"), Input("api-base-store","data"),
)
def cmp_hosts(_, base_url):
    base = get_base_url(base_url)
    try:
        names = [h["hostname"] for h in list_hosts(base).get("hosts",[]) if h.get("hostname")]
        return [{"label":n,"value":n} for n in names], (names[0] if names else None)
    except: return [], None


@callback(
    Output("cmp-a","options"), Output("cmp-a","value"),
    Output("cmp-b","options"), Output("cmp-b","value"),
    Input("cmp-host","value"), State("api-base-store","data"),
)
def cmp_audits(hostname, base_url):
    if not hostname: return [],[],[],[]
    base = get_base_url(base_url)
    try:
        ids  = sorted([int(a["audit_id"]) for a in list_audits(base,hostname,30).get("audits",[]) if a.get("audit_id")])
        opts = [{"label":f"Audit #{i}","value":i} for i in ids]
        return opts,(ids[0] if ids else None),opts,(ids[-1] if ids else None)
    except: return [],[],[],[]


@callback(
    Output("compare-body","children"),
    Input("cmp-a","value"), Input("cmp-b","value"),
    State("api-base-store","data"),
)
def run_compare(a_id, b_id, base_url):
    if not a_id or not b_id: return empty_state("Select two audits to compare.")
    if a_id == b_id: return error_banner("Please select two different audit IDs.")
    base = get_base_url(base_url)
    try:
        A = evaluated_audit(base, a_id)
        B = evaluated_audit(base, b_id)
    except Exception as e:
        return error_banner(f"Failed to load audits: {e}")

    ssA, ssB = get_score_summary(A), get_score_summary(B)
    a_s, b_s = ssA.get("compliance_score"), ssB.get("compliance_score")
    a_r, b_r = ssA.get("risk_score"),       ssB.get("risk_score")

    dc = round(float(b_s)-float(a_s),1) if a_s and b_s else None
    dr = round(float(b_r)-float(a_r),1) if a_r and b_r else None

    def dc_color(d, invert=False):
        if d is None: return "#6b7280"
        return "#16a34a" if (d<0 if invert else d>0) else "#dc2626"

    score_strip = html.Div([
        kpi_card("Audit A Compliance", f"{a_s}%" if a_s else "—", "#3b82f6"),
        kpi_card("Audit B Compliance", f"{b_s}%" if b_s else "—", "#8b5cf6"),
        kpi_card("Compliance Δ",  f"{dc:+.1f}%" if dc is not None else "—", dc_color(dc)),
        kpi_card("Risk Score Δ",  f"{dr:+.1f}"  if dr is not None else "—", dc_color(dr,invert=True)),
    ], className="kpi-row")

    ctrlsA = {c["control_id"]:c for c in normalize_controls(A.get("results",[]))}
    ctrlsB = {c["control_id"]:c for c in normalize_controls(B.get("results",[]))}
    changed, improved, regressed = [], 0, 0
    for cid in sorted(set(ctrlsA)|set(ctrlsB)):
        sA = ctrlsA.get(cid,{}).get("status","")
        sB = ctrlsB.get(cid,{}).get("status","")
        if sA != sB:
            merged = ctrlsB.get(cid,{}) or ctrlsA.get(cid,{})
            if sB == "PASS": improved  += 1
            else:            regressed += 1
            changed.append({
                "Control ID":    cid,
                "Audit A":       status_badge(sA) if sA else html.Span("—"),
                "Audit B":       status_badge(sB) if sB else html.Span("—"),
                "Domain":        merged.get("domain",""),
                "Severity":      sev_badge(merged.get("severity","")),
                "Evidence B":    ctrlsB.get(cid,{}).get("evidence",""),
                "Recommendation":merged.get("recommendation",""),
                "_rk": "high" if sB=="FAIL" else "low",
            })

    imp_reg = html.Div([
        kpi_card("Improvements (FAIL→PASS)", improved,  "#16a34a"),
        kpi_card("Regressions (PASS→FAIL)",  regressed, "#dc2626"),
    ], className="kpi-row", style={"marginTop":"1.5rem"})

    diff_cols = ["Control ID","Audit A","Audit B","Domain","Severity","Evidence B","Recommendation"]
    diff_tbl  = data_table(diff_cols, changed, row_risk_key_col="_rk",
                           wrap_cols={"Evidence B","Recommendation"}) \
                if changed else empty_state("No status changes between these two audits. ✅")

    return html.Div([
        score_strip,
        html.Div(style={"height":"1.5rem"}),
        section_header("Improvement Summary","📊"),
        imp_reg,
        html.Div(style={"height":"1.5rem"}),
        section_header("Changed Controls","🔄"),
        diff_tbl,
    ])
