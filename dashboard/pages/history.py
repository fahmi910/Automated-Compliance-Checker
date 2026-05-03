import dash
from dash import html, dcc, callback, Input, Output, State
from helpers import (
    get_base_url, list_hosts, list_audits, evaluated_audit, get_score_summary,
    fmt_dt, risk_key, kpi_card, section_header, data_table,
    risk_badge, make_line_chart, empty_state, error_banner,
)

dash.register_page(__name__, path="/history", name="History")

layout = html.Div([
    html.Div([
        html.H1("Audit History"),
        html.P("Track compliance and risk trends over time.", className="page-subtitle"),
    ], className="page-header"),

    html.Div([
        html.Div([
            html.Label("Select Host", className="filter-label"),
            dcc.Dropdown(id="hist-host", placeholder="Loading…", className="dash-dropdown"),
        ], style={"flex":"1","maxWidth":"340px"}),
        html.Div([
            html.Label("Max Audits", className="filter-label"),
            dcc.Slider(id="hist-limit", min=5, max=50, step=5, value=20,
                       marks={5:"5",20:"20",35:"35",50:"50"}, className="slider"),
        ], style={"flex":"1","maxWidth":"300px"}),
    ], className="filter-row"),

    html.Div(id="history-body"),
], className="page")


@callback(
    Output("hist-host","options"), Output("hist-host","value"),
    Input("global-refresh","n_intervals"), Input("api-base-store","data"),
)
def hist_hosts(_, base_url):
    base = get_base_url(base_url)
    try:
        names = [h["hostname"] for h in list_hosts(base).get("hosts",[]) if h.get("hostname")]
        return [{"label":n,"value":n} for n in names], (names[0] if names else None)
    except: return [], None


@callback(
    Output("history-body","children"),
    Input("hist-host","value"), Input("hist-limit","value"),
    Input("global-refresh","n_intervals"), State("api-base-store","data"),
)
def load_history(hostname, limit, _, base_url):
    if not hostname: return empty_state("Select a host to view history.")
    base = get_base_url(base_url)
    try:
        audits = list_audits(base, hostname, limit or 20).get("audits",[])
    except Exception as e:
        return error_banner(f"Failed: {e}")
    if not audits: return empty_state("No audit records found.")

    rows, cx, cy, rx, ry = [], [], [], [], []
    for a in audits:
        try:
            ev  = evaluated_audit(base, a["audit_id"])
            ss  = get_score_summary(ev)
            rk  = risk_key(ss.get("risk_score"))
            at  = fmt_dt(a.get("received_at"))
            c   = ss.get("compliance_score")
            rs  = ss.get("risk_score")
            rows.append({
                "Audit ID":   str(a.get("audit_id","—")),
                "Received At": at,
                "Compliance": html.Span(f"{c}%" if c is not None else "—",
                                        style={"color":"#2563eb","fontWeight":"700"}),
                "Risk Score": f"{rs:.1f}" if rs is not None else "—",
                "Risk Level": risk_badge(rk),
                "_rk": rk,
            })
            if c  is not None: cx.append(at); cy.append(float(c))
            if rs is not None: rx.append(at); ry.append(float(rs))
        except: pass

    log_cols = ["Audit ID","Received At","Compliance","Risk Score","Risk Level"]
    charts = []
    if len(cy) >= 2:
        charts.append(html.Div([
            section_header("Compliance Score Trend","📈"),
            dcc.Graph(figure=make_line_chart(cx,cy,"Compliance %","#3b82f6"),
                      config={"displayModeBar":False}),
        ]))
    if len(ry) >= 2:
        charts.append(html.Div([
            section_header("Risk Score Trend","📉"),
            dcc.Graph(figure=make_line_chart(rx,ry,"Risk Score","#dc2626"),
                      config={"displayModeBar":False}),
        ]))

    return html.Div([
        section_header("Audit Log","🗂"),
        data_table(log_cols, rows, row_risk_key_col="_rk"),
        html.Div(style={"height":"2rem"}),
        *charts,
    ])
