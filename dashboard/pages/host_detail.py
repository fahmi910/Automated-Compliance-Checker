import dash
from dash import html, dcc, callback, Input, Output, State
from helpers import (
    get_base_url, list_hosts, latest_evaluated, get_score_summary,
    normalize_controls, fmt_dt, risk_key, sev_key, RISK_MAP,
    kpi_card, section_header, data_table, risk_badge, sev_badge,
    status_badge, make_bar_chart, empty_state, error_banner,
)

dash.register_page(__name__, path="/host", name="Host Details")

layout = html.Div([
    html.Div([
        html.H1("Host Details"),
        html.P("Drill into scores, domain risk, and individual controls.", className="page-subtitle"),
    ], className="page-header"),

    html.Div([
        html.Div([
            html.Label("Select Host", className="filter-label"),
            dcc.Dropdown(id="host-select", placeholder="Loading hosts…", className="dash-dropdown"),
        ], style={"flex":"1","maxWidth":"340px"}),
    ], className="filter-row"),

    html.Div(id="host-detail-body"),
], className="page")


@callback(
    Output("host-select","options"),
    Output("host-select","value"),
    Input("global-refresh","n_intervals"),
    Input("api-base-store","data"),
)
def load_host_list(_, base_url):
    base = get_base_url(base_url)
    try:
        hosts = list_hosts(base).get("hosts",[])
        names = [h["hostname"] for h in hosts if h.get("hostname")]
        return [{"label":n,"value":n} for n in names], (names[0] if names else None)
    except:
        return [], None


@callback(
    Output("host-detail-body","children"),
    Input("host-select","value"),
    Input("global-refresh","n_intervals"),
    State("api-base-store","data"),
)
def load_host_detail(hostname, _, base_url):
    if not hostname:
        return empty_state("Select a host above to view details.")
    base = get_base_url(base_url)
    try:
        ev = latest_evaluated(base, hostname)
    except Exception as e:
        return error_banner(f"Failed to load audit for {hostname}: {e}")

    ss     = get_score_summary(ev)
    ctrls  = normalize_controls(ev.get("results",[]))
    score  = ss.get("compliance_score")
    rscore = ss.get("risk_score")
    rk     = risk_key(rscore)
    rinfo  = RISK_MAP.get(rk, RISK_MAP["unknown"])

    total  = len(ctrls)
    fails  = [c for c in ctrls if c["status"]=="FAIL"]
    passes = [c for c in ctrls if c["status"]=="PASS"]
    hfails = [c for c in fails  if c["severity"]=="high"]

    # ── Score row ──
    score_pct  = f"{score}" if score is not None else "—"
    score_color = rinfo["color"]
    bar_color   = rinfo["color"]

    score_card = html.Div([
        html.Div("Compliance Score", className="gauge-label"),
        html.Div([
            html.Span(score_pct, style={"fontSize":"3.5rem","fontWeight":"800",
                                        "letterSpacing":"-0.03em","color":score_color,
                                        "lineHeight":"1"}),
            html.Span("%", style={"fontSize":"1.6rem","fontWeight":"600",
                                  "color":score_color,"opacity":"0.7",
                                  "verticalAlign":"super","marginLeft":"2px"})
                  if score is not None else None,
        ], style={"margin":"0.5rem 0 0.3rem","display":"flex",
                  "alignItems":"baseline","justifyContent":"center","gap":"0"}),
        html.Div(f"Risk Score: {rscore:.1f}" if rscore else "—",
                 className="score-sublabel"),
        html.Div(risk_badge(rk), style={"marginBottom":"0.5rem"}),
    ], className="gauge-card", style={"--gauge-color": bar_color})

    score_row = html.Div([
        score_card,
        html.Div([
            html.Div([
                kpi_card("Total Controls", total,        "#3b82f6"),
                kpi_card("Passed",         len(passes),  "#16a34a"),
                kpi_card("Failed",         len(fails),   "#dc2626"),
                kpi_card("High Severity",  len(hfails),  "#ea580c"),
            ], className="kpi-row"),
            html.Div(
                f"Audit ID: {ev.get('audit_id','—')}  ·  Received: {fmt_dt(ev.get('received_at'))}",
                className="audit-meta",
            ),
        ], style={"flex":"1"}),
    ], className="score-kpi-row")

    # ── Domain breakdown ──
    domain_scores = ss.get("domain_scores",{})
    domain_section = html.Div()
    if domain_scores:
        d_rows = []
        for dname, info in domain_scores.items():
            drk = risk_key(info.get("risk_score"))
            d_rows.append({
                "Domain":       dname,
                "Compliance":   html.Span(f'{info.get("compliance_score","—")}%',
                                          style={"color":"#2563eb","fontWeight":"700"}),
                "Risk Score":   f'{info.get("risk_score",0):.1f}',
                "Risk Level":   risk_badge(drk),
                "Earned / Max": f'{info.get("compliance_earned_points","—")} / {info.get("compliance_max_points","—")}',
                "High Fails":   str(info.get("high_fail_count","—")),
                "_rk": drk,
            })
        d_rows.sort(key=lambda x: float(x["Risk Score"]), reverse=True)
        d_cols  = ["Domain","Compliance","Risk Score","Risk Level","Earned / Max","High Fails"]
        labels  = [r["Domain"] for r in d_rows]
        rscores = [float(r["Risk Score"]) for r in d_rows]
        colors  = [RISK_MAP.get(r["_rk"], RISK_MAP["unknown"])["color"] for r in d_rows]

        domain_section = html.Div([
            section_header("Domain Breakdown", "📊"),
            html.Div([
                html.Div(data_table(d_cols, d_rows, row_risk_key_col="_rk"), style={"flex":"1.2"}),
                html.Div(dcc.Graph(figure=make_bar_chart(labels,rscores,colors),
                                   config={"displayModeBar":False},
                                   style={"height":"260px"}), style={"flex":"1"}),
            ], style={"display":"flex","gap":"1.5rem","alignItems":"flex-start"}),
        ])

    # ── Top risks ──
    top_risks = sorted(ss.get("top_risks",[]), key=lambda x:x.get("residual_risk",0), reverse=True)
    risk_cards = []
    for r in top_risks[:5]:
        sk    = sev_key(r.get("severity",""))
        rm    = RISK_MAP.get(sk, RISK_MAP["unknown"])
        risk_cards.append(html.Div([
            html.Div([
                risk_badge(sk),
                html.Span(r.get("title",""),
                          style={"fontWeight":"600","color":"#111827","marginLeft":"10px"}),
                html.Span(f" · {r.get('domain','')}",
                          style={"color":"#6b7280","fontSize":"0.82rem"}),
                html.Span(f"  Residual Risk: {r.get('residual_risk','')}",
                          style={"color":"#9ca3af","fontSize":"0.78rem","marginLeft":"6px"}),
            ], style={"display":"flex","alignItems":"center","flexWrap":"wrap","gap":"4px"}),
            html.P(r.get("reason",""),
                   style={"color":"#4b5563","fontSize":"0.85rem","margin":"8px 0 4px","lineHeight":"1.6"}),
            html.Div([
                html.Span("Recommendation: ",
                          style={"color":"#374151","fontSize":"0.82rem","fontWeight":"600"}),
                html.Span(r.get("recommendation",""),
                          style={"color":"#6b7280","fontSize":"0.82rem"}),
            ]),
        ], className="risk-card", style={
            "borderLeft": f"3px solid {rm['color']}",
            "background": rm["bg"],
            "border":     f"1px solid {rm['border']}",
            "borderLeftWidth":"3px",
        }))

    # ── Control results (with filters stored in dcc.Store) ──
    ctrl_section = html.Div([
        section_header("Control Results", "📋"),
        html.Div([
            html.Div([
                html.Label("Status", className="filter-label"),
                dcc.RadioItems(id="ctrl-status-filter",
                    options=[{"label":"All","value":"ALL"},
                             {"label":"FAIL only","value":"FAIL"},
                             {"label":"PASS only","value":"PASS"}],
                    value="FAIL", inline=True, className="radio-group"),
            ]),
            html.Div([
                html.Label("Domain", className="filter-label"),
                dcc.Dropdown(id="ctrl-domain-filter",
                    options=[{"label":"All","value":"ALL"}]+
                            [{"label":d,"value":d} for d in sorted({c["domain"] for c in ctrls if c["domain"]})],
                    value="ALL", clearable=False, className="dash-dropdown",
                    style={"width":"220px"}),
            ]),
            html.Div([
                html.Label("Severity", className="filter-label"),
                dcc.Dropdown(id="ctrl-sev-filter",
                    options=[{"label":"All","value":"ALL"},
                             {"label":"High","value":"high"},
                             {"label":"Medium","value":"medium"},
                             {"label":"Low","value":"low"}],
                    value="ALL", clearable=False, className="dash-dropdown",
                    style={"width":"160px"}),
            ]),
        ], className="filter-row"),
        html.Div(id="ctrl-table-container",
                 children=_build_ctrl_table(ctrls,"FAIL","ALL","ALL")),
        dcc.Store(id="ctrls-store", data=ctrls),
    ])

    return html.Div([
        score_row,
        html.Div(style={"height":"1.5rem"}),
        domain_section,
        html.Div(style={"height":"1rem"}),
        section_header("Top Risks", "🔥"),
        html.Div(risk_cards) if risk_cards else empty_state("No major risks detected."),
        html.Div(style={"height":"1rem"}),
        ctrl_section,
    ])


def _build_ctrl_table(ctrls, status_f, domain_f, sev_f):
    f = ctrls
    if status_f != "ALL": f = [c for c in f if c["status"] == status_f]
    if domain_f != "ALL": f = [c for c in f if c["domain"] == domain_f]
    if sev_f    != "ALL": f = [c for c in f if c["severity"] == sev_f]
    f = sorted(f, key=lambda x:(-{"high":3,"medium":2,"low":1}.get(x["severity"],0), x["control_id"]))
    if not f:
        return empty_state("No controls match the current filters.")
    rows = []
    for c in f:
        rows.append({
            "Control ID":    c["control_id"],
            "Title":         c["title"],
            "Domain":        c["domain"],
            "Status":        status_badge(c["status"]),
            "Severity":      sev_badge(c["severity"]),
            "Residual Risk": f'{c["residual_risk"]:.2f}',
            "Evidence":      c["evidence"],
            "Recommendation":c["recommendation"],
            "_rk": sev_key(c["severity"]),
        })
    cols = ["Control ID","Title","Domain","Status","Severity","Residual Risk","Evidence","Recommendation"]
    return html.Div([
        html.Div(f"Showing {len(f)} of {len(ctrls)} controls",
                 style={"color":"#9ca3af","fontSize":"0.78rem","marginBottom":"0.5rem"}),
        data_table(cols, rows, row_risk_key_col="_rk",
                   wrap_cols={"Evidence","Recommendation","Title"}),
    ])


@callback(
    Output("ctrl-table-container","children"),
    Input("ctrl-status-filter","value"),
    Input("ctrl-domain-filter","value"),
    Input("ctrl-sev-filter","value"),
    State("ctrls-store","data"),
)
def filter_controls(status_f, domain_f, sev_f, ctrls):
    if not ctrls: return empty_state()
    return _build_ctrl_table(ctrls, status_f or "ALL", domain_f or "ALL", sev_f or "ALL")
