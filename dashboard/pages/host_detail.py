import dash
from dash import html, dcc, callback, Input, Output, State, ctx
from helpers import (
    get_base_url, list_hosts, latest_evaluated, get_score_summary,
    normalize_controls, fmt_dt, risk_key, sev_key, RISK_MAP,
    risk_badge, status_badge, sev_badge, make_bar_chart,
    empty_state, error_banner,
    get_plain_reason, get_plain_recommendation,
)

dash.register_page(__name__, path="/host", name="Host Details")

# ── CSS tokens (mirror style.css vars) ───────────────────────────────────────
_C = {
    "card":      "#ffffff",
    "bg":        "#f4f6fb",
    "border":    "#e5e9f2",
    "text":      "#374151",
    "text_dim":  "#9ca3af",
    "text_bright":"#111827",
    "blue":      "#2563eb",
    "blue_dim":  "rgba(37,99,235,0.08)",
    "shadow_sm": "0 1px 3px rgba(0,0,0,0.06)",
    "shadow_md": "0 4px 12px rgba(0,0,0,0.08)",
    "radius":    "10px",
    "radius_lg": "14px",
}


# ── Shared sub-components ─────────────────────────────────────────────────────

def _card(children, extra=None):
    s = {
        "background":   _C["card"],
        "border":       f"1px solid {_C['border']}",
        "borderRadius": _C["radius_lg"],
        "boxShadow":    _C["shadow_sm"],
    }
    if extra:
        s.update(extra)
    return html.Div(children, style=s)


def _label(text):
    return html.Div(text, style={
        "fontSize": "0.62rem", "fontWeight": "700",
        "letterSpacing": "0.10em", "textTransform": "uppercase",
        "color": _C["text_dim"], "marginBottom": "0.3rem",
    })


def _divider():
    return html.Div(style={
        "height": "1px", "background": _C["border"],
        "margin": "0.85rem 0",
    })


def _section_label(text):
    return html.Div([
        html.Span(text, style={
            "fontSize": "0.62rem", "fontWeight": "700",
            "letterSpacing": "0.12em", "textTransform": "uppercase",
            "color": _C["blue"],
        }),
        html.Div(style={"flex": "1", "height": "1px", "background": _C["border"]}),
    ], style={
        "display": "flex", "alignItems": "center",
        "gap": "0.75rem", "marginBottom": "0.75rem", "marginTop": "1.25rem",
    })


# ── Layout ────────────────────────────────────────────────────────────────────

def _page_header(title, subtitle):
    return html.Div([
        html.Div([
            html.H1(title, style={
                "fontSize": "1.65rem", "fontWeight": "800", "color": _C["text_bright"],
                "letterSpacing": "-0.03em", "margin": "0 0 4px 0",
            }),
            html.Div(subtitle, style={
                "fontSize": "0.78rem", "color": _C["text_dim"],
            }),
        ]),
    ], style={"marginBottom": "1.25rem"})


layout = html.Div([
    _page_header(
        "Host Detail",
        "Drill into compliance scores, domain risk, and individual control evidence.",
    ),
    html.Div([
        html.Div([
            html.Label("Select Host", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": _C["text_dim"], "marginBottom": "0.3rem",
                "display": "block",
            }),
            dcc.Dropdown(
                id="host-select",
                placeholder="Choose a host…",
                className="dash-dropdown",
                style={"width": "300px"},
            ),
        ]),
    ], style={
        "display": "flex", "alignItems": "flex-end",
        "marginBottom": "1.5rem",
    }),
    html.Div(id="host-detail-body"),
], className="page")


# ── Host list loader ──────────────────────────────────────────────────────────

@callback(
    Output("host-select", "options"),
    Output("host-select", "value"),
    Input("global-refresh", "n_intervals"),
    Input("api-base-store", "data"),
)
def load_host_list(_, base_url):
    base = get_base_url(base_url)
    try:
        hosts = list_hosts(base).get("hosts", [])
        names = [h["hostname"] for h in hosts if h.get("hostname")]
        return [{"label": n, "value": n} for n in names], (names[0] if names else None)
    except:
        return [], None


# ── Zone builders ─────────────────────────────────────────────────────────────

def _zone1_header(ev, ss, ctrls):
    """Identity header bar + 4 stat cards."""
    score  = ss.get("compliance_score")
    rscore = ss.get("risk_score")
    rk     = risk_key(rscore)
    accent = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]

    passes   = [c for c in ctrls if c["status"] == "PASS"]
    fails    = [c for c in ctrls if c["status"] == "FAIL"]
    partials = [c for c in ctrls if c["status"] == "PARTIAL"]

    platform = ev.get("platform", "")
    os_label = ev.get("os_version", ev.get("os_type", "—"))
    platform_icon = {
        "linux": "Linux", "windows_server": "Windows Server", "windows10": "Windows 10",
    }.get(platform.lower(), platform)

    # Identity bar
    identity = _card([
        html.Div([
            # Left: host info
            html.Div([
                html.Div(ev.get("hostname", "—"), style={
                    "fontSize": "1.5rem", "fontWeight": "800",
                    "color": _C["text_bright"], "letterSpacing": "-0.02em",
                }),
                html.Div([
                    html.Span(platform_icon, style={
                        "fontSize": "0.72rem", "fontWeight": "700",
                        "color": _C["blue"], "background": _C["blue_dim"],
                        "borderRadius": "4px", "padding": "2px 8px",
                    }),
                    html.Span(ev.get("ip_address", "—"), style={
                        "fontSize": "0.78rem", "color": _C["text_dim"],
                        "fontFamily": "monospace",
                    }),
                    html.Span(os_label[:60], style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                    }),
                ], style={"display": "flex", "alignItems": "center", "gap": "0.75rem",
                          "marginTop": "0.35rem", "flexWrap": "wrap"}),
            ]),
            # Right: audit meta
            html.Div([
                html.Div([
                    html.Span("Audit ID  ", style={"color": _C["text_dim"], "fontSize": "0.72rem"}),
                    html.Span(str(ev.get("audit_id", "—")), style={
                        "fontWeight": "700", "color": _C["text_bright"], "fontSize": "0.78rem",
                    }),
                ]),
                html.Div([
                    html.Span("Received  ", style={"color": _C["text_dim"], "fontSize": "0.72rem"}),
                    html.Span(fmt_dt(ev.get("received_at")), style={
                        "fontWeight": "600", "color": _C["text"], "fontSize": "0.78rem",
                    }),
                ]),
            ], style={"textAlign": "right"}),
        ], style={"display": "flex", "justifyContent": "space-between",
                  "alignItems": "flex-start"}),
    ], {
        "padding": "1.2rem 1.5rem",
        "borderTop": f"4px solid {accent}",
        "marginBottom": "1rem",
    })

    # 4 stat cards
    def _stat(value, label, accent):
        return _card([
            html.Div(style={"height": "3px", "background": accent,
                            "borderRadius": "14px 14px 0 0", "marginBottom": "1rem"}),
            html.Div([
                html.Div(str(value), style={
                    "fontSize": "2.2rem", "fontWeight": "800", "color": accent,
                    "lineHeight": "1", "fontVariantNumeric": "tabular-nums",
                    "letterSpacing": "-0.02em", "marginBottom": "0.4rem",
                }),
                html.Div(label, style={
                    "fontSize": "0.78rem", "color": _C["text_dim"],
                    "fontWeight": "500", "textAlign": "center",
                }),
            ], style={"display": "flex", "flexDirection": "column",
                      "alignItems": "center", "paddingBottom": "1rem"}),
        ], {"overflow": "hidden"})

    score_accent = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]
    stats = html.Div([
        _stat(f"{score:.0f}%" if score is not None else "—", "Compliance Score", score_accent),
        _stat(f"{rscore:.1f}" if rscore is not None else "—", "Risk Score", score_accent),
        _stat(len(passes),   "Controls Passed", "#16a34a"),
        _stat(len(fails),    "Controls Failed",  "#dc2626"),
    ], style={"display": "grid", "gridTemplateColumns": "repeat(4, 1fr)",
              "gap": "1rem", "marginBottom": "1rem"})

    return html.Div([identity, stats])


def _zone2_domain_and_status(ss, ctrls):
    """Domain bar chart (left) + control status breakdown (right)."""
    domain_scores = ss.get("domain_scores", {})

    # Left: horizontal domain compliance bars
    DOMAIN_ORDER = [
        "Access Control", "Logging & Monitoring",
        "Asset & Configuration Management", "Cryptography", "Backup & Recovery",
    ]
    domain_rows = []
    for d in DOMAIN_ORDER:
        if d not in domain_scores:
            continue
        info = domain_scores[d]
        comp = info.get("compliance_score") or 0
        drk  = risk_key(info.get("risk_score", 0))
        accent = RISK_MAP.get(drk, RISK_MAP["unknown"])["color"]
        domain_rows.append((d, comp, accent, drk))

    # Sort worst first
    domain_rows.sort(key=lambda x: x[1])

    bar_rows = []
    for dname, comp, accent, drk in domain_rows:
        bar_rows.append(html.Div([
            html.Div(dname, style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": _C["text_bright"], "marginBottom": "4px",
            }),
            html.Div([
                html.Div(
                    html.Div(style={
                        "width": f"{min(comp,100)}%", "height": "100%",
                        "background": accent, "borderRadius": "4px",
                        "minWidth": "2px", "transition": "width 0.5s ease",
                    }),
                    style={
                        "flex": "1", "height": "10px", "background": _C["bg"],
                        "borderRadius": "4px", "overflow": "hidden",
                        "border": f"1px solid {_C['border']}",
                    },
                ),
                html.Span(f"{comp:.0f}%", style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": accent, "width": "38px", "textAlign": "right",
                    "flexShrink": "0", "fontVariantNumeric": "tabular-nums",
                    "marginLeft": "0.75rem",
                }),
                html.Div(risk_badge(drk), style={"marginLeft": "0.5rem", "flexShrink": "0"}),
            ], style={"display": "flex", "alignItems": "center"}),
        ], style={"marginBottom": "0.85rem"}))

    domain_card = _card([
        html.Div("Domain Compliance", style={
            "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
            "paddingBottom": "0.85rem", "marginBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div(bar_rows),
    ], {"padding": "1.3rem 1.4rem"})

    # Right: status breakdown
    status_counts = {}
    for c in ctrls:
        s = c["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    STATUS_CONFIG = {
        "PASS":    ("#16a34a", "#f0fdf4", "#86efac"),
        "FAIL":    ("#dc2626", "#fef2f2", "#fca5a5"),
        "PARTIAL": ("#ca8a04", "#fefce8", "#fde047"),
        "UNKNOWN": ("#6b7280", "#f9fafb", "#d1d5db"),
    }

    status_items = []
    for s, (color, bg, border) in STATUS_CONFIG.items():
        count = status_counts.get(s, 0)
        total = len(ctrls) or 1
        pct   = round(count / total * 100)
        status_items.append(html.Div([
            html.Div([
                html.Span(s, style={
                    "fontSize": "0.75rem", "fontWeight": "700", "color": color,
                }),
                html.Span(str(count), style={
                    "fontSize": "1.4rem", "fontWeight": "800", "color": color,
                    "fontVariantNumeric": "tabular-nums",
                }),
            ], style={"display": "flex", "justifyContent": "space-between",
                      "alignItems": "center", "marginBottom": "5px"}),
            html.Div(
                html.Div(style={
                    "width": f"{pct}%", "height": "100%",
                    "background": color, "borderRadius": "3px",
                    "minWidth": "2px" if count > 0 else "0",
                }),
                style={"width": "100%", "height": "8px", "background": bg,
                       "borderRadius": "3px", "overflow": "hidden",
                       "border": f"1px solid {border}"},
            ),
        ], style={"marginBottom": "1rem"}))

    # Severity breakdown
    sev_counts = {"high": 0, "medium": 0, "low": 0}
    for c in [c for c in ctrls if c["status"] == "FAIL"]:
        sev = c.get("severity", "").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    sev_items = []
    sev_cfg = {
        "high":   ("#dc2626", "High Severity FAIL"),
        "medium": ("#ca8a04", "Medium Severity FAIL"),
        "low":    ("#16a34a", "Low Severity FAIL"),
    }
    for sev, (color, label) in sev_cfg.items():
        count = sev_counts[sev]
        sev_items.append(html.Div([
            html.Span(label, style={"fontSize": "0.72rem", "color": _C["text_dim"]}),
            html.Span(str(count), style={
                "fontSize": "0.82rem", "fontWeight": "700", "color": color,
                "background": "#fef2f2" if color == "#dc2626" else "#fefce8" if color == "#ca8a04" else "#f0fdf4",
                "border": f"1px solid {'#fca5a5' if color=='#dc2626' else '#fde047' if color=='#ca8a04' else '#86efac'}",
                "borderRadius": "999px", "padding": "1px 8px",
            }),
        ], style={"display": "flex", "justifyContent": "space-between",
                  "alignItems": "center", "marginBottom": "0.5rem"}))

    status_card = _card([
        html.Div("Control Status", style={
            "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
            "paddingBottom": "0.85rem", "marginBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div(status_items),
        html.Div("Failures by Severity", style={
            "fontSize": "0.72rem", "fontWeight": "700", "color": _C["text_dim"],
            "textTransform": "uppercase", "letterSpacing": "0.08em",
            "marginBottom": "0.6rem", "marginTop": "0.25rem",
        }),
        html.Div(sev_items),
    ], {"padding": "1.3rem 1.4rem"})

    return html.Div([
        html.Div(domain_card,  style={"gridColumn": "1 / 2"}),
        html.Div(status_card,  style={"gridColumn": "2 / 3"}),
    ], style={"display": "grid", "gridTemplateColumns": "1.4fr 1fr",
              "gap": "1rem", "alignItems": "start"})


def _zone3_controls_table(ctrls, raw_results):
    """Filterable control table with expandable evidence drawer."""
    # Build a lookup from control_id → raw result for the drawer
    raw_lookup = {r.get("control_id", ""): r for r in (raw_results or [])}

    domains = sorted({c["domain"] for c in ctrls if c["domain"]})

    filters = html.Div([
        html.Div([
            html.Label("Status", style={"fontSize": "0.72rem", "fontWeight": "600",
                                        "color": _C["text_dim"], "display": "block",
                                        "marginBottom": "0.3rem"}),
            dcc.RadioItems(
                id="ctrl-status-filter",
                options=[
                    {"label": "All",     "value": "ALL"},
                    {"label": "FAIL",    "value": "FAIL"},
                    {"label": "PARTIAL", "value": "PARTIAL"},
                    {"label": "PASS",    "value": "PASS"},
                ],
                value="ALL", inline=True, className="radio-group",
            ),
        ]),
        html.Div([
            html.Label("Domain", style={"fontSize": "0.72rem", "fontWeight": "600",
                                        "color": _C["text_dim"], "display": "block",
                                        "marginBottom": "0.3rem"}),
            dcc.Dropdown(
                id="ctrl-domain-filter",
                options=[{"label": "All Domains", "value": "ALL"}] +
                        [{"label": d, "value": d} for d in domains],
                value="ALL", clearable=False, className="dash-dropdown",
                style={"width": "240px"},
            ),
        ]),
        html.Div([
            html.Label("Severity", style={"fontSize": "0.72rem", "fontWeight": "600",
                                          "color": _C["text_dim"], "display": "block",
                                          "marginBottom": "0.3rem"}),
            dcc.Dropdown(
                id="ctrl-sev-filter",
                options=[
                    {"label": "All Severities", "value": "ALL"},
                    {"label": "High",           "value": "high"},
                    {"label": "Medium",         "value": "medium"},
                    {"label": "Low",            "value": "low"},
                ],
                value="ALL", clearable=False, className="dash-dropdown",
                style={"width": "180px"},
            ),
        ]),
    ], style={"display": "flex", "gap": "1.5rem", "alignItems": "flex-end",
              "marginBottom": "1rem", "flexWrap": "wrap"})

    return html.Div([
        filters,
        html.Div(id="ctrl-table-container",
                 children=_build_ctrl_rows(ctrls, raw_lookup, "ALL", "ALL", "ALL")),
        dcc.Store(id="ctrls-store",     data=ctrls),
        dcc.Store(id="raw-ctrl-store",  data=raw_results),
        dcc.Store(id="expanded-ctrl",   data=None),
    ])


def _build_ctrl_rows(ctrls, raw_lookup, status_f, domain_f, sev_f, expanded_id=None):
    """Build the control rows with optional expanded drawer."""
    f = ctrls
    if status_f != "ALL": f = [c for c in f if c["status"] == status_f]
    if domain_f != "ALL": f = [c for c in f if c["domain"] == domain_f]
    if sev_f    != "ALL": f = [c for c in f if c["severity"] == sev_f]
    f = sorted(f, key=lambda x: (
        -{"high": 3, "medium": 2, "low": 1}.get(x["severity"], 0),
        -x.get("residual_risk", 0),
    ))

    if not f:
        return empty_state("No controls match the current filters.")

    th_style = {
        "padding": "0.65rem 1rem", "fontSize": "0.65rem", "fontWeight": "700",
        "color": _C["text_dim"], "textTransform": "uppercase",
        "letterSpacing": "0.07em", "background": _C["bg"],
        "borderBottom": f"1px solid {_C['border']}", "textAlign": "left",
        "whiteSpace": "nowrap",
    }

    header = html.Tr([
        html.Th("",            style={**th_style, "width": "32px"}),  # expand icon
        html.Th("Control",     style=th_style),
        html.Th("Domain",      style=th_style),
        html.Th("Status",      style=th_style),
        html.Th("Severity",    style=th_style),
        html.Th("Residual Risk", style=th_style),
        html.Th("Decision",    style=th_style),
    ])

    body_rows = []
    for c in f:
        cid      = c["control_id"]
        is_open  = (expanded_id == cid)
        rk       = sev_key(c["severity"])
        accent   = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]
        row_bg   = "#fef2f2" if c["status"] == "FAIL" else \
                   "#fefce8" if c["status"] == "PARTIAL" else "#ffffff"

        td = lambda content, extra=None: html.Td(content, style={
            "padding": "0.75rem 1rem",
            "borderBottom": f"1px solid {_C['border']}",
            "fontSize": "0.82rem",
            "color": _C["text"],
            **(extra or {}),
        })

        toggle_btn = html.Td(
            html.Div(
                "▾" if is_open else "▸",
                id={"type": "ctrl-toggle", "index": cid},
                n_clicks=0,
                style={
                    "cursor": "pointer", "fontSize": "0.75rem",
                    "color": _C["blue"], "userSelect": "none",
                    "padding": "4px 6px",
                },
            ),
            style={"padding": "0.75rem 0.5rem",
                   "borderBottom": f"1px solid {_C['border']}",
                   "width": "32px"},
        )

        # Control ID + title cell
        ctrl_cell = td(html.Div([
            html.Div(cid, style={
                "fontSize": "0.72rem", "fontWeight": "700",
                "color": _C["blue"], "marginBottom": "2px",
                "fontFamily": "monospace",
            }),
            html.Div(c["title"], style={
                "fontSize": "0.82rem", "fontWeight": "600",
                "color": _C["text_bright"],
            }),
        ]))

        body_rows.append(html.Tr([
            toggle_btn,
            ctrl_cell,
            td(c["domain"], {"color": _C["text_dim"]}),
            td(status_badge(c["status"])),
            td(sev_badge(c["severity"])),
            td(f'{c["residual_risk"]:.2f}', {
                "fontWeight": "700", "color": accent,
                "fontVariantNumeric": "tabular-nums",
            }),
            td(html.Span(
                c.get("decision_source", "—").capitalize() if isinstance(c.get("decision_source"), str) else "—",
                style={
                    "fontSize": "0.68rem", "fontWeight": "600",
                    "color": "#ca8a04" if str(c.get("decision_source","")).lower() == "secondary" else _C["text_dim"],
                    "background": "#fefce8" if str(c.get("decision_source","")).lower() == "secondary" else _C["bg"],
                    "borderRadius": "4px", "padding": "2px 7px",
                },
            )),
        ], style={"background": row_bg}))

        # Evidence drawer — expands below the row
        if is_open:
            raw = raw_lookup.get(cid, {})
            body_rows.append(html.Tr([
                html.Td(
                    _evidence_drawer(raw),
                    colSpan=7,
                    style={"padding": "0", "background": "#f8faff",
                           "borderBottom": f"2px solid {_C['blue']}"},
                ),
            ]))

    count_text = html.Div(
        f"Showing {len(f)} of {len(ctrls)} controls",
        style={"fontSize": "0.72rem", "color": _C["text_dim"], "marginBottom": "0.5rem"},
    )

    table = html.Table(
        [html.Thead(header), html.Tbody(body_rows)],
        style={"width": "100%", "borderCollapse": "collapse"},
    )

    return html.Div([
        count_text,
        _card(html.Div(table, style={"overflowX": "auto"}), {"padding": "0", "overflow": "hidden"}),
    ])


def _evidence_drawer(raw):
    """Full evidence + risk calculation drawer for one control."""
    if not raw:
        return html.Div("No evidence data available.", style={"padding": "1rem", "color": _C["text_dim"]})

    pri  = raw.get("primary_evidence") or {}
    sec  = raw.get("secondary_evidence") or {}
    supp = raw.get("supporting_validation") or {}
    risk = raw.get("risk") or {}
    calc = risk.get("calculation") or {}
    exp  = risk.get("exposure") or {}
    mit  = risk.get("mitigation") or {}

    def _ev_block(title, ev_dict, note=None):
        if not ev_dict:
            return None
        collected = ev_dict.get("collected", False)
        color = "#16a34a" if collected else "#9ca3af"
        return html.Div([
            html.Div([
                html.Span("●", style={"color": color, "marginRight": "6px", "fontSize": "0.6rem"}),
                html.Span(title, style={"fontWeight": "700", "fontSize": "0.78rem",
                                        "color": _C["text_bright"]}),
                html.Span(" (collected)" if collected else " (not collected)",
                          style={"fontSize": "0.68rem", "color": color, "marginLeft": "6px"}),
            ], style={"marginBottom": "0.4rem", "display": "flex", "alignItems": "center"}),
            html.Div([
                html.Div([
                    html.Span("Source: ", style={"fontWeight": "600", "color": _C["text_dim"],
                                                 "fontSize": "0.72rem"}),
                    html.Span(str(ev_dict.get("source") or "—"),
                              style={"fontSize": "0.72rem", "color": _C["text"], "fontFamily": "monospace"}),
                ], style={"marginBottom": "3px"}) if ev_dict.get("source") else None,
                html.Div([
                    html.Span("Value: ", style={"fontWeight": "600", "color": _C["text_dim"],
                                                "fontSize": "0.72rem"}),
                    html.Span(str(ev_dict.get("value") or "—"),
                              style={"fontSize": "0.72rem", "color": _C["text"], "fontFamily": "monospace"}),
                ], style={"marginBottom": "3px"}) if ev_dict.get("value") is not None else None,
                html.Div([
                    html.Span("Raw snippet: ", style={"fontWeight": "600", "color": _C["text_dim"],
                                                      "fontSize": "0.72rem"}),
                    html.Code(str(ev_dict.get("raw_snippet") or "—")[:300],
                              style={"fontSize": "0.72rem", "background": _C["bg"],
                                     "padding": "2px 6px", "borderRadius": "4px",
                                     "color": _C["text"]}),
                ]) if ev_dict.get("raw_snippet") else None,
                html.Div(note, style={"fontSize": "0.68rem", "color": "#ca8a04",
                                      "marginTop": "4px"}) if note else None,
            ], style={"paddingLeft": "1rem"}),
        ], style={"marginBottom": "0.85rem"})

    # Supporting validation signals
    supp_items = []
    for key, val in supp.items():
        if not isinstance(val, dict):
            continue
        hit   = val.get("status") == "HIT"
        color = "#16a34a" if hit else "#9ca3af"
        supp_items.append(html.Div([
            html.Span("▸ " + key, style={
                "fontSize": "0.72rem", "fontWeight": "600",
                "color": _C["text_bright"],
            }),
            html.Span("HIT" if hit else "MISS", style={
                "fontSize": "0.65rem", "fontWeight": "700",
                "color": color,
                "background": "#f0fdf4" if hit else "#f9fafb",
                "border": f"1px solid {'#86efac' if hit else '#d1d5db'}",
                "borderRadius": "4px", "padding": "1px 6px", "marginLeft": "8px",
            }),
            html.Span(str(val.get("value", ""))[:80], style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
                "marginLeft": "8px", "fontFamily": "monospace",
            }),
            html.Div(val.get("note") or "", style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
                "paddingLeft": "1rem",
            }) if val.get("note") else None,
        ], style={"marginBottom": "5px"}))

    # Risk calculation breakdown
    risk_calc = html.Div([
        _risk_calc_row("Impact Score",       f'{calc.get("impact_score", "—")}'),
        _risk_calc_row("Inherent Risk",      f'{calc.get("inherent_risk_weight", "—")}'),
        _risk_calc_row("Status Factor",      f'{calc.get("status_factor", "—")}'),
        _risk_calc_row("Mitigation %",       f'{mit.get("percent", 0) * 100:.0f}%'),
        _risk_calc_row("Residual Risk",      f'{calc.get("residual_risk_final", "—")}', bold=True),
        _risk_calc_row("Exposure Likelihood",f'{exp.get("final_exposure_likelihood", "—")} / 5'),
    ])

    # ISO / PDPA
    iso_items  = raw.get("iso_mapping", []) or []
    pdpa_items = raw.get("pdpa_mapping", []) or []

    _cid    = raw.get("control_id", "")
    _status = raw.get("status", "")
    _plain_r   = get_plain_reason(_cid, _status)
    _plain_rec = get_plain_recommendation(_cid, _status)
    _tech_r    = raw.get("reason", "—")
    _tech_rec  = raw.get("recommendation", "—")

    return html.Div([
        html.Div([
            # Left column: evidence
            html.Div([
                html.Div("Evidence", style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": _C["text_bright"], "marginBottom": "0.75rem",
                    "paddingBottom": "0.5rem",
                    "borderBottom": f"1px solid {_C['border']}",
                }),
                _ev_block("Primary Evidence", pri),
                _ev_block("Secondary Evidence", sec,
                          note=raw.get("fallback_note")),
                html.Div("What This Means", style={
                    "fontSize": "0.72rem", "fontWeight": "700",
                    "color": _C["text_dim"], "marginBottom": "4px",
                    "textTransform": "uppercase", "letterSpacing": "0.06em",
                }),
                html.P(_plain_r or _tech_r, style={
                    "fontSize": "0.78rem", "color": _C["text"],
                    "lineHeight": "1.6", "margin": "0 0 0.5rem 0",
                    "whiteSpace": "normal", "wordBreak": "break-word",
                }),
                html.Details([
                    html.Summary("Technical detail", style={
                        "fontSize": "0.68rem", "color": _C["text_dim"],
                        "cursor": "pointer", "marginBottom": "4px",
                    }),
                    html.P(_tech_r, style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                        "lineHeight": "1.5", "margin": "0",
                        "fontFamily": "monospace",
                    }),
                ], style={"marginBottom": "0.85rem"}),
                html.Div("What To Do", style={
                    "fontSize": "0.72rem", "fontWeight": "700",
                    "color": _C["text_dim"], "marginBottom": "4px",
                    "textTransform": "uppercase", "letterSpacing": "0.06em",
                }),
                html.P(_plain_rec or _tech_rec, style={
                    "fontSize": "0.78rem", "color": "#16a34a",
                    "lineHeight": "1.6", "margin": "0 0 0.5rem 0",
                    "fontWeight": "600",
                    "whiteSpace": "normal", "wordBreak": "break-word",
                }),
                html.Details([
                    html.Summary("Technical detail", style={
                        "fontSize": "0.68rem", "color": _C["text_dim"],
                        "cursor": "pointer", "marginBottom": "4px",
                    }),
                    html.P(_tech_rec, style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                        "lineHeight": "1.5", "margin": "0",
                        "fontFamily": "monospace",
                    }),
                ], style={"marginBottom": "0"}),
            ], style={"flex": "2", "minWidth": "0"}),

            # Middle column: signals + risk calc
            html.Div([
                html.Div("Validation Signals", style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": _C["text_bright"], "marginBottom": "0.75rem",
                    "paddingBottom": "0.5rem",
                    "borderBottom": f"1px solid {_C['border']}",
                }),
                html.Div(supp_items if supp_items else
                         html.Span("No signals recorded.", style={
                             "fontSize": "0.72rem", "color": _C["text_dim"],
                         })),
                html.Div(style={"height": "1rem"}),
                html.Div("Risk Calculation", style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": _C["text_bright"], "marginBottom": "0.75rem",
                    "paddingBottom": "0.5rem",
                    "borderBottom": f"1px solid {_C['border']}",
                }),
                risk_calc,
            ], style={"flex": "1", "minWidth": "0"}),

            # Right column: ISO / PDPA
            html.Div([
                html.Div("ISO 27001 Mapping", style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": _C["text_bright"], "marginBottom": "0.75rem",
                    "paddingBottom": "0.5rem",
                    "borderBottom": f"1px solid {_C['border']}",
                }),
                html.Div([
                    html.Div(item, style={
                        "fontSize": "0.72rem", "color": _C["text"],
                        "background": _C["blue_dim"], "borderRadius": "4px",
                        "padding": "4px 8px", "marginBottom": "4px",
                    }) for item in iso_items
                ] if iso_items else html.Span("—", style={"fontSize": "0.72rem", "color": _C["text_dim"]})),
                html.Div(style={"height": "0.85rem"}),
                html.Div("PDPA Mapping", style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": _C["text_bright"], "marginBottom": "0.75rem",
                    "paddingBottom": "0.5rem",
                    "borderBottom": f"1px solid {_C['border']}",
                }),
                html.Div([
                    html.Div(item, style={
                        "fontSize": "0.72rem", "color": _C["text"],
                        "background": "#f0fdf4", "borderRadius": "4px",
                        "padding": "4px 8px", "marginBottom": "4px",
                    }) for item in pdpa_items
                ] if pdpa_items else html.Span("—", style={"fontSize": "0.72rem", "color": _C["text_dim"]})),
            ], style={"flex": "0.8", "minWidth": "0"}),

        ], style={
            "display": "flex", "gap": "2rem",
            "alignItems": "flex-start",
            "flexWrap": "wrap",
            "minWidth": "0",
        }),
    ], style={
        "padding": "1.2rem 1.5rem",
        "borderTop": f"1px solid {_C['border']}",
    })


def _risk_calc_row(label, value, bold=False):
    return html.Div([
        html.Span(label, style={
            "fontSize": "0.72rem", "color": _C["text_dim"],
            "flex": "1",
        }),
        html.Span(str(value), style={
            "fontSize": "0.78rem",
            "fontWeight": "800" if bold else "600",
            "color": "#dc2626" if bold else _C["text_bright"],
            "fontFamily": "monospace",
        }),
    ], style={
        "display": "flex", "justifyContent": "space-between",
        "alignItems": "center", "padding": "4px 0",
        "borderBottom": f"1px solid {_C['border']}",
    })


def _zone4_top_risks(ss):
    """Top 5 risks as priority fix cards."""
    top_risks = sorted(
        ss.get("top_risks", []),
        key=lambda x: x.get("residual_risk", 0),
        reverse=True,
    )[:5]

    if not top_risks:
        return empty_state("No major risks detected.")

    cards = []
    for i, r in enumerate(top_risks):
        sk     = sev_key(r.get("severity", ""))
        rinfo  = RISK_MAP.get(sk, RISK_MAP["unknown"])
        accent = rinfo["color"]

        cards.append(html.Div([
            # Priority number + control ID + risk score
            html.Div([
                html.Div(f"#{i+1}", style={
                    "fontSize": "1.1rem", "fontWeight": "800",
                    "color": accent, "width": "32px", "flexShrink": "0",
                }),
                html.Div([
                    html.Div([
                        html.Span(r.get("control_id", ""), style={
                            "fontSize": "0.72rem", "fontWeight": "700",
                            "color": _C["blue"], "fontFamily": "monospace",
                            "marginRight": "0.5rem",
                        }),
                        html.Span(r.get("title", ""), style={
                            "fontSize": "0.85rem", "fontWeight": "700",
                            "color": _C["text_bright"],
                        }),
                        html.Span(f'· {r.get("domain","")}', style={
                            "fontSize": "0.72rem", "color": _C["text_dim"],
                            "marginLeft": "0.5rem",
                        }),
                    ], style={"display": "flex", "alignItems": "center", "flexWrap": "wrap"}),
                    html.P(r.get("reason", ""), style={
                        "fontSize": "0.78rem", "color": _C["text"],
                        "lineHeight": "1.6", "margin": "0.35rem 0 0.35rem 0",
                    }),
                    html.Div([
                        html.Span("Fix: ", style={
                            "fontSize": "0.75rem", "fontWeight": "700",
                            "color": "#16a34a",
                        }),
                        html.Span(r.get("recommendation", ""), style={
                            "fontSize": "0.75rem", "color": _C["text"],
                        }),
                    ]),
                ], style={"flex": "1"}),
                html.Div([
                    html.Div(f'{r.get("residual_risk", 0):.1f}', style={
                        "fontSize": "1.4rem", "fontWeight": "800",
                        "color": accent, "fontVariantNumeric": "tabular-nums",
                        "textAlign": "right", "lineHeight": "1",
                    }),
                    html.Div("risk score", style={
                        "fontSize": "0.62rem", "color": _C["text_dim"],
                        "textAlign": "right",
                    }),
                ], style={"flexShrink": "0"}),
            ], style={"display": "flex", "gap": "1rem", "alignItems": "flex-start"}),
        ], style={
            "padding": "1rem 1.2rem",
            "borderLeft": f"4px solid {accent}",
            "background": rinfo["bg"],
            "borderRadius": "0 10px 10px 0",
            "marginBottom": "0.75rem",
            "boxShadow": _C["shadow_sm"],
        }))

    return html.Div(cards)


# ── Main callback ─────────────────────────────────────────────────────────────

@callback(
    Output("host-detail-body", "children"),
    Input("host-select", "value"),
    Input("global-refresh", "n_intervals"),
    State("api-base-store", "data"),
)
def load_host_detail(hostname, _, base_url):
    if not hostname:
        return empty_state("Select a host above to view details.")
    base = get_base_url(base_url)
    try:
        ev = latest_evaluated(base, hostname)
    except Exception as e:
        return error_banner(f"Failed to load audit for {hostname}: {e}")

    ss          = get_score_summary(ev)
    ctrls       = normalize_controls(ev.get("results", []))
    raw_results = ev.get("results", [])

    # Add decision_source to normalized ctrls for table display
    raw_lookup = {r.get("control_id", ""): r for r in raw_results}
    for c in ctrls:
        c["decision_source"] = raw_lookup.get(c["control_id"], {}).get("decision_source", "")

    return html.Div([
        _zone1_header(ev, ss, ctrls),

        _section_label("Domain Compliance & Control Status"),
        _zone2_domain_and_status(ss, ctrls),

        _section_label("Top 5 Priority Risks"),
        _zone4_top_risks(ss),

        _section_label("All Controls"),
        _zone3_controls_table(ctrls, raw_results),
    ])


# ── Filter callback ───────────────────────────────────────────────────────────

@callback(
    Output("ctrl-table-container", "children"),
    Input("ctrl-status-filter", "value"),
    Input("ctrl-domain-filter", "value"),
    Input("ctrl-sev-filter", "value"),
    Input("expanded-ctrl", "data"),
    State("ctrls-store", "data"),
    State("raw-ctrl-store", "data"),
)
def filter_controls(status_f, domain_f, sev_f, expanded_id, ctrls, raw_results):
    if not ctrls:
        return empty_state()
    raw_lookup = {r.get("control_id", ""): r for r in (raw_results or [])}
    return _build_ctrl_rows(
        ctrls, raw_lookup,
        status_f or "ALL", domain_f or "ALL", sev_f or "ALL",
        expanded_id=expanded_id,
    )


# ── Toggle drawer callback ────────────────────────────────────────────────────

@callback(
    Output("expanded-ctrl", "data"),
    Input({"type": "ctrl-toggle", "index": dash.ALL}, "n_clicks"),
    State("expanded-ctrl", "data"),
    State({"type": "ctrl-toggle", "index": dash.ALL}, "id"),
    prevent_initial_call=True,
)
def toggle_drawer(n_clicks_list, current_expanded, ids):
    if not ctx.triggered_id:
        return current_expanded
    clicked_id = ctx.triggered_id.get("index")
    # Toggle: if same row clicked again, collapse
    if clicked_id == current_expanded:
        return None
    return clicked_id