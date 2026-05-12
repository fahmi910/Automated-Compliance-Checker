import dash
from dash import html, dcc, callback, Input, Output, State
import plotly.graph_objects as go
from helpers import (
    get_base_url, list_hosts, list_audits, evaluated_audit,
    get_score_summary, normalize_controls, fmt_dt, risk_key,
    RISK_MAP, risk_badge, status_badge, sev_badge,
    empty_state, error_banner,
)

dash.register_page(__name__, path="/history", name="History")

# ── CSS tokens ────────────────────────────────────────────────────────────────
_C = {
    "card":       "#ffffff",
    "bg":         "#f4f6fb",
    "border":     "#e5e9f2",
    "text":       "#374151",
    "text_dim":   "#9ca3af",
    "text_bright":"#111827",
    "blue":       "#2563eb",
    "blue_dim":   "rgba(37,99,235,0.08)",
    "shadow_sm":  "0 1px 3px rgba(0,0,0,0.06)",
    "radius_lg":  "14px",
}


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
        "Audit History",
        "Track compliance and risk trends over time for each host.",
    ),
    html.Div([
        html.Div([
            html.Label("Select Host", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": _C["text_dim"], "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(
                id="hist-host", placeholder="Choose a host…",
                className="dash-dropdown", style={"width": "300px"},
            ),
        ]),
        html.Div([
            html.Label("Max Audits", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": _C["text_dim"], "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Slider(
                id="hist-limit", min=5, max=50, step=5, value=20,
                marks={5: "5", 20: "20", 35: "35", 50: "50"},
                className="slider",
            ),
        ], style={"width": "260px"}),
    ], style={
        "display": "flex", "alignItems": "flex-end",
        "gap": "2rem", "marginBottom": "1.5rem", "flexWrap": "wrap",
    }),
    html.Div(id="history-body"),
], className="page")


# ── Host list loader ──────────────────────────────────────────────────────────

@callback(
    Output("hist-host", "options"),
    Output("hist-host", "value"),
    Input("global-refresh", "n_intervals"),
    Input("api-base-store", "data"),
)
def hist_hosts(_, base_url):
    base = get_base_url(base_url)
    try:
        names = [h["hostname"] for h in list_hosts(base).get("hosts", [])
                 if h.get("hostname")]
        return [{"label": n, "value": n} for n in names], (names[0] if names else None)
    except:
        return [], None


# ── Chart builders ────────────────────────────────────────────────────────────

def _dual_trend_chart(audit_records):
    """
    Combined compliance + risk score trend on one chart.
    audit_records: list of (label, compliance_score, risk_score)
    Oldest → newest left to right.
    """
    labels  = [r[0] for r in audit_records]
    comp    = [r[1] for r in audit_records]
    risk    = [r[2] for r in audit_records]

    fig = go.Figure()

    # Compliance line
    fig.add_trace(go.Scatter(
        x=labels, y=comp, name="Compliance %",
        mode="lines+markers",
        line=dict(color="#2563eb", width=2.5, shape="spline"),
        marker=dict(size=7, color="#2563eb", line=dict(color="white", width=2)),
        fill="tozeroy", fillcolor="rgba(37,99,235,0.06)",
        hovertemplate="<b>%{x}</b><br>Compliance: %{y:.1f}%<extra></extra>",
        yaxis="y",
    ))

    # Risk line (secondary y-axis, same scale 0-100)
    fig.add_trace(go.Scatter(
        x=labels, y=risk, name="Risk Score",
        mode="lines+markers",
        line=dict(color="#dc2626", width=2, shape="spline", dash="dot"),
        marker=dict(size=6, color="#dc2626", line=dict(color="white", width=2)),
        hovertemplate="<b>%{x}</b><br>Risk: %{y:.1f}<extra></extra>",
        yaxis="y",
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#ffffff",
        margin=dict(l=10, r=10, t=10, b=60),
        height=260,
        xaxis=dict(
            tickfont={"color": "#9ca3af", "size": 10},
            showgrid=False, linecolor="#e5e7eb",
            tickangle=-30,
        ),
        yaxis=dict(
            range=[0, 105],
            tickfont={"color": "#9ca3af", "size": 10},
            gridcolor="#f3f4f6", linecolor="#e5e7eb",
        ),
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02,
            xanchor="right", x=1,
            font={"size": 11, "color": "#6b7280"},
            bgcolor="rgba(0,0,0,0)",
        ),
        hovermode="x unified",
        font={"family": "DM Sans, sans-serif"},
    )
    return fig


# ── Delta card ────────────────────────────────────────────────────────────────

def _delta_card(latest_ss, prev_ss, latest_ctrls, prev_ctrls):
    """Compare latest audit against previous one."""

    def _delta_row(label, cur, prev, suffix="", invert=False):
        """invert=True means lower is better (risk score)."""
        if cur is None or prev is None:
            return None
        diff = cur - prev
        improved = diff > 0 if not invert else diff < 0
        neutral  = abs(diff) < 0.05
        color  = "#16a34a" if improved and not neutral else "#dc2626" if not improved and not neutral else "#9ca3af"
        arrow  = "↑" if diff > 0 else "↓" if diff < 0 else "→"
        return html.Div([
            html.Span(label, style={
                "fontSize": "0.75rem", "color": _C["text_dim"], "flex": "1",
            }),
            html.Div([
                html.Span(f"{cur:.1f}{suffix}", style={
                    "fontSize": "0.85rem", "fontWeight": "700",
                    "color": _C["text_bright"],
                }),
                html.Span(f" {arrow} {abs(diff):.1f}{suffix}", style={
                    "fontSize": "0.75rem", "fontWeight": "700",
                    "color": color, "marginLeft": "6px",
                }),
            ]),
        ], style={
            "display": "flex", "justifyContent": "space-between",
            "alignItems": "center",
            "padding": "0.55rem 0",
            "borderBottom": f"1px solid {_C['border']}",
        })

    c_cur  = latest_ss.get("compliance_score")
    c_prev = prev_ss.get("compliance_score")
    r_cur  = latest_ss.get("risk_score")
    r_prev = prev_ss.get("risk_score")

    # Controls that changed status
    prev_lookup = {c["control_id"]: c["status"] for c in prev_ctrls}
    changes = []
    for c in latest_ctrls:
        cid     = c["control_id"]
        new_st  = c["status"]
        old_st  = prev_lookup.get(cid)
        if old_st and old_st != new_st:
            changes.append((cid, c["title"], old_st, new_st, c["severity"]))

    change_items = []
    for cid, title, old_st, new_st, sev in changes[:6]:
        regressed = new_st == "FAIL" and old_st in ("PASS", "PARTIAL")
        improved  = new_st == "PASS" and old_st in ("FAIL", "PARTIAL")
        bg    = "#fef2f2" if regressed else "#f0fdf4" if improved else _C["bg"]
        arrow = "↓" if regressed else "↑" if improved else "→"
        arrow_color = "#dc2626" if regressed else "#16a34a" if improved else "#9ca3af"
        change_items.append(html.Div([
            html.Span(arrow, style={
                "color": arrow_color, "fontWeight": "800",
                "fontSize": "0.9rem", "marginRight": "6px", "flexShrink": "0",
            }),
            html.Div([
                html.Div(title, style={
                    "fontSize": "0.75rem", "fontWeight": "700",
                    "color": _C["text_bright"],
                }),
                html.Div([
                    html.Span(old_st, style={
                        "fontSize": "0.65rem", "color": _C["text_dim"],
                    }),
                    html.Span(" → ", style={"color": _C["text_dim"], "fontSize": "0.65rem"}),
                    html.Span(new_st, style={
                        "fontSize": "0.65rem", "fontWeight": "700",
                        "color": arrow_color,
                    }),
                ]),
            ], style={"flex": "1"}),
            sev_badge(sev),
        ], style={
            "display": "flex", "alignItems": "center", "gap": "6px",
            "padding": "0.5rem 0.6rem", "background": bg,
            "borderRadius": "6px", "marginBottom": "5px",
        }))

    return _card([
        html.Div("Changes Since Last Audit", style={
            "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
            "paddingBottom": "0.85rem", "marginBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div([
            _delta_row("Compliance Score", c_cur, c_prev, suffix="%", invert=False),
            _delta_row("Risk Score",       r_cur, r_prev, suffix="",  invert=True),
        ], style={"marginBottom": "1rem"}),
        html.Div("Control Status Changes", style={
            "fontSize": "0.72rem", "fontWeight": "700", "color": _C["text_dim"],
            "textTransform": "uppercase", "letterSpacing": "0.08em",
            "marginBottom": "0.6rem",
        }),
        html.Div(
            change_items if change_items
            else html.Div("No status changes since last audit.", style={
                "fontSize": "0.78rem", "color": _C["text_dim"],
                "textAlign": "center", "padding": "1rem 0",
            }),
        ),
    ], {"padding": "1.3rem 1.4rem"})


# ── Audit timeline ────────────────────────────────────────────────────────────

def _audit_timeline(audit_records, selected_idx=0):
    """
    audit_records: list of dicts with audit_id, label, compliance, risk_score, rk, n_controls
    """
    items = []
    for i, a in enumerate(audit_records):
        is_selected = (i == selected_idx)
        rinfo  = RISK_MAP.get(a["rk"], RISK_MAP["unknown"])
        accent = rinfo["color"]
        comp   = a["compliance"]
        rscore = a["risk_score"]

        items.append(html.Div([
            # Timeline dot
            html.Div(style={
                "width":        "10px",
                "height":       "10px",
                "borderRadius": "50%",
                "background":   accent if is_selected else _C["border"],
                "border":       f"2px solid {accent}",
                "flexShrink":   "0",
                "marginTop":    "6px",
            }),
            # Content
            html.Div([
                html.Div([
                    html.Span(f"Audit #{a['audit_id']}", style={
                        "fontSize": "0.78rem", "fontWeight": "700",
                        "color": _C["text_bright"] if is_selected else _C["text"],
                        "flex": "1",
                    }),
                    # Compliance score — blue
                    html.Span(
                        f"{comp:.0f}%" if comp is not None else "—",
                        style={
                            "fontSize": "0.75rem", "fontWeight": "800",
                            "color": "#2563eb",
                            "marginLeft": "0.5rem",
                            "fontVariantNumeric": "tabular-nums",
                        },
                    ),
                    # Risk score — red
                    html.Span(
                        f"{rscore:.1f}" if rscore is not None else "—",
                        style={
                            "fontSize": "0.75rem", "fontWeight": "800",
                            "color": "#dc2626",
                            "marginLeft": "0.6rem",
                            "fontVariantNumeric": "tabular-nums",
                        },
                    ),
                ], style={"display": "flex", "alignItems": "center"}),
                html.Div(a["label"], style={
                    "fontSize": "0.68rem", "color": _C["text_dim"],
                    "marginTop": "2px",
                }),
                html.Div([
                    risk_badge(a["rk"]),
                    html.Span(f'{a["n_controls"]} controls', style={
                        "fontSize": "0.65rem", "color": _C["text_dim"],
                        "marginLeft": "0.5rem",
                    }),
                ], style={"marginTop": "5px", "display": "flex", "alignItems": "center"}),
            ], style={"flex": "1"}),
        ], style={
            "display":     "flex",
            "gap":         "0.75rem",
            "padding":     "0.75rem 0.85rem",
            "background":  _C["blue_dim"] if is_selected else "transparent",
            "borderRadius":"8px",
            "borderLeft":  f"3px solid {accent}" if is_selected else f"3px solid transparent",
            "marginBottom":"4px",
            "cursor":      "pointer",
        }, id={"type": "audit-timeline-item", "index": i},
           n_clicks=0))

    # Legend indicators matching the trend chart colours
    legend = html.Div([
        html.Span(style={
            "display": "inline-block", "width": "18px", "height": "3px",
            "background": "#2563eb", "borderRadius": "2px",
            "marginRight": "4px", "verticalAlign": "middle",
        }),
        html.Span("Compliance", style={
            "fontSize": "0.65rem", "color": _C["text_dim"], "marginRight": "10px",
        }),
        html.Span(style={
            "display": "inline-block", "width": "18px", "height": "3px",
            "background": "#dc2626", "borderRadius": "2px",
            "borderTop": "2px dashed #dc2626", "height": "0",
            "marginRight": "4px", "verticalAlign": "middle",
        }),
        html.Span("Risk", style={
            "fontSize": "0.65rem", "color": _C["text_dim"],
        }),
    ], style={"display": "flex", "alignItems": "center"})

    return _card([
        html.Div([
            html.Div("Audit Timeline", style={
                "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
            }),
            legend,
        ], style={
            "display": "flex", "justifyContent": "space-between",
            "alignItems": "center",
            "paddingBottom": "0.85rem", "marginBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div(items, style={"overflowY": "auto", "maxHeight": "420px"}),
    ], {"padding": "1.3rem 1.4rem"})


# ── Selected audit controls table ─────────────────────────────────────────────

def _selected_audit_table(ev, audit_id, timestamp):
    ctrls = normalize_controls(ev.get("results", []))
    ctrls_sorted = sorted(ctrls, key=lambda c: (
        -{"high": 3, "medium": 2, "low": 1}.get(c["severity"], 0),
        -c.get("residual_risk", 0),
    ))

    th_style = {
        "padding": "0.6rem 1rem", "fontSize": "0.65rem", "fontWeight": "700",
        "color": _C["text_dim"], "textTransform": "uppercase",
        "letterSpacing": "0.07em", "background": _C["bg"],
        "borderBottom": f"1px solid {_C['border']}",
        "textAlign": "left", "whiteSpace": "nowrap",
    }

    header = html.Tr([
        html.Th("Control",      style=th_style),
        html.Th("Domain",       style=th_style),
        html.Th("Status",       style=th_style),
        html.Th("Severity",     style=th_style),
        html.Th("Residual Risk",style=th_style),
    ])

    rows = []
    for c in ctrls_sorted:
        rk     = c["severity"]
        accent = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]
        row_bg = "#fef2f2" if c["status"] == "FAIL" else \
                 "#fefce8" if c["status"] == "PARTIAL" else "#ffffff"

        def td(content, extra=None):
            return html.Td(content, style={
                "padding": "0.65rem 1rem",
                "borderBottom": f"1px solid {_C['border']}",
                "fontSize": "0.8rem", "color": _C["text"],
                **(extra or {}),
            })

        rows.append(html.Tr([
            td(html.Div([
                html.Div(c["control_id"], style={
                    "fontSize": "0.68rem", "fontWeight": "700",
                    "color": _C["blue"], "fontFamily": "monospace",
                }),
                html.Div(c["title"], style={
                    "fontSize": "0.78rem", "fontWeight": "600",
                    "color": _C["text_bright"],
                }),
            ])),
            td(c["domain"], {"color": _C["text_dim"]}),
            td(status_badge(c["status"])),
            td(sev_badge(c["severity"])),
            td(f'{c["residual_risk"]:.2f}', {
                "fontWeight": "700", "color": accent,
                "fontVariantNumeric": "tabular-nums",
            }),
        ], style={"background": row_bg}))

    ss    = get_score_summary(ev)
    comp  = ss.get("compliance_score")
    rscore= ss.get("risk_score")
    rk    = risk_key(rscore)
    accent= RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]

    return _card([
        html.Div([
            html.Div([
                html.Div(f"Audit #{audit_id}", style={
                    "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
                }),
                html.Div(timestamp, style={
                    "fontSize": "0.72rem", "color": _C["text_dim"], "marginTop": "2px",
                }),
            ]),
            html.Div([
                html.Span(
                    f"{comp:.0f}%" if comp is not None else "—",
                    style={
                        "fontSize": "1.3rem", "fontWeight": "800",
                        "color": accent, "fontVariantNumeric": "tabular-nums",
                    },
                ),
                html.Span(" compliance", style={
                    "fontSize": "0.72rem", "color": _C["text_dim"], "marginLeft": "4px",
                }),
                html.Div(risk_badge(rk), style={"marginTop": "4px"}),
            ], style={"textAlign": "right"}),
        ], style={
            "display": "flex", "justifyContent": "space-between",
            "alignItems": "flex-start",
            "paddingBottom": "0.85rem", "marginBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div(
            html.Table(
                [html.Thead(header), html.Tbody(rows)],
                style={"width": "100%", "borderCollapse": "collapse"},
            ),
            style={"overflowX": "auto"},
        ),
    ], {"padding": "1.3rem 1.4rem 0", "overflow": "hidden"})


# ── Main callback ─────────────────────────────────────────────────────────────

@callback(
    Output("history-body", "children"),
    Input("hist-host", "value"),
    Input("hist-limit", "value"),
    Input("global-refresh", "n_intervals"),
    State("api-base-store", "data"),
)
def load_history(hostname, limit, _, base_url):
    if not hostname:
        return empty_state("Select a host to view history.")
    base = get_base_url(base_url)

    try:
        audits = list_audits(base, hostname, limit or 20).get("audits", [])
    except Exception as e:
        return error_banner(f"Failed to load audits: {e}")

    if not audits:
        return empty_state("No audit records found for this host.")

    # Load all evaluated audits oldest → newest
    loaded = []
    for a in reversed(audits):
        try:
            ev    = evaluated_audit(base, a["audit_id"])
            ss    = get_score_summary(ev)
            rk    = risk_key(ss.get("risk_score"))
            comp  = ss.get("compliance_score")
            rscore= ss.get("risk_score")
            label = fmt_dt(a.get("received_at"))
            loaded.append({
                "audit_id":   a["audit_id"],
                "label":      label,
                "compliance": float(comp)  if comp   is not None else None,
                "risk_score": float(rscore)if rscore is not None else None,
                "rk":         rk,
                "n_controls": ev.get("evaluated_controls", 0),
                "ev":         ev,
                "ss":         ss,
            })
        except:
            pass

    if not loaded:
        return empty_state("Could not evaluate audit records.")

    # Trend chart data (oldest → newest)
    chart_records = [(a["label"], a["compliance"], a["risk_score"]) for a in loaded
                     if a["compliance"] is not None and a["risk_score"] is not None]

    # Timeline is newest → oldest
    timeline_records = list(reversed(loaded))

    # Latest and previous for delta card
    latest_ev    = loaded[-1]["ev"]
    latest_ss    = loaded[-1]["ss"]
    latest_ctrls = normalize_controls(latest_ev.get("results", []))

    has_prev   = len(loaded) >= 2
    prev_ev    = loaded[-2]["ev"] if has_prev else None
    prev_ss    = loaded[-2]["ss"] if has_prev else {}
    prev_ctrls = normalize_controls(prev_ev.get("results", [])) if prev_ev else []

    # ── Zone 1: Trend chart ────────────────────────────────────────────────
    trend_zone = html.Div()
    if len(chart_records) >= 2:
        trend_zone = _card([
            html.Div([
                html.Div("Compliance & Risk Trend", style={
                    "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
                }),
                html.Div([
                    html.Span("—", style={
                        "color": "#2563eb", "fontWeight": "700",
                        "marginRight": "4px", "fontSize": "1rem",
                    }),
                    html.Span("Compliance %", style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                        "marginRight": "1rem",
                    }),
                    html.Span("- -", style={
                        "color": "#dc2626", "fontWeight": "700",
                        "marginRight": "4px", "fontSize": "0.9rem",
                    }),
                    html.Span("Risk Score", style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                    }),
                ], style={"display": "flex", "alignItems": "center"}),
            ], style={
                "display": "flex", "justifyContent": "space-between",
                "alignItems": "center",
                "paddingBottom": "0.85rem", "marginBottom": "0.5rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            dcc.Graph(
                figure=_dual_trend_chart(chart_records),
                config={"displayModeBar": False},
                style={"height": "260px"},
            ),
        ], {"padding": "1.3rem 1.4rem 0.5rem"})

    # ── Zone 2: Timeline + Delta ───────────────────────────────────────────
    timeline_zone = html.Div([
        html.Div(
            html.Div(
                _audit_timeline(timeline_records, selected_idx=0),
                id="timeline-container",
            ),
            style={"gridColumn": "1 / 2"},
        ),
        html.Div(
            _delta_card(latest_ss, prev_ss, latest_ctrls, prev_ctrls)
            if has_prev else _card([
                html.Div("Changes Since Last Audit", style={
                    "fontSize": "1rem", "fontWeight": "700",
                    "color": _C["text_bright"],
                    "paddingBottom": "0.85rem", "marginBottom": "0.85rem",
                    "borderBottom": f"1px solid {_C['border']}",
                }),
                html.Div("Only one audit available — run another audit to see changes.", style={
                    "fontSize": "0.78rem", "color": _C["text_dim"],
                    "textAlign": "center", "padding": "2rem 0",
                }),
            ], {"padding": "1.3rem 1.4rem"}),
            style={"gridColumn": "2 / 3"},
        ),
    ], style={
        "display": "grid", "gridTemplateColumns": "1fr 1fr",
        "gap": "1rem", "alignItems": "start",
    })

    # Store all loaded audit data for the selected audit callback
    store_data = [
        {
            "audit_id":  a["audit_id"],
            "label":     a["label"],
            "compliance":a["compliance"],
            "risk_score":a["risk_score"],
            "rk":        a["rk"],
            "n_controls":a["n_controls"],
        }
        for a in loaded
    ]
    # Store full evaluated payloads indexed by audit_id
    ev_store = {str(a["audit_id"]): a["ev"] for a in loaded}

    # ── Zone 3: Selected audit detail (default = latest) ──────────────────
    latest = loaded[-1]
    selected_table = _selected_audit_table(
        latest["ev"], latest["audit_id"], latest["label"]
    )

    return html.Div([
        _section_label("Compliance & Risk Trend"),
        trend_zone,
        _section_label("Audit Timeline & Changes"),
        timeline_zone,
        html.Div([
            _section_label("Audit Control Results"),
        ], id="selected-audit-label"),
        html.Div(selected_table, id="selected-audit-table"),
        dcc.Store(id="hist-loaded-store",  data=store_data),
        dcc.Store(id="hist-ev-store",      data=ev_store),
        dcc.Store(id="hist-selected-idx",  data=0),
    ])

# ── Timeline click → update selected audit ────────────────────────────────────

@callback(
    Output("hist-selected-idx",   "data"),
    Output("timeline-container",  "children"),
    Output("selected-audit-table","children"),
    Input({"type": "audit-timeline-item", "index": dash.ALL}, "n_clicks"),
    State("hist-selected-idx", "data"),
    State("hist-loaded-store", "data"),
    State("hist-ev-store",     "data"),
    State({"type": "audit-timeline-item", "index": dash.ALL}, "id"),
    prevent_initial_call=True,
)
def timeline_select(n_clicks_list, current_idx, store_data, ev_store, ids):
    from dash import ctx
    if not ctx.triggered_id:
        return current_idx, dash.no_update, dash.no_update

    new_idx = ctx.triggered_id.get("index", current_idx or 0)

    # Rebuild timeline with new highlight
    if store_data:
        timeline_records = list(reversed(store_data))
        new_timeline = _audit_timeline(timeline_records, selected_idx=new_idx)
    else:
        new_timeline = dash.no_update

    # Rebuild selected audit table
    if store_data and ev_store:
        timeline = list(reversed(store_data))
        if new_idx >= len(timeline):
            new_idx = 0
        meta = timeline[new_idx]
        ev   = ev_store.get(str(meta["audit_id"]))
        new_table = (
            _selected_audit_table(ev, meta["audit_id"], meta["label"])
            if ev else empty_state(f"Could not load audit #{meta['audit_id']}.")
        )
    else:
        new_table = dash.no_update

    return new_idx, new_timeline, new_table