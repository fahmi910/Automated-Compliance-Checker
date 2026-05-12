import dash
from dash import html, dcc, callback, Input, Output, State
import plotly.graph_objects as go
from helpers import (
    get_base_url, list_hosts, list_audits, latest_evaluated,
    evaluated_audit, get_score_summary, normalize_controls,
    fmt_dt, risk_key, sev_key, RISK_MAP,
    risk_badge, status_badge, sev_badge,
    empty_state, error_banner,
)

dash.register_page(__name__, path="/compare", name="Compare")

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

DOMAIN_ORDER = [
    "Access Control",
    "Logging & Monitoring",
    "Asset & Configuration Management",
    "Cryptography",
    "Backup & Recovery",
]


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


def _score_accent(score):
    if score is None: return "#6b7280"
    return "#16a34a" if score >= 70 else "#ca8a04" if score >= 40 else "#dc2626"


def _page_header():
    return html.Div([
        html.Div([
            html.H1("Compare Hosts", style={
                "fontSize": "1.65rem", "fontWeight": "800",
                "color": _C["text_bright"], "letterSpacing": "-0.03em",
                "margin": "0 0 4px 0",
            }),
            html.Div(
                "Identify shared vulnerabilities and measure remediation progress across hosts.",
                style={"fontSize": "0.78rem", "color": _C["text_dim"]},
            ),
        ]),
    ], style={"marginBottom": "1.25rem"})


# ── Mode toggle ───────────────────────────────────────────────────────────────

def _mode_toggle(mode):
    def _btn(label, val):
        active = (mode == val)
        return html.Button(label, id={"type": "mode-btn", "index": val}, n_clicks=0, style={
            "padding":        "6px 18px",
            "fontSize":       "0.8rem",
            "fontWeight":     "700",
            "border":         f"1px solid {_C['blue'] if active else _C['border']}",
            "borderRadius":   "8px",
            "background":     _C["blue"] if active else _C["card"],
            "color":          "#ffffff" if active else _C["text_dim"],
            "cursor":         "pointer",
            "transition":     "all 0.15s ease",
        })
    return html.Div([
        _btn("Fleet View",    "fleet"),
        _btn("Head-to-Head",  "h2h"),
        _btn("Session Diff",  "session"),
    ], style={"display": "flex", "gap": "0.5rem", "marginBottom": "1.25rem"})


# ══════════════════════════════════════════════════════════════════════════════
# FLEET VIEW
# ══════════════════════════════════════════════════════════════════════════════

def _fleet_compliance_chart(host_data):
    """
    host_data: list of (hostname, compliance_score, risk_key)
    Horizontal bar chart sorted worst → best.
    """
    sorted_data = sorted(host_data, key=lambda x: (x[1] or 0))
    labels  = [d[0] for d in sorted_data]
    values  = [d[1] or 0 for d in sorted_data]
    colors  = [RISK_MAP.get(_score_rk(d[1]), RISK_MAP["unknown"])["color"] for d in sorted_data]

    fig = go.Figure(go.Bar(
        y=labels, x=values,
        orientation="h",
        marker_color=colors,
        marker_line_width=0,
        text=[f"{v:.0f}%" for v in values],
        textposition="inside",
        textfont=dict(color="white", size=12, family="DM Sans, sans-serif"),
        hovertemplate="<b>%{y}</b><br>Compliance: %{x:.1f}%<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#ffffff",
        margin=dict(l=10, r=30, t=10, b=10),
        height=max(120, len(labels) * 60),
        xaxis=dict(range=[0, 105], tickfont={"color": "#9ca3af", "size": 10},
                   gridcolor="#f3f4f6", linecolor="#e5e7eb"),
        yaxis=dict(tickfont={"color": "#374151", "size": 12, "family": "DM Sans, sans-serif"},
                   showgrid=False),
        bargap=0.35,
        font={"family": "DM Sans, sans-serif"},
    )
    return fig


def _score_rk(score):
    if score is None: return "unknown"
    return "severe" if score < 20 else "critical" if score < 40 else \
           "high" if score < 70 else "moderate" if score < 90 else "low"


def _fleet_domain_heatmap(all_host_domain_data):
    """
    all_host_domain_data: dict { hostname: { domain: compliance_score } }
    Renders a host × domain grid with colour-coded cells.
    """
    hostnames = list(all_host_domain_data.keys())
    if not hostnames:
        return html.Div()

    th_style = {
        "padding": "0.55rem 0.75rem", "fontSize": "0.65rem", "fontWeight": "700",
        "color": _C["text_dim"], "textTransform": "uppercase",
        "letterSpacing": "0.07em", "background": _C["bg"],
        "borderBottom": f"1px solid {_C['border']}",
        "textAlign": "center", "whiteSpace": "nowrap",
    }

    header = html.Tr([
        html.Th("Host", style={**th_style, "textAlign": "left"}),
        *[html.Th(d.replace(" & ", " &\u200b"), style=th_style) for d in DOMAIN_ORDER],
    ])

    rows = []
    for hostname in hostnames:
        domain_scores = all_host_domain_data[hostname]
        cells = [html.Td(hostname, style={
            "padding": "0.6rem 0.75rem", "fontSize": "0.78rem",
            "fontWeight": "700", "color": _C["text_bright"],
            "borderBottom": f"1px solid {_C['border']}",
            "whiteSpace": "nowrap",
        })]
        for domain in DOMAIN_ORDER:
            score = domain_scores.get(domain)
            rk    = _score_rk(score)
            rinfo = RISK_MAP.get(rk, RISK_MAP["unknown"])
            cells.append(html.Td(
                html.Div([
                    html.Div(f"{score:.0f}%" if score is not None else "—", style={
                        "fontSize": "0.82rem", "fontWeight": "800",
                        "color": rinfo["color"],
                        "fontVariantNumeric": "tabular-nums",
                    }),
                    html.Div(rk.capitalize(), style={
                        "fontSize": "0.6rem", "color": rinfo["text"],
                        "fontWeight": "600",
                    }),
                ], style={"textAlign": "center"}),
                style={
                    "padding": "0.55rem 0.75rem",
                    "background": rinfo["bg"],
                    "border": f"1px solid {_C['border']}",
                    "borderBottom": f"1px solid {_C['border']}",
                },
            ))
        rows.append(html.Tr(cells))

    return _card(
        html.Div(
            html.Table(
                [html.Thead(header), html.Tbody(rows)],
                style={"width": "100%", "borderCollapse": "collapse"},
            ),
            style={"overflowX": "auto"},
        ),
        {"padding": "0", "overflow": "hidden"},
    )


def _fleet_shared_failures(all_host_ctrls):
    """
    all_host_ctrls: dict { hostname: [normalized_ctrl, ...] }
    Find controls failing on 2+ hosts.
    """
    from collections import defaultdict
    fail_map = defaultdict(list)   # control_id → [(hostname, ctrl)]

    for hostname, ctrls in all_host_ctrls.items():
        for c in ctrls:
            if c["status"] == "FAIL":
                fail_map[c["control_id"]].append((hostname, c))

    shared = [(cid, entries) for cid, entries in fail_map.items() if len(entries) >= 2]
    shared.sort(key=lambda x: (-len(x[1]), -{"high":3,"medium":2,"low":1}.get(
        x[1][0][1].get("severity",""), 0)))

    if not shared:
        return _card(
            html.Div("No controls are failing on multiple hosts.", style={
                "textAlign": "center", "color": _C["text_dim"],
                "fontSize": "0.82rem", "padding": "2rem 0",
            }),
            {"padding": "1.3rem 1.4rem"},
        )

    th_style = {
        "padding": "0.6rem 1rem", "fontSize": "0.65rem", "fontWeight": "700",
        "color": _C["text_dim"], "textTransform": "uppercase",
        "letterSpacing": "0.07em", "background": _C["bg"],
        "borderBottom": f"1px solid {_C['border']}",
        "textAlign": "left", "whiteSpace": "nowrap",
    }

    header = html.Tr([
        html.Th("Affected", style={**th_style, "width": "60px"}),
        html.Th("Control",  style=th_style),
        html.Th("Domain",   style=th_style),
        html.Th("Severity", style=th_style),
        html.Th("Hosts",    style=th_style),
    ])

    body_rows = []
    for cid, entries in shared:
        sample  = entries[0][1]
        sev     = sample.get("severity", "")
        accent  = RISK_MAP.get(sev_key(sev), RISK_MAP["unknown"])["color"]
        hosts_affected = [hn for hn, _ in entries]

        body_rows.append(html.Tr([
            html.Td(
                html.Span(str(len(entries)), style={
                    "fontSize": "1rem", "fontWeight": "800", "color": accent,
                    "fontVariantNumeric": "tabular-nums",
                }),
                style={"padding": "0.7rem 1rem",
                       "borderBottom": f"1px solid {_C['border']}"},
            ),
            html.Td(html.Div([
                html.Div(cid, style={
                    "fontSize": "0.68rem", "fontWeight": "700",
                    "color": _C["blue"], "fontFamily": "monospace",
                }),
                html.Div(sample.get("title", ""), style={
                    "fontSize": "0.78rem", "fontWeight": "600",
                    "color": _C["text_bright"],
                }),
            ]), style={"padding": "0.7rem 1rem",
                       "borderBottom": f"1px solid {_C['border']}"}),
            html.Td(sample.get("domain", "—"), style={
                "padding": "0.7rem 1rem", "fontSize": "0.78rem",
                "color": _C["text_dim"],
                "borderBottom": f"1px solid {_C['border']}",
            }),
            html.Td(sev_badge(sev), style={
                "padding": "0.7rem 1rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            html.Td(
                html.Div([
                    html.Span(hn, style={
                        "fontSize": "0.68rem", "fontWeight": "600",
                        "color": _C["blue"], "background": _C["blue_dim"],
                        "borderRadius": "4px", "padding": "2px 6px",
                        "marginRight": "4px",
                    }) for hn in hosts_affected
                ]),
                style={"padding": "0.7rem 1rem",
                       "borderBottom": f"1px solid {_C['border']}"},
            ),
        ], style={"background": "#fef2f2"}))

    return _card(
        html.Div(
            html.Table(
                [html.Thead(header), html.Tbody(body_rows)],
                style={"width": "100%", "borderCollapse": "collapse"},
            ),
            style={"overflowX": "auto"},
        ),
        {"padding": "0", "overflow": "hidden"},
    )


def _build_fleet_view(base, hosts):
    host_data         = []   # (hostname, compliance, rk)
    all_host_domain   = {}   # hostname → {domain → score}
    all_host_ctrls    = {}   # hostname → [ctrls]
    errors            = []

    for h in hosts:
        hostname = h.get("hostname")
        if not hostname:
            continue
        try:
            ev    = latest_evaluated(base, hostname)
            ss    = get_score_summary(ev)
            ctrls = normalize_controls(ev.get("results", []))
            comp  = ss.get("compliance_score")
            rk    = risk_key(ss.get("risk_score"))

            host_data.append((hostname, comp, rk))
            all_host_ctrls[hostname] = ctrls

            domain_scores = ss.get("domain_scores", {})
            all_host_domain[hostname] = {
                d: info.get("compliance_score")
                for d, info in domain_scores.items()
            }
        except Exception as e:
            errors.append(f"{hostname}: {e}")

    if not host_data:
        return empty_state("No host data could be loaded.")

    # Chart card
    chart_card = _card([
        html.Div("Compliance Score by Host", style={
            "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
            "paddingBottom": "0.85rem", "marginBottom": "0.5rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        dcc.Graph(
            figure=_fleet_compliance_chart(host_data),
            config={"displayModeBar": False},
            style={"height": f"{max(120, len(host_data) * 60)}px"},
        ),
    ], {"padding": "1.3rem 1.4rem 0.5rem"})

    return html.Div([
        _section_label("Fleet Compliance Overview"),
        chart_card,

        _section_label("Domain Health Heatmap"),
        _fleet_domain_heatmap(all_host_domain),

        _section_label("Shared Failures — Controls Failing on Multiple Hosts"),
        _fleet_shared_failures(all_host_ctrls),

        html.Div([
            html.Span("Use Head-to-Head mode to diff two specific hosts in detail.",
                      style={"fontSize": "0.72rem", "color": _C["text_dim"]}),
        ], style={"marginTop": "1rem", "textAlign": "center"}),
    ])


# ══════════════════════════════════════════════════════════════════════════════
# HEAD-TO-HEAD VIEW
# ══════════════════════════════════════════════════════════════════════════════

def _h2h_score_strip(ssA, ssB, hn_a, hn_b):
    """Side-by-side score cards with delta in the middle."""
    c_a  = ssA.get("compliance_score")
    c_b  = ssB.get("compliance_score")
    r_a  = ssA.get("risk_score")
    r_b  = ssB.get("risk_score")
    rk_a = risk_key(r_a)
    rk_b = risk_key(r_b)

    def _score_col(hostname, comp, rscore, rk, align):
        accent = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]
        return html.Div([
            html.Div(hostname, style={
                "fontSize": "0.82rem", "fontWeight": "700",
                "color": _C["blue"], "marginBottom": "0.75rem",
                "textAlign": align,
            }),
            html.Div(
                f"{comp:.0f}%" if comp is not None else "—",
                style={
                    "fontSize": "2.4rem", "fontWeight": "800",
                    "color": accent, "lineHeight": "1",
                    "fontVariantNumeric": "tabular-nums",
                    "letterSpacing": "-0.03em", "textAlign": align,
                    "marginBottom": "0.35rem",
                },
            ),
            html.Div("compliance", style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
                "textAlign": align, "marginBottom": "0.5rem",
            }),
            html.Div(f"Risk: {rscore:.1f}" if rscore else "Risk: —", style={
                "fontSize": "0.78rem", "fontWeight": "600",
                "color": _C["text"], "textAlign": align,
                "marginBottom": "0.4rem",
            }),
            html.Div(risk_badge(rk), style={"textAlign": align}),
        ], style={"flex": "1"})

    # Delta column
    dc = round(float(c_b) - float(c_a), 1) if c_a and c_b else None
    dr = round(float(r_b) - float(r_a), 1) if r_a and r_b else None

    def _delta_item(label, val, invert=False):
        if val is None:
            return html.Div("—", style={"color": _C["text_dim"], "fontSize": "0.75rem"})
        improved = (val < 0) if invert else (val > 0)
        color    = "#16a34a" if improved else "#dc2626" if val != 0 else "#9ca3af"
        arrow    = "↑" if val > 0 else "↓" if val < 0 else "→"
        return html.Div([
            html.Div(f"{arrow} {abs(val):.1f}", style={
                "fontSize": "1.1rem", "fontWeight": "800",
                "color": color, "textAlign": "center",
            }),
            html.Div(label, style={
                "fontSize": "0.62rem", "color": _C["text_dim"],
                "textAlign": "center", "marginTop": "2px",
            }),
        ], style={"marginBottom": "0.75rem"})

    delta_col = html.Div([
        html.Div("Delta", style={
            "fontSize": "0.62rem", "fontWeight": "700", "color": _C["text_dim"],
            "textTransform": "uppercase", "letterSpacing": "0.1em",
            "textAlign": "center", "marginBottom": "0.75rem",
        }),
        _delta_item("Compliance", dc,  invert=False),
        _delta_item("Risk Score", dr,  invert=True),
    ], style={
        "width": "80px", "flexShrink": "0",
        "padding": "0 0.75rem",
        "borderLeft":  f"1px solid {_C['border']}",
        "borderRight": f"1px solid {_C['border']}",
    })

    return _card([
        html.Div([
            _score_col(hn_a, c_a, r_a, rk_a, "left"),
            delta_col,
            _score_col(hn_b, c_b, r_b, rk_b, "right"),
        ], style={"display": "flex", "alignItems": "flex-start", "gap": "0"}),
    ], {"padding": "1.3rem 1.6rem"})


def _h2h_domain_bars(ssA, ssB, hn_a, hn_b):
    """Domain comparison bars — sorted by gap (biggest first)."""
    ds_a = ssA.get("domain_scores", {})
    ds_b = ssB.get("domain_scores", {})
    all_domains = set(ds_a) | set(ds_b)

    domain_rows = []
    for d in DOMAIN_ORDER:
        if d not in all_domains:
            continue
        score_a = (ds_a.get(d) or {}).get("compliance_score")
        score_b = (ds_b.get(d) or {}).get("compliance_score")
        gap = abs((score_a or 0) - (score_b or 0))
        domain_rows.append((d, score_a, score_b, gap))

    domain_rows.sort(key=lambda x: -x[3])   # biggest gap first

    rows = []
    for dname, score_a, score_b, gap in domain_rows:
        pct_a = float(score_a) if score_a is not None else 0.0
        pct_b = float(score_b) if score_b is not None else 0.0
        acc_a = _score_accent(score_a)
        acc_b = _score_accent(score_b)

        rows.append(html.Div([
            # Domain name + gap badge
            html.Div([
                html.Div(dname, style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": _C["text_bright"],
                }),
                html.Span(f"Δ {gap:.0f}", style={
                    "fontSize": "0.65rem", "fontWeight": "700",
                    "color": "#dc2626" if gap > 20 else "#ca8a04" if gap > 5 else "#16a34a",
                    "background": "#fef2f2" if gap > 20 else "#fefce8" if gap > 5 else "#f0fdf4",
                    "border": "1px solid #fca5a5" if gap > 20 else "1px solid #fde047" if gap > 5 else "1px solid #86efac",
                    "borderRadius": "999px", "padding": "1px 7px",
                }) if gap > 0 else None,
            ], style={
                "display": "flex", "justifyContent": "space-between",
                "alignItems": "center", "marginBottom": "6px",
            }),
            # Host A bar
            html.Div([
                html.Div(hn_a[:14], style={
                    "fontSize": "0.65rem", "color": _C["text_dim"],
                    "width": "100px", "flexShrink": "0",
                }),
                html.Div(
                    html.Div(style={
                        "width": f"{min(pct_a,100)}%", "height": "100%",
                        "background": acc_a, "borderRadius": "3px", "minWidth": "2px",
                    }),
                    style={"flex": "1", "height": "9px", "background": _C["bg"],
                           "borderRadius": "3px", "overflow": "hidden",
                           "border": f"1px solid {_C['border']}", "margin": "0 0.5rem"},
                ),
                html.Span(f"{pct_a:.0f}%", style={
                    "fontSize": "0.72rem", "fontWeight": "700", "color": acc_a,
                    "width": "34px", "textAlign": "right",
                    "fontVariantNumeric": "tabular-nums",
                }),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "4px"}),
            # Host B bar
            html.Div([
                html.Div(hn_b[:14], style={
                    "fontSize": "0.65rem", "color": _C["text_dim"],
                    "width": "100px", "flexShrink": "0",
                }),
                html.Div(
                    html.Div(style={
                        "width": f"{min(pct_b,100)}%", "height": "100%",
                        "background": acc_b, "borderRadius": "3px", "minWidth": "2px",
                    }),
                    style={"flex": "1", "height": "9px", "background": _C["bg"],
                           "borderRadius": "3px", "overflow": "hidden",
                           "border": f"1px solid {_C['border']}", "margin": "0 0.5rem"},
                ),
                html.Span(f"{pct_b:.0f}%", style={
                    "fontSize": "0.72rem", "fontWeight": "700", "color": acc_b,
                    "width": "34px", "textAlign": "right",
                    "fontVariantNumeric": "tabular-nums",
                }),
            ], style={"display": "flex", "alignItems": "center"}),
        ], style={
            "padding": "0.85rem 0",
            "borderBottom": f"1px solid {_C['border']}",
        }))

    return _card([
        html.Div("Domain Comparison — Sorted by Gap", style={
            "fontSize": "1rem", "fontWeight": "700", "color": _C["text_bright"],
            "paddingBottom": "0.85rem", "marginBottom": "0.5rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div(rows),
    ], {"padding": "1.3rem 1.4rem"})


def _h2h_diff_table(ctrlsA, ctrlsB, hn_a, hn_b):
    """Controls with different status between the two hosts."""
    all_ids = sorted(set(ctrlsA) | set(ctrlsB))
    diff_rows = []
    improved = regressed = unchanged_fail = 0

    for cid in all_ids:
        ca = ctrlsA.get(cid, {})
        cb = ctrlsB.get(cid, {})
        sa = ca.get("status", "—")
        sb = cb.get("status", "—")
        if sa == sb:
            if sa == "FAIL":
                unchanged_fail += 1
            continue
        sample = cb if cb else ca
        if sb == "PASS" and sa in ("FAIL", "PARTIAL"):
            improved += 1
        elif sb == "FAIL" and sa in ("PASS", "PARTIAL"):
            regressed += 1

        row_bg = "#fef2f2" if sb == "FAIL" else "#f0fdf4" if sb == "PASS" else "#fefce8"
        diff_rows.append({
            "cid":    cid,
            "title":  sample.get("title", ""),
            "domain": sample.get("domain", ""),
            "sev":    sample.get("severity", ""),
            "sa":     sa,
            "sb":     sb,
            "bg":     row_bg,
        })

    # Summary counters
    summary = html.Div([
        html.Div([
            html.Span(str(improved), style={
                "fontSize": "1.4rem", "fontWeight": "800", "color": "#16a34a",
                "fontVariantNumeric": "tabular-nums",
            }),
            html.Div(f"{hn_b} improved", style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
            }),
        ], style={"textAlign": "center", "flex": "1"}),
        html.Div(style={"width": "1px", "background": _C["border"], "margin": "0 1rem"}),
        html.Div([
            html.Span(str(regressed), style={
                "fontSize": "1.4rem", "fontWeight": "800", "color": "#dc2626",
                "fontVariantNumeric": "tabular-nums",
            }),
            html.Div(f"{hn_b} regressed", style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
            }),
        ], style={"textAlign": "center", "flex": "1"}),
        html.Div(style={"width": "1px", "background": _C["border"], "margin": "0 1rem"}),
        html.Div([
            html.Span(str(unchanged_fail), style={
                "fontSize": "1.4rem", "fontWeight": "800", "color": "#ca8a04",
                "fontVariantNumeric": "tabular-nums",
            }),
            html.Div("both still failing", style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
            }),
        ], style={"textAlign": "center", "flex": "1"}),
    ], style={
        "display": "flex", "alignItems": "center",
        "padding": "1rem 0", "marginBottom": "0.85rem",
        "borderBottom": f"1px solid {_C['border']}",
    })

    if not diff_rows:
        return _card([
            summary,
            html.Div("No status differences between these two hosts.", style={
                "textAlign": "center", "color": _C["text_dim"],
                "fontSize": "0.82rem", "padding": "1.5rem 0",
            }),
        ], {"padding": "1.3rem 1.4rem"})

    th_style = {
        "padding": "0.6rem 1rem", "fontSize": "0.65rem", "fontWeight": "700",
        "color": _C["text_dim"], "textTransform": "uppercase",
        "letterSpacing": "0.07em", "background": _C["bg"],
        "borderBottom": f"1px solid {_C['border']}",
        "textAlign": "left", "whiteSpace": "nowrap",
    }

    header = html.Tr([
        html.Th("Control",       style=th_style),
        html.Th("Domain",        style=th_style),
        html.Th("Severity",      style=th_style),
        html.Th(hn_a,            style={**th_style, "color": "#2563eb"}),
        html.Th(hn_b,            style={**th_style, "color": "#7c3aed"}),
    ])

    body_rows = []
    for r in diff_rows:
        body_rows.append(html.Tr([
            html.Td(html.Div([
                html.Div(r["cid"], style={
                    "fontSize": "0.68rem", "fontWeight": "700",
                    "color": _C["blue"], "fontFamily": "monospace",
                }),
                html.Div(r["title"], style={
                    "fontSize": "0.78rem", "fontWeight": "600",
                    "color": _C["text_bright"],
                }),
            ]), style={"padding": "0.7rem 1rem",
                       "borderBottom": f"1px solid {_C['border']}"}),
            html.Td(r["domain"], style={
                "padding": "0.7rem 1rem", "fontSize": "0.78rem",
                "color": _C["text_dim"],
                "borderBottom": f"1px solid {_C['border']}",
            }),
            html.Td(sev_badge(r["sev"]), style={
                "padding": "0.7rem 1rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            html.Td(status_badge(r["sa"]), style={
                "padding": "0.7rem 1rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            html.Td(status_badge(r["sb"]), style={
                "padding": "0.7rem 1rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
        ], style={"background": r["bg"]}))

    return _card([
        summary,
        html.Div(
            html.Table(
                [html.Thead(header), html.Tbody(body_rows)],
                style={"width": "100%", "borderCollapse": "collapse"},
            ),
            style={"overflowX": "auto"},
        ),
    ], {"padding": "1.3rem 1.4rem 0", "overflow": "hidden"})


def _build_h2h_view(base, hn_a, hn_b):
    if not hn_a or not hn_b:
        return empty_state("Select two hosts above to compare.")
    if hn_a == hn_b:
        return error_banner("Please select two different hosts.")
    try:
        ev_a = latest_evaluated(base, hn_a)
        ev_b = latest_evaluated(base, hn_b)
    except Exception as e:
        return error_banner(f"Failed to load host data: {e}")

    ss_a = get_score_summary(ev_a)
    ss_b = get_score_summary(ev_b)
    ctrls_a = {c["control_id"]: c for c in normalize_controls(ev_a.get("results", []))}
    ctrls_b = {c["control_id"]: c for c in normalize_controls(ev_b.get("results", []))}

    return html.Div([
        _section_label("Score Comparison"),
        _h2h_score_strip(ss_a, ss_b, hn_a, hn_b),
        _section_label("Domain Comparison"),
        _h2h_domain_bars(ss_a, ss_b, hn_a, hn_b),
        _section_label("Control Diff — Status Differences Only"),
        _h2h_diff_table(ctrls_a, ctrls_b, hn_a, hn_b),
    ])



# ══════════════════════════════════════════════════════════════════════════════
# SESSION DIFF VIEW
# ══════════════════════════════════════════════════════════════════════════════

def _build_session_view(base, sess_host, sess_a_id, sess_b_id):
    """Compare two audit sessions for the same host."""
    if not sess_host:
        return empty_state("Select a host to compare sessions.")
    if not sess_a_id or not sess_b_id:
        return empty_state("Select two audit sessions above.")
    if sess_a_id == sess_b_id:
        return error_banner("Please select two different audit sessions.")

    try:
        ev_a = evaluated_audit(base, sess_a_id)
        ev_b = evaluated_audit(base, sess_b_id)
    except Exception as e:
        return error_banner(f"Failed to load sessions: {e}")

    ss_a = get_score_summary(ev_a)
    ss_b = get_score_summary(ev_b)
    label_a = f"Session #{sess_a_id}  ·  {fmt_dt(ev_a.get('received_at'))}"
    label_b = f"Session #{sess_b_id}  ·  {fmt_dt(ev_b.get('received_at'))}"

    # Score strip — reuse h2h components with session labels
    ctrls_a = {c["control_id"]: c for c in normalize_controls(ev_a.get("results", []))}
    ctrls_b = {c["control_id"]: c for c in normalize_controls(ev_b.get("results", []))}

    c_a  = ss_a.get("compliance_score")
    c_b  = ss_b.get("compliance_score")
    r_a  = ss_a.get("risk_score")
    r_b  = ss_b.get("risk_score")
    rk_a = risk_key(r_a)
    rk_b = risk_key(r_b)
    dc   = round(float(c_b) - float(c_a), 1) if c_a and c_b else None
    dr   = round(float(r_b) - float(r_a), 1) if r_a and r_b else None

    def _delta_item(label, val, invert=False):
        if val is None:
            return html.Div("—", style={"color": _C["text_dim"], "fontSize": "0.75rem"})
        improved = (val < 0) if invert else (val > 0)
        color    = "#16a34a" if improved else "#dc2626" if val != 0 else "#9ca3af"
        arrow    = "↑" if val > 0 else "↓" if val < 0 else "→"
        return html.Div([
            html.Div(f"{arrow} {abs(val):.1f}", style={
                "fontSize": "1.1rem", "fontWeight": "800",
                "color": color, "textAlign": "center",
            }),
            html.Div(label, style={
                "fontSize": "0.62rem", "color": _C["text_dim"],
                "textAlign": "center", "marginTop": "2px",
            }),
        ], style={"marginBottom": "0.75rem"})

    def _sess_col(label, comp, rscore, rk, align):
        accent = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]
        return html.Div([
            html.Div(label, style={
                "fontSize": "0.72rem", "fontWeight": "700",
                "color": _C["text_dim"], "marginBottom": "0.75rem",
                "textAlign": align,
            }),
            html.Div(
                f"{comp:.0f}%" if comp is not None else "—",
                style={
                    "fontSize": "2.4rem", "fontWeight": "800", "color": accent,
                    "lineHeight": "1", "fontVariantNumeric": "tabular-nums",
                    "letterSpacing": "-0.03em", "textAlign": align,
                    "marginBottom": "0.35rem",
                },
            ),
            html.Div("compliance", style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
                "textAlign": align, "marginBottom": "0.5rem",
            }),
            html.Div(f"Risk: {rscore:.1f}" if rscore else "Risk: —", style={
                "fontSize": "0.78rem", "fontWeight": "600",
                "color": _C["text"], "textAlign": align,
                "marginBottom": "0.4rem",
            }),
            html.Div(risk_badge(rk), style={"textAlign": align}),
        ], style={"flex": "1"})

    delta_col = html.Div([
        html.Div("Delta", style={
            "fontSize": "0.62rem", "fontWeight": "700", "color": _C["text_dim"],
            "textTransform": "uppercase", "letterSpacing": "0.1em",
            "textAlign": "center", "marginBottom": "0.75rem",
        }),
        _delta_item("Compliance", dc,  invert=False),
        _delta_item("Risk Score", dr,  invert=True),
    ], style={
        "width": "80px", "flexShrink": "0", "padding": "0 0.75rem",
        "borderLeft": f"1px solid {_C['border']}",
        "borderRight": f"1px solid {_C['border']}",
    })

    score_card = _card([
        # Host pill at top
        html.Div([
            html.Span(sess_host, style={
                "fontSize": "0.78rem", "fontWeight": "700",
                "color": _C["blue"], "background": _C["blue_dim"],
                "borderRadius": "6px", "padding": "3px 10px",
            }),
            html.Span("Same host — different audit sessions", style={
                "fontSize": "0.72rem", "color": _C["text_dim"],
                "marginLeft": "0.6rem",
            }),
        ], style={
            "marginBottom": "1rem", "paddingBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
            "display": "flex", "alignItems": "center",
        }),
        html.Div([
            _sess_col(label_a, c_a, r_a, rk_a, "left"),
            delta_col,
            _sess_col(label_b, c_b, r_b, rk_b, "right"),
        ], style={"display": "flex", "alignItems": "flex-start"}),
    ], {"padding": "1.3rem 1.6rem"})

    # Domain comparison — reuse h2h bars with session labels
    domain_bars = _h2h_domain_bars(ss_a, ss_b, f"#{sess_a_id}", f"#{sess_b_id}")

    # Control diff — reuse h2h diff table with session labels
    diff_table = _h2h_diff_table(
        ctrls_a, ctrls_b,
        f"Session #{sess_a_id}",
        f"Session #{sess_b_id}",
    )

    return html.Div([
        _section_label("Session Score Comparison"),
        score_card,
        _section_label("Domain Comparison"),
        domain_bars,
        _section_label("Control Diff — Status Changes Between Sessions"),
        diff_table,
    ])


# ── Layout ────────────────────────────────────────────────────────────────────

layout = html.Div([
    _page_header(),
    dcc.Store(id="compare-mode", data="fleet"),
    html.Div(id="compare-mode-toggle", children=_mode_toggle("fleet")),

    # H2H host selectors — hidden unless h2h mode
    html.Div([
        html.Div([
            html.Label("Host A", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": "#2563eb", "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(id="cmp-host-a", placeholder="Choose Host A…",
                         className="dash-dropdown", style={"width": "260px"}),
        ]),
        html.Div([
            html.Label("Host B", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": "#7c3aed", "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(id="cmp-host-b", placeholder="Choose Host B…",
                         className="dash-dropdown", style={"width": "260px"}),
        ]),
    ], id="h2h-selectors", style={
        "display": "none", "gap": "1.5rem",
        "alignItems": "flex-end", "marginBottom": "1.25rem",
    }),

    # Session Diff selectors — hidden unless session mode
    html.Div([
        html.Div([
            html.Label("Host", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": _C["text_dim"], "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(id="sess-host", placeholder="Choose host…",
                         className="dash-dropdown", style={"width": "220px"}),
        ]),
        html.Div([
            html.Label("Session A (baseline)", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": "#2563eb", "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(id="sess-a", placeholder="Audit ID…",
                         className="dash-dropdown", style={"width": "200px"}),
        ]),
        html.Div([
            html.Label("Session B (comparison)", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": "#7c3aed", "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(id="sess-b", placeholder="Audit ID…",
                         className="dash-dropdown", style={"width": "200px"}),
        ]),
    ], id="session-selectors", style={
        "display": "none", "gap": "1.5rem",
        "alignItems": "flex-end", "marginBottom": "1.25rem",
        "flexWrap": "wrap",
    }),

    html.Div(id="compare-body"),
], className="page")


# ── Callbacks ─────────────────────────────────────────────────────────────────

@callback(
    Output("cmp-host-a", "options"),
    Output("cmp-host-a", "value"),
    Output("cmp-host-b", "options"),
    Output("cmp-host-b", "value"),
    Input("global-refresh", "n_intervals"),
    Input("api-base-store", "data"),
)
def load_host_options(_, base_url):
    base = get_base_url(base_url)
    try:
        names = [h["hostname"] for h in list_hosts(base).get("hosts", [])
                 if h.get("hostname")]
        opts = [{"label": n, "value": n} for n in names]
        a = names[0] if len(names) > 0 else None
        b = names[1] if len(names) > 1 else None
        return opts, a, opts, b
    except:
        return [], None, [], None


@callback(
    Output("compare-mode",        "data"),
    Output("compare-mode-toggle", "children"),
    Output("h2h-selectors",       "style"),
    Output("session-selectors",   "style"),
    Input({"type": "mode-btn", "index": dash.ALL}, "n_clicks"),
    State("compare-mode", "data"),
    prevent_initial_call=True,
)
def switch_mode(n_clicks_list, current_mode):
    from dash import ctx
    if not ctx.triggered_id:
        return current_mode, _mode_toggle(current_mode), dash.no_update, dash.no_update
    new_mode = ctx.triggered_id.get("index", current_mode)
    _flex = {"display": "flex", "gap": "1.5rem",
             "alignItems": "flex-end", "marginBottom": "1.25rem", "flexWrap": "wrap"}
    _hide = {"display": "none"}
    h2h_style     = _flex if new_mode == "h2h"      else _hide
    session_style = _flex if new_mode == "session"   else _hide
    return new_mode, _mode_toggle(new_mode), h2h_style, session_style


@callback(
    Output("sess-host", "options"),
    Output("sess-host", "value"),
    Input("global-refresh", "n_intervals"),
    Input("api-base-store", "data"),
)
def load_sess_host_options(_, base_url):
    base = get_base_url(base_url)
    try:
        names = [h["hostname"] for h in list_hosts(base).get("hosts", [])
                 if h.get("hostname")]
        opts = [{"label": n, "value": n} for n in names]
        return opts, (names[0] if names else None)
    except:
        return [], None


@callback(
    Output("sess-a", "options"),
    Output("sess-a", "value"),
    Output("sess-b", "options"),
    Output("sess-b", "value"),
    Input("sess-host", "value"),
    State("api-base-store", "data"),
)
def load_sess_audit_options(hostname, base_url):
    if not hostname:
        return [], None, [], None
    base = get_base_url(base_url)
    try:
        ids = sorted([
            int(a["audit_id"])
            for a in list_audits(base, hostname, 30).get("audits", [])
            if a.get("audit_id")
        ])
        opts = [{"label": f"Audit #{i}  ·  #{i}", "value": i} for i in ids]
        a = ids[0]  if len(ids) > 0 else None
        b = ids[-1] if len(ids) > 1 else None
        return opts, a, opts, b
    except:
        return [], None, [], None


@callback(
    Output("compare-body", "children"),
    Input("compare-mode",   "data"),
    Input("cmp-host-a",     "value"),
    Input("cmp-host-b",     "value"),
    Input("sess-host",      "value"),
    Input("sess-a",         "value"),
    Input("sess-b",         "value"),
    Input("global-refresh", "n_intervals"),
    State("api-base-store", "data"),
)
def render_compare(mode, hn_a, hn_b, sess_host, sess_a_id, sess_b_id, _, base_url):
    base  = get_base_url(base_url)
    try:
        hosts = list_hosts(base).get("hosts", [])
    except Exception as e:
        return error_banner(f"Cannot reach API: {e}")

    if mode == "fleet":
        return _build_fleet_view(base, hosts)
    elif mode == "h2h":
        return _build_h2h_view(base, hn_a, hn_b)
    else:
        return _build_session_view(base, sess_host, sess_a_id, sess_b_id)