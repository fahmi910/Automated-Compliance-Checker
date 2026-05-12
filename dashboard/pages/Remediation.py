import dash
from dash import html, dcc, callback, Input, Output, State
from helpers import (
    get_base_url, list_hosts, latest_evaluated, get_score_summary,
    normalize_controls, fmt_dt, risk_key, sev_key, RISK_MAP,
    risk_badge, status_badge, sev_badge, empty_state, error_banner,
    get_plain_reason, get_plain_recommendation,
)

dash.register_page(__name__, path="/remediation", name="Remediation Tracker")

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


# ── Summary stat card ─────────────────────────────────────────────────────────

def _stat_card(value, label, accent, sublabel=""):
    return _card([
        html.Div(style={"height": "3px", "background": accent,
                        "borderRadius": "14px 14px 0 0", "marginBottom": "1rem"}),
        html.Div([
            html.Div(str(value), style={
                "fontSize": "2rem", "fontWeight": "800", "color": accent,
                "lineHeight": "1", "fontVariantNumeric": "tabular-nums",
                "letterSpacing": "-0.02em", "marginBottom": "0.3rem",
            }),
            html.Div(label, style={
                "fontSize": "0.78rem", "fontWeight": "500",
                "color": _C["text_dim"], "textAlign": "center",
            }),
            html.Div(sublabel, style={
                "fontSize": "0.65rem", "color": _C["text_dim"],
                "marginTop": "2px", "textAlign": "center",
            }) if sublabel else None,
        ], style={"display": "flex", "flexDirection": "column",
                  "alignItems": "center", "paddingBottom": "1rem"}),
    ], {"overflow": "hidden"})


# ── Remediation item row ──────────────────────────────────────────────────────

def _item_row(rank, hostname, platform, control_id, title, domain,
              status, severity, residual_risk, recommendation, reason):
    _plain_r   = get_plain_reason(control_id, status.upper()) or reason
    _plain_rec = get_plain_recommendation(control_id, status.upper()) or recommendation
    sev_low   = severity.lower()
    rk        = sev_key(sev_low)
    accent    = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]

    # Risk bar (shows how much of 25 max this is)
    bar_pct = min((residual_risk / 25.0) * 100, 100)

    plat_colors = {
        "linux":          ("#16a34a", "#f0fdf4"),
        "windows_server": ("#2563eb", "#eff6ff"),
        "windows10":      ("#7c3aed", "#f5f3ff"),
    }
    plat_color, plat_bg = plat_colors.get(platform.lower(), (_C["text_dim"], _C["bg"]))
    plat_label = {
        "linux": "Linux", "windows_server": "Win Server", "windows10": "Win 10",
    }.get(platform.lower(), platform)

    status_cfg = {
        "FAIL":    ("#dc2626", "#fef2f2", "#fca5a5"),
        "PARTIAL": ("#ca8a04", "#fefce8", "#fde047"),
    }
    st_color, st_bg, st_border = status_cfg.get(status, ("#6b7280", "#f9fafb", "#d1d5db"))

    return html.Div([
        # Left: rank number
        html.Div(f"#{rank}", style={
            "fontSize": "1.1rem", "fontWeight": "800", "color": accent,
            "width": "36px", "flexShrink": "0", "textAlign": "center",
            "fontVariantNumeric": "tabular-nums",
        }),

        # Middle: control info
        html.Div([
            # Top row: control id + title + badges
            html.Div([
                html.Span(control_id, style={
                    "fontSize": "0.72rem", "fontWeight": "800",
                    "color": _C["blue"], "fontFamily": "monospace",
                    "marginRight": "0.5rem",
                }),
                html.Span(title, style={
                    "fontSize": "0.85rem", "fontWeight": "700",
                    "color": _C["text_bright"],
                }),
            ], style={"marginBottom": "0.3rem",
                      "display": "flex", "alignItems": "center", "flexWrap": "wrap"}),

            # Meta row: host + platform + domain + status + severity
            html.Div([
                html.Span(hostname, style={
                    "fontSize": "0.7rem", "fontWeight": "700",
                    "color": _C["blue"], "background": _C["blue_dim"],
                    "borderRadius": "4px", "padding": "1px 7px",
                }),
                html.Span(plat_label, style={
                    "fontSize": "0.68rem", "fontWeight": "600",
                    "color": plat_color, "background": plat_bg,
                    "borderRadius": "4px", "padding": "1px 7px",
                }),
                html.Span(domain, style={
                    "fontSize": "0.68rem", "color": _C["text_dim"],
                }),
                html.Span(status, style={
                    "fontSize": "0.65rem", "fontWeight": "800",
                    "color": st_color, "background": st_bg,
                    "border": f"1px solid {st_border}",
                    "borderRadius": "4px", "padding": "1px 6px",
                }),
                html.Span(severity.capitalize(), style={
                    "fontSize": "0.65rem", "fontWeight": "700",
                    "color": accent,
                }),
            ], style={"display": "flex", "alignItems": "center",
                      "gap": "0.5rem", "flexWrap": "wrap", "marginBottom": "0.4rem"}),

            html.Div(_plain_r, style={
                "fontSize": "0.75rem", "color": _C["text"],
                "lineHeight": "1.6", "marginBottom": "0.4rem",
                "whiteSpace": "normal", "wordBreak": "break-word",
            }),

            # Fix recommendation
            html.Div([
                html.Span("Fix: ", style={
                    "fontSize": "0.72rem", "fontWeight": "700",
                    "color": "#16a34a", "flexShrink": "0",
                }),
                html.Span(_plain_rec, style={
                    "fontSize": "0.72rem", "color": _C["text"],
                    "lineHeight": "1.6",
                    "whiteSpace": "normal", "wordBreak": "break-word",
                }),
            ], style={"display": "flex", "gap": "4px", "alignItems": "flex-start"}),
        ], style={"flex": "1", "minWidth": "0"}),

        # Right: residual risk score + bar
        html.Div([
            html.Div(f"{residual_risk:.1f}", style={
                "fontSize": "1.5rem", "fontWeight": "800", "color": accent,
                "fontVariantNumeric": "tabular-nums", "textAlign": "right",
                "lineHeight": "1", "marginBottom": "3px",
            }),
            html.Div("residual risk", style={
                "fontSize": "0.6rem", "color": _C["text_dim"],
                "textAlign": "right", "marginBottom": "6px",
            }),
            html.Div(
                html.Div(style={
                    "width": f"{bar_pct:.0f}%", "height": "100%",
                    "background": accent, "borderRadius": "3px",
                    "minWidth": "2px",
                }),
                style={
                    "width": "80px", "height": "6px",
                    "background": _C["bg"], "borderRadius": "3px",
                    "overflow": "hidden", "border": f"1px solid {_C['border']}",
                },
            ),
        ], style={"flexShrink": "0", "textAlign": "right"}),

    ], style={
        "display": "flex", "gap": "1rem", "alignItems": "flex-start",
        "padding": "1rem 1.2rem",
        "borderLeft": f"4px solid {accent}",
        "background": _C["card"],
        "borderRadius": "0 10px 10px 0",
        "marginBottom": "0.6rem",
        "boxShadow": _C["shadow_sm"],
        "borderTop": f"1px solid {_C['border']}",
        "borderRight": f"1px solid {_C['border']}",
        "borderBottom": f"1px solid {_C['border']}",
    })


# ── Build remediation list ────────────────────────────────────────────────────

def _build_remediation(all_items, status_f, sev_f, host_f):
    """
    all_items: list of dicts with hostname, platform, and control fields
    """
    filtered = all_items

    if status_f and status_f != "All":
        filtered = [i for i in filtered if i["status"] == status_f]

    if sev_f and sev_f != "All Severities":
        filtered = [i for i in filtered if i["severity"].lower() == sev_f.lower()]

    if host_f and host_f != "All Hosts":
        filtered = [i for i in filtered if i["hostname"] == host_f]

    if not filtered:
        return html.Div("No items match the current filters.", style={
            "textAlign": "center", "color": _C["text_dim"],
            "fontSize": "0.85rem", "padding": "3rem 0",
        })

    rows = []
    for rank, item in enumerate(filtered, 1):
        rows.append(_item_row(
            rank=rank,
            hostname=item["hostname"],
            platform=item["platform"],
            control_id=item["control_id"],
            title=item["title"],
            domain=item["domain"],
            status=item["status"],
            severity=item["severity"],
            residual_risk=item["residual_risk"],
            recommendation=item["recommendation"],
            reason=item["reason"],
        ))

    count = html.Div(
        f"Showing {len(filtered)} of {len(all_items)} items",
        style={"fontSize": "0.72rem", "color": _C["text_dim"],
               "marginBottom": "0.75rem"},
    )
    return html.Div([count, *rows])


# ── Layout ────────────────────────────────────────────────────────────────────

layout = html.Div([
    html.Div([
        html.H1("Remediation Tracker", style={
            "fontSize": "1.65rem", "fontWeight": "800", "color": _C["text_bright"],
            "letterSpacing": "-0.03em", "margin": "0 0 4px 0",
        }),
        html.Div(
            "All active FAIL and PARTIAL controls across every host — "
            "prioritised by residual risk so you know what to fix first.",
            style={"fontSize": "0.78rem", "color": _C["text_dim"]},
        ),
    ], style={"marginBottom": "1.5rem"}),

    html.Div(id="remediation-body"),
], className="page")


# ── Main callback ─────────────────────────────────────────────────────────────

@callback(
    Output("remediation-body", "children"),
    Input("global-refresh", "n_intervals"),
    Input("api-base-store", "data"),
)
def load_remediation(_, base_url):
    base = get_base_url(base_url)
    try:
        hosts = list_hosts(base).get("hosts", [])
    except Exception as e:
        return error_banner(f"Cannot reach API: {e}")

    if not hosts:
        return empty_state("No hosts registered yet.")

    all_items   = []
    total_risk  = 0.0
    host_names  = []

    for h in hosts:
        hostname = h.get("hostname")
        if not hostname:
            continue
        try:
            ev       = latest_evaluated(base, hostname)
            platform = ev.get("platform", "")
            raw_results = ev.get("results", [])
            host_names.append(hostname)

            for r in raw_results:
                status = (r.get("status") or "").upper()
                if status not in ("FAIL", "PARTIAL"):
                    continue
                res_risk = (r.get("risk") or {}).get("calculation", {}).get(
                    "residual_risk_final", 0.0)
                total_risk += res_risk

                # Get reason from evidence
                ds  = r.get("decision_source")
                pri = r.get("primary_evidence") or {}
                sec = r.get("secondary_evidence") or {}
                ev_block = pri if ds == "primary" else sec if ds == "secondary" else pri or sec
                reason = r.get("reason") or ev_block.get("raw_snippet") or "—"

                all_items.append({
                    "hostname":       hostname,
                    "platform":       platform,
                    "control_id":     r.get("control_id", ""),
                    "title":          r.get("title", ""),
                    "domain":         r.get("domain", ""),
                    "status":         status,
                    "severity":       (r.get("severity") or "low").lower(),
                    "residual_risk":  float(res_risk),
                    "recommendation": r.get("recommendation", "—"),
                    "reason":         str(reason)[:200],
                })
        except Exception:
            pass

    # Sort: severity (high first) then residual risk (highest first)
    sev_rank = {"high": 3, "medium": 2, "low": 1}
    all_items.sort(key=lambda x: (
        -sev_rank.get(x["severity"], 0),
        -x["residual_risk"],
    ))

    if not all_items:
        return empty_state("No FAIL or PARTIAL controls found across all hosts.")

    # Summary stats
    fails    = [i for i in all_items if i["status"] == "FAIL"]
    partials = [i for i in all_items if i["status"] == "PARTIAL"]
    high_sev = [i for i in all_items if i["severity"] == "high"]

    stats = html.Div([
        _stat_card(len(all_items),  "Total Items to Fix",     "#dc2626", "FAIL + PARTIAL"),
        _stat_card(len(fails),      "Active Failures",         "#dc2626", "FAIL controls"),
        _stat_card(len(partials),   "Partial Controls",        "#ca8a04", "PARTIAL controls"),
        _stat_card(len(high_sev),   "High Severity",           "#ea580c", "Immediate attention"),
        _stat_card(f"{total_risk:.1f}", "Total Residual Risk", "#7c3aed", "If all fixed → 0"),
    ], style={
        "display": "grid", "gridTemplateColumns": "repeat(5, 1fr)",
        "gap": "1rem", "marginBottom": "1.25rem",
    })

    # Filter bar
    label_style = {
        "fontSize": "0.72rem", "fontWeight": "600",
        "color": _C["text_dim"], "display": "block", "marginBottom": "0.3rem",
    }
    filters = html.Div([
        html.Div([
            html.Label("Status", style=label_style),
            dcc.RadioItems(
                id="rem-status-filter",
                options=[
                    {"label": "All",     "value": "All"},
                    {"label": "FAIL",    "value": "FAIL"},
                    {"label": "PARTIAL", "value": "PARTIAL"},
                ],
                value="All", inline=True, className="radio-group",
            ),
        ]),
        html.Div([
            html.Label("Severity", style=label_style),
            dcc.Dropdown(
                id="rem-sev-filter",
                options=[
                    {"label": "All Severities", "value": "All Severities"},
                    {"label": "High",            "value": "high"},
                    {"label": "Medium",          "value": "medium"},
                ],
                value="All Severities", clearable=False,
                className="dash-dropdown", style={"width": "180px"},
            ),
        ]),
        html.Div([
            html.Label("Host", style=label_style),
            dcc.Dropdown(
                id="rem-host-filter",
                options=[{"label": "All Hosts", "value": "All Hosts"}] +
                        [{"label": h, "value": h} for h in host_names],
                value="All Hosts", clearable=False,
                className="dash-dropdown", style={"width": "220px"},
            ),
        ]),
    ], style={
        "display": "flex", "gap": "1.5rem",
        "alignItems": "flex-end", "marginBottom": "1rem", "flexWrap": "wrap",
    })

    return html.Div([
        stats,
        _section_label("Prioritised Action List"),
        filters,
        html.Div(
            id="rem-list",
            children=_build_remediation(all_items, "All", "All Severities", "All Hosts"),
        ),
        dcc.Store(id="rem-items-store", data=all_items),
        dcc.Store(id="rem-hosts-store", data=host_names),
    ])


# ── Filter callback ───────────────────────────────────────────────────────────

@callback(
    Output("rem-list", "children"),
    Input("rem-status-filter", "value"),
    Input("rem-sev-filter",    "value"),
    Input("rem-host-filter",   "value"),
    State("rem-items-store",   "data"),
    prevent_initial_call=True,
)
def filter_remediation(status_f, sev_f, host_f, items):
    if not items:
        return empty_state("No data available.")
    return _build_remediation(
        items,
        status_f or "All",
        sev_f    or "All Severities",
        host_f   or "All Hosts",
    )