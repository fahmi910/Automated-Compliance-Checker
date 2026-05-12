import base64
import dash
from dash import html, dcc, callback, Input, Output, State
from helpers import (
    get_base_url, list_hosts, latest_evaluated, list_audits,
    evaluated_audit, get_score_summary, fmt_dt, risk_key, RISK_MAP,
    risk_badge, empty_state, error_banner,
)

dash.register_page(__name__, path="/report", name="Report Export")

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

layout = html.Div([
    # Page header
    html.Div([
        html.H1("Report Export", style={
            "fontSize": "1.65rem", "fontWeight": "800", "color": _C["text_bright"],
            "letterSpacing": "-0.03em", "margin": "0 0 4px 0",
        }),
        html.Div(
            "Generate a downloadable PDF compliance report for any host and audit session.",
            style={"fontSize": "0.78rem", "color": _C["text_dim"]},
        ),
    ], style={"marginBottom": "1.5rem"}),

    # Selectors row
    html.Div([
        html.Div([
            html.Label("Host", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": _C["text_dim"], "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(
                id="rpt-host", placeholder="Choose a host…",
                className="dash-dropdown", style={"width": "260px"},
            ),
        ]),
        html.Div([
            html.Label("Audit Session", style={
                "fontSize": "0.75rem", "fontWeight": "600",
                "color": _C["text_dim"], "display": "block", "marginBottom": "0.3rem",
            }),
            dcc.Dropdown(
                id="rpt-audit", placeholder="Latest audit",
                className="dash-dropdown", style={"width": "240px"},
                value="latest",
            ),
        ]),
        html.Div([
            html.Label(" ", style={"display": "block", "marginBottom": "0.3rem",
                                    "fontSize": "0.75rem"}),
            html.Button(
                "Generate Report",
                id="rpt-generate-btn",
                n_clicks=0,
                style={
                    "padding":       "8px 22px",
                    "fontSize":      "0.85rem",
                    "fontWeight":    "700",
                    "background":    _C["blue"],
                    "color":         "#ffffff",
                    "border":        "none",
                    "borderRadius":  "8px",
                    "cursor":        "pointer",
                    "height":        "38px",
                    "boxShadow":     "0 2px 6px rgba(37,99,235,0.25)",
                },
            ),
        ]),
    ], style={
        "display": "flex", "gap": "1.5rem",
        "alignItems": "flex-end", "marginBottom": "1.5rem", "flexWrap": "wrap",
    }),

    # Status / download area
    html.Div(id="rpt-status"),

    # Hidden download component
    dcc.Download(id="rpt-download"),

], className="page")


# ── Load host list ────────────────────────────────────────────────────────────

@callback(
    Output("rpt-host", "options"),
    Output("rpt-host", "value"),
    Input("global-refresh", "n_intervals"),
    Input("api-base-store", "data"),
)
def load_hosts(_, base_url):
    base = get_base_url(base_url)
    try:
        names = [h["hostname"] for h in list_hosts(base).get("hosts", [])
                 if h.get("hostname")]
        opts = [{"label": n, "value": n} for n in names]
        return opts, (names[0] if names else None)
    except:
        return [], None


# ── Load audit list for selected host ────────────────────────────────────────

@callback(
    Output("rpt-audit", "options"),
    Output("rpt-audit", "value"),
    Input("rpt-host", "value"),
    State("api-base-store", "data"),
)
def load_audits(hostname, base_url):
    if not hostname:
        return [{"label": "Latest audit", "value": "latest"}], "latest"
    base = get_base_url(base_url)
    try:
        audits = list_audits(base, hostname, 20).get("audits", [])
        opts = [{"label": "Latest audit", "value": "latest"}] + [
            {"label": f"Audit #{a['audit_id']}  ·  {fmt_dt(a.get('received_at'))}",
             "value": str(a["audit_id"])}
            for a in audits if a.get("audit_id")
        ]
        return opts, "latest"
    except:
        return [{"label": "Latest audit", "value": "latest"}], "latest"


# ── Show preview card when host is selected ───────────────────────────────────

@callback(
    Output("rpt-status", "children"),
    Input("rpt-host", "value"),
    Input("rpt-audit", "value"),
    State("api-base-store", "data"),
    prevent_initial_call=False,
)
def show_preview(hostname, audit_val, base_url):
    if not hostname:
        return empty_state("Select a host above to preview the report.")

    base = get_base_url(base_url)
    try:
        if audit_val and audit_val != "latest":
            ev = evaluated_audit(base, int(audit_val))
        else:
            ev = latest_evaluated(base, hostname)
    except Exception as e:
        return error_banner(f"Failed to load audit: {e}")

    ss     = get_score_summary(ev)
    comp   = ss.get("compliance_score")
    rscore = ss.get("risk_score")
    rk     = risk_key(rscore)
    rinfo  = RISK_MAP.get(rk, RISK_MAP["unknown"])
    accent = rinfo["color"]

    audit_id    = ev.get("audit_id", "—")
    received    = fmt_dt(ev.get("received_at"))
    n_controls  = ev.get("evaluated_controls", len(ev.get("results", [])))
    platform    = ev.get("platform", "—")
    ip          = ev.get("ip_address", "—")

    results  = ev.get("results", [])
    fails    = sum(1 for r in results if r.get("status") == "FAIL")
    partials = sum(1 for r in results if r.get("status") == "PARTIAL")
    passes   = sum(1 for r in results if r.get("status") == "PASS")

    # Report preview card
    preview = _card([
        # Top accent bar
        html.Div(style={
            "height": "4px", "background": accent,
            "borderRadius": "14px 14px 0 0", "marginBottom": "1.3rem",
        }),
        html.Div([
            # Left: report info
            html.Div([
                html.Div("Report Preview", style={
                    "fontSize": "0.62rem", "fontWeight": "700", "color": _C["text_dim"],
                    "textTransform": "uppercase", "letterSpacing": "0.1em",
                    "marginBottom": "0.5rem",
                }),
                html.Div(hostname, style={
                    "fontSize": "1.3rem", "fontWeight": "800",
                    "color": _C["text_bright"], "letterSpacing": "-0.02em",
                    "marginBottom": "0.3rem",
                }),
                html.Div([
                    html.Span(platform, style={
                        "fontSize": "0.72rem", "fontWeight": "700",
                        "color": _C["blue"], "background": _C["blue_dim"],
                        "borderRadius": "4px", "padding": "2px 8px",
                    }),
                    html.Span(ip, style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                        "fontFamily": "monospace",
                    }),
                    html.Span(f"Audit #{audit_id}", style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                    }),
                    html.Span(received, style={
                        "fontSize": "0.72rem", "color": _C["text_dim"],
                    }),
                ], style={"display": "flex", "gap": "0.75rem",
                          "alignItems": "center", "flexWrap": "wrap",
                          "marginBottom": "1rem"}),

                # Control status summary
                html.Div([
                    html.Div([
                        html.Span(str(passes), style={
                            "fontSize": "1.4rem", "fontWeight": "800",
                            "color": "#16a34a",
                        }),
                        html.Div("PASS", style={
                            "fontSize": "0.62rem", "color": _C["text_dim"],
                        }),
                    ], style={"textAlign": "center"}),
                    html.Div(style={"width": "1px", "background": _C["border"]}),
                    html.Div([
                        html.Span(str(fails), style={
                            "fontSize": "1.4rem", "fontWeight": "800",
                            "color": "#dc2626",
                        }),
                        html.Div("FAIL", style={
                            "fontSize": "0.62rem", "color": _C["text_dim"],
                        }),
                    ], style={"textAlign": "center"}),
                    html.Div(style={"width": "1px", "background": _C["border"]}),
                    html.Div([
                        html.Span(str(partials), style={
                            "fontSize": "1.4rem", "fontWeight": "800",
                            "color": "#ca8a04",
                        }),
                        html.Div("PARTIAL", style={
                            "fontSize": "0.62rem", "color": _C["text_dim"],
                        }),
                    ], style={"textAlign": "center"}),
                    html.Div(style={"width": "1px", "background": _C["border"]}),
                    html.Div([
                        html.Span(str(n_controls), style={
                            "fontSize": "1.4rem", "fontWeight": "800",
                            "color": _C["blue"],
                        }),
                        html.Div("TOTAL", style={
                            "fontSize": "0.62rem", "color": _C["text_dim"],
                        }),
                    ], style={"textAlign": "center"}),
                ], style={
                    "display": "flex", "gap": "1.5rem", "alignItems": "center",
                }),
            ], style={"flex": "1"}),

            # Right: score display
            html.Div([
                html.Div(
                    f"{comp:.0f}%" if comp is not None else "—",
                    style={
                        "fontSize": "3rem", "fontWeight": "800",
                        "color": accent, "lineHeight": "1",
                        "fontVariantNumeric": "tabular-nums",
                        "letterSpacing": "-0.03em",
                        "textAlign": "right", "marginBottom": "4px",
                    },
                ),
                html.Div("compliance", style={
                    "fontSize": "0.68rem", "color": _C["text_dim"],
                    "textAlign": "right", "marginBottom": "0.5rem",
                }),
                html.Div(risk_badge(rk), style={"textAlign": "right"}),
            ], style={"flexShrink": "0"}),
        ], style={
            "display": "flex", "justifyContent": "space-between",
            "alignItems": "flex-start", "padding": "0 1.4rem",
        }),

        # What's included section
        html.Div([
            html.Div(style={"height": "1px", "background": _C["border"], "margin": "1rem 0"}),
            html.Div("Report will include:", style={
                "fontSize": "0.72rem", "fontWeight": "700", "color": _C["text_dim"],
                "textTransform": "uppercase", "letterSpacing": "0.08em",
                "marginBottom": "0.6rem",
            }),
            html.Div([
                _include_item("Host identity & audit metadata"),
                _include_item("Compliance score & risk level"),
                _include_item("Domain breakdown table"),
                _include_item("Top 5 priority risks with recommendations"),
                _include_item("Full control results table"),
            ], style={
                "display": "grid", "gridTemplateColumns": "1fr 1fr",
                "gap": "0.3rem",
            }),
        ], style={"padding": "0 1.4rem 1.3rem"}),
    ], {"overflow": "hidden"})

    return html.Div([
        _section_label("Report Preview"),
        preview,
        html.Div(
            "Click Generate Report above to download the PDF.",
            style={
                "fontSize": "0.75rem", "color": _C["text_dim"],
                "textAlign": "center", "marginTop": "0.75rem",
            },
        ),
    ])


def _include_item(text):
    return html.Div([
        html.Span("✓ ", style={"color": "#16a34a", "fontWeight": "700"}),
        html.Span(text, style={"fontSize": "0.75rem", "color": _C["text"]}),
    ])


# ── Generate and download PDF ─────────────────────────────────────────────────

@callback(
    Output("rpt-download", "data"),
    Input("rpt-generate-btn", "n_clicks"),
    State("rpt-host",  "value"),
    State("rpt-audit", "value"),
    State("api-base-store", "data"),
    prevent_initial_call=True,
)
def generate_and_download(n_clicks, hostname, audit_val, base_url):
    if not hostname:
        return dash.no_update

    base = get_base_url(base_url)
    try:
        if audit_val and audit_val != "latest":
            ev = evaluated_audit(base, int(audit_val))
        else:
            ev = latest_evaluated(base, hostname)
    except Exception:
        return dash.no_update

    # Import generator from server/services/report_generator.py
    import sys, os
    _here = os.path.dirname(os.path.abspath(__file__))
    _srv  = os.path.normpath(os.path.join(_here, "..", "..", "server", "services"))
    if _srv not in sys.path:
        sys.path.insert(0, _srv)
    try:
        from report_generator import generate_report
    except ImportError as _ie:
        raise ImportError(
            f"Could not import report_generator. "
            f"Make sure reportlab is installed (pip install reportlab) "
            f"and report_generator.py is in server/services/. "
            f"Looked in: {_srv}. Original error: {_ie}"
        ) from _ie

    pdf_bytes = generate_report(ev)
    audit_id  = ev.get("audit_id", "latest")
    filename  = f"compliance_report_{hostname}_audit{audit_id}.pdf"

    return dcc.send_bytes(pdf_bytes, filename)