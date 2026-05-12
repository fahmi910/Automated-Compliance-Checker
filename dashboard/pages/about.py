import dash
from dash import html

dash.register_page(__name__, path="/about", name="About")

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
        "background": _C["card"],
        "border": f"1px solid {_C['border']}",
        "borderRadius": _C["radius_lg"],
        "boxShadow": _C["shadow_sm"],
        "padding": "1.4rem 1.6rem",
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


def _table(headers, rows):
    th_style = {
        "padding": "0.6rem 1rem", "fontSize": "0.65rem", "fontWeight": "700",
        "color": "#ffffff", "textTransform": "uppercase", "letterSpacing": "0.07em",
        "background": _C["blue"], "textAlign": "left", "whiteSpace": "nowrap",
    }
    td_style = {
        "padding": "0.6rem 1rem", "fontSize": "0.8rem",
        "color": _C["text"], "borderBottom": f"1px solid {_C['border']}",
    }
    header_row = html.Tr([html.Th(h, style=th_style) for h in headers])
    body_rows = []
    for i, row in enumerate(rows):
        bg = _C["bg"] if i % 2 == 0 else _C["card"]
        body_rows.append(html.Tr([
            html.Td(row[h], style={**td_style, "background": bg,
                                   "fontWeight": "600" if j == 0 else "400",
                                   "color": _C["blue"] if j == 0 else _C["text"],
                                   "fontFamily": "monospace" if j == 0 else "inherit"})
            for j, h in enumerate(headers)
        ]))
    return html.Div(
        html.Table(
            [html.Thead(header_row), html.Tbody(body_rows)],
            style={"width": "100%", "borderCollapse": "collapse"},
        ),
        style={"overflowX": "auto", "borderRadius": "8px",
               "border": f"1px solid {_C['border']}", "overflow": "hidden"},
    )


def _domain_row(name, icon, description, controls, iso):
    dom_colors = {
        "Access Control":                   "#2563eb",
        "Logging & Monitoring":             "#7c3aed",
        "Asset & Configuration Management": "#ca8a04",
        "Cryptography":                     "#16a34a",
        "Backup & Recovery":                "#ea580c",
    }
    color = dom_colors.get(name, _C["blue"])
    return html.Div([
        html.Div(style={
            "width": "4px", "background": color,
            "borderRadius": "2px", "flexShrink": "0",
        }),
        html.Div([
            html.Div([
                html.Span(icon + " ", style={"fontSize": "1rem"}),
                html.Span(name, style={
                    "fontSize": "0.9rem", "fontWeight": "700",
                    "color": _C["text_bright"],
                }),
                html.Span(f"{controls} controls", style={
                    "fontSize": "0.68rem", "fontWeight": "600",
                    "color": color,
                    "background": f"rgba({int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)},0.1)",
                    "borderRadius": "999px", "padding": "1px 8px",
                    "marginLeft": "0.5rem",
                }),
            ], style={"display": "flex", "alignItems": "center",
                      "marginBottom": "0.3rem"}),
            html.Div(description, style={
                "fontSize": "0.78rem", "color": _C["text"],
                "lineHeight": "1.5", "marginBottom": "0.3rem",
            }),
            html.Div(iso, style={
                "fontSize": "0.7rem", "color": _C["text_dim"],
                "fontStyle": "italic",
            }),
        ], style={"flex": "1"}),
    ], style={
        "display": "flex", "gap": "0.75rem",
        "padding": "0.85rem 0",
        "borderBottom": f"1px solid {_C['border']}",
    })


def _scoring_row(label, formula, description):
    return html.Div([
        html.Div(label, style={
            "fontSize": "0.78rem", "fontWeight": "700",
            "color": _C["text_bright"], "marginBottom": "4px",
        }),
        html.Code(formula, style={
            "display": "block", "fontSize": "0.75rem",
            "background": _C["bg"], "padding": "6px 10px",
            "borderRadius": "6px", "color": _C["blue"],
            "fontFamily": "monospace", "marginBottom": "4px",
            "border": f"1px solid {_C['border']}",
        }),
        html.Div(description, style={
            "fontSize": "0.72rem", "color": _C["text_dim"],
            "lineHeight": "1.5",
        }),
    ], style={
        "padding": "0.75rem 0",
        "borderBottom": f"1px solid {_C['border']}",
    })


def _stack_badge(name, role, color):
    return html.Div([
        html.Div(name, style={
            "fontSize": "0.82rem", "fontWeight": "700",
            "color": color, "marginBottom": "2px",
        }),
        html.Div(role, style={
            "fontSize": "0.7rem", "color": _C["text_dim"],
        }),
    ], style={
        "background": _C["card"],
        "border": f"1px solid {_C['border']}",
        "borderTop": f"3px solid {color}",
        "borderRadius": _C["radius_lg"],
        "padding": "0.75rem 1rem",
        "minWidth": "100px",
    })


# ── Layout ────────────────────────────────────────────────────────────────────

layout = html.Div([

    # Page header
    html.Div([
        html.H1("About", style={
            "fontSize": "1.65rem", "fontWeight": "800", "color": _C["text_bright"],
            "letterSpacing": "-0.03em", "margin": "0 0 4px 0",
        }),
        html.Div("ComplianceAI — ISO/IEC 27001 & PDPA Automated Compliance System · FYP 2025/26",
                 style={"fontSize": "0.78rem", "color": _C["text_dim"]}),
    ], style={"marginBottom": "1.5rem"}),

    # ── Hero card ─────────────────────────────────────────────────────────────
    _card([
        html.Div([
            html.Div([
                html.Div("ComplianceAI", style={
                    "fontSize": "1.5rem", "fontWeight": "800",
                    "color": _C["text_bright"], "letterSpacing": "-0.02em",
                    "marginBottom": "0.4rem",
                }),
                html.Div("Automated Security Compliance Monitoring System", style={
                    "fontSize": "0.85rem", "color": _C["blue"],
                    "fontWeight": "600", "marginBottom": "0.85rem",
                }),
                html.P(
                    "ComplianceAI deploys lightweight agents across Linux and Windows hosts to "
                    "automatically collect security evidence, evaluate compliance against "
                    "ISO/IEC 27001 Annex A and PDPA 2010 controls, calculate risk scores using "
                    "a multi-factor scoring model, and surface findings through this real-time "
                    "dashboard. The system covers 5 security domains across 3 virtual machines.",
                    style={"fontSize": "0.82rem", "color": _C["text"],
                           "lineHeight": "1.7", "maxWidth": "640px",
                           "margin": "0"},
                ),
            ], style={"flex": "1"}),
            html.Div([
                html.Div([
                    html.Div("3", style={"fontSize": "2rem", "fontWeight": "800",
                                         "color": _C["blue"], "lineHeight": "1"}),
                    html.Div("Virtual Machines", style={"fontSize": "0.68rem",
                                                         "color": _C["text_dim"]}),
                ], style={"textAlign": "center", "padding": "0 1.2rem",
                           "borderRight": f"1px solid {_C['border']}"}),
                html.Div([
                    html.Div("25", style={"fontSize": "2rem", "fontWeight": "800",
                                          "color": "#16a34a", "lineHeight": "1"}),
                    html.Div("Security Controls", style={"fontSize": "0.68rem",
                                                          "color": _C["text_dim"]}),
                ], style={"textAlign": "center", "padding": "0 1.2rem",
                           "borderRight": f"1px solid {_C['border']}"}),
                html.Div([
                    html.Div("5", style={"fontSize": "2rem", "fontWeight": "800",
                                         "color": "#7c3aed", "lineHeight": "1"}),
                    html.Div("Security Domains", style={"fontSize": "0.68rem",
                                                         "color": _C["text_dim"]}),
                ], style={"textAlign": "center", "padding": "0 1.2rem"}),
            ], style={"display": "flex", "alignItems": "center", "flexShrink": "0"}),
        ], style={"display": "flex", "justifyContent": "space-between",
                  "alignItems": "flex-start", "gap": "2rem"}),
    ]),

    # ── Security Domains ──────────────────────────────────────────────────────
    _section_label("Security Domains"),
    _card([
        _domain_row("Access Control", "🔐",
                    "Controls SSH configuration, account policies, password complexity, "
                    "lockout policies, and guest account status across Linux and Windows hosts.",
                    8, "ISO A.5.15 · A.8.2 · A.8.5 · A.5.16 · A.5.17"),
        _domain_row("Logging & Monitoring", "📋",
                    "Ensures system logging services are active, authentication logs exist, "
                    "Windows Event Log is running, and log rotation is configured.",
                    5, "ISO A.8.15 · A.8.16"),
        _domain_row("Asset & Configuration Management", "⚙️",
                    "Checks firewall status across Linux (UFW) and Windows (all profiles), "
                    "Windows Update service status, and patch recency.",
                    6, "ISO A.8.8 · A.8.9 · A.8.20 · A.8.21 · A.8.22"),
        _domain_row("Cryptography", "🔒",
                    "Verifies absence of weak SSH algorithms on Linux, TLS 1.0/1.1 disabled "
                    "on Windows Server, and BitLocker encryption on Windows 10.",
                    3, "ISO A.8.24 · A.8.5 · A.8.20 · A.7.10"),
        _domain_row("Backup & Recovery", "💾",
                    "Confirms backup tools are installed and scheduled on Linux, "
                    "and Volume Shadow Copy Service (VSS) is running on Windows.",
                    3, "ISO A.8.13 · A.5.29"),
    ], {"padding": "0 1.4rem"}),

    # ── Scoring Model ─────────────────────────────────────────────────────────
    _section_label("Scoring Model v2"),
    html.Div([
        _card([
            html.Div("Compliance Score", style={
                "fontSize": "0.9rem", "fontWeight": "700", "color": _C["text_bright"],
                "marginBottom": "0.85rem", "paddingBottom": "0.75rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            _scoring_row(
                "Earned Points per Control",
                "Earned = Severity Weight × Points Multiplier",
                "PASS=1.0, PARTIAL=0.5, FAIL=0.0, UNKNOWN=0.0 | Weight: High=3, Medium=2, Low=1",
            ),
            _scoring_row(
                "Domain Compliance Score",
                "Domain % = (Sum Earned / Sum Max) × 100",
                "Calculated independently per domain using only applicable controls.",
            ),
            _scoring_row(
                "Overall Compliance Score",
                "Overall % = (Total Earned / Total Max) × 100",
                "Aggregated across all controls applicable to the host platform.",
            ),
        ], {"flex": "1"}),
        _card([
            html.Div("Risk Score", style={
                "fontSize": "0.9rem", "fontWeight": "700", "color": _C["text_bright"],
                "marginBottom": "0.85rem", "paddingBottom": "0.75rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            _scoring_row(
                "Impact Score (IS)",
                "IS = (0.35×SI) + (0.20×BC) + (0.20×ACov) + (0.25×CI)",
                "SI=Security Impact, BC=Business Criticality, ACov=Asset Coverage, CI=Compliance Importance. Scale 1–5.",
            ),
            _scoring_row(
                "Inherent Risk Weight (IRW)",
                "IRW = IS × Exposure Likelihood",
                "Exposure Likelihood is evidence-driven: base value adjusted by firewall status, open ports, failed logins.",
            ),
            _scoring_row(
                "Residual Risk (Final)",
                "Residual = (IRW × Status Factor) × (1 − Mitigation%)",
                "PASS=0.0, PARTIAL=0.5, FAIL=1.0, UNKNOWN=0.7 | Mitigation capped at 30%.",
            ),
            _scoring_row(
                "Overall Risk Score (0–100)",
                "Risk Score = (Sum Residual / Sum IRW) × 100",
                "0 = no remaining risk (all PASS). 100 = maximum risk (all FAIL, no mitigation).",
            ),
        ], {"flex": "1"}),
    ], style={"display": "grid", "gridTemplateColumns": "1fr 1fr", "gap": "1rem"}),

    # Risk level table
    html.Div(style={"marginTop": "1rem"}),
    _card([
        html.Div("Risk Level Thresholds", style={
            "fontSize": "0.9rem", "fontWeight": "700", "color": _C["text_bright"],
            "marginBottom": "0.85rem", "paddingBottom": "0.75rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div([
            html.Div([
                html.Div(level, style={
                    "fontSize": "0.78rem", "fontWeight": "700",
                    "color": color, "marginBottom": "2px",
                }),
                html.Div(rng, style={"fontSize": "0.7rem", "color": _C["text_dim"]}),
            ], style={
                "flex": "1", "textAlign": "center",
                "borderLeft": f"3px solid {color}",
                "paddingLeft": "0.75rem",
            })
            for level, rng, color in [
                ("Low",      "0 – 19",  "#16a34a"),
                ("Moderate", "20 – 39", "#7c3aed"),
                ("High",     "40 – 59", "#ca8a04"),
                ("Critical", "60 – 79", "#ea580c"),
                ("Severe",   "80 – 100","#dc2626"),
            ]
        ], style={"display": "flex", "gap": "1rem"}),
    ]),

    # ── Framework mappings ────────────────────────────────────────────────────
    _section_label("Compliance Frameworks"),
    html.Div([
        _card([
            html.Div("ISO/IEC 27001:2022 Annex A", style={
                "fontSize": "0.9rem", "fontWeight": "700", "color": _C["text_bright"],
                "marginBottom": "0.85rem", "paddingBottom": "0.75rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            html.P(
                "ISO/IEC 27001 is the international standard for information security management. "
                "This system maps controls to Annex A clauses covering access control (A.5.15–A.5.17, A.8.2, A.8.5), "
                "logging (A.8.15–A.8.16), network security (A.8.20–A.8.22), cryptography (A.8.24), "
                "vulnerability management (A.8.8–A.8.9), and backup (A.8.13, A.5.29).",
                style={"fontSize": "0.78rem", "color": _C["text"], "lineHeight": "1.7", "margin": "0"},
            ),
        ], {"flex": "1"}),
        _card([
            html.Div("PDPA 2010 (Malaysia)", style={
                "fontSize": "0.9rem", "fontWeight": "700", "color": _C["text_bright"],
                "marginBottom": "0.85rem", "paddingBottom": "0.75rem",
                "borderBottom": f"1px solid {_C['border']}",
            }),
            html.P(
                "The Personal Data Protection Act 2010 requires organisations handling personal data "
                "to implement adequate security measures. This system maps each control to PDPA's "
                "security principle — ensuring personal data is protected from unauthorised access, "
                "disclosure, loss, and destruction through technical controls on endpoints.",
                style={"fontSize": "0.78rem", "color": _C["text"], "lineHeight": "1.7", "margin": "0"},
            ),
        ], {"flex": "1"}),
    ], style={"display": "grid", "gridTemplateColumns": "1fr 1fr", "gap": "1rem"}),

    # ── API Endpoints ─────────────────────────────────────────────────────────
    _section_label("API Endpoints"),
    _card([
        _table(
            ["Method", "Endpoint", "Description"],
            [
                {"Method": "GET",  "Endpoint": "/health",                  "Description": "Server health check"},
                {"Method": "POST", "Endpoint": "/submit",                  "Description": "Agent submits audit payload"},
                {"Method": "GET",  "Endpoint": "/hosts",                   "Description": "List all registered hosts"},
                {"Method": "GET",  "Endpoint": "/audits/latest/evaluated", "Description": "Latest evaluated audit for a host"},
                {"Method": "GET",  "Endpoint": "/audits",                  "Description": "Audit history with limit parameter"},
                {"Method": "GET",  "Endpoint": "/audits/<id>/evaluated",   "Description": "Full evaluated audit by ID"},
            ],
        ),
    ], {"padding": "1.2rem 1.4rem"}),

    # ── Dashboard Pages ───────────────────────────────────────────────────────
    _section_label("Dashboard Pages"),
    _card([
        _table(
            ["Page", "Path", "Description"],
            [
                {"Page": "Overview",             "Path": "/",            "Description": "Fleet KPIs, host compliance bars, top risks, domain health"},
                {"Page": "Host Detail",          "Path": "/host",        "Description": "Per-host scores, domain breakdown, control evidence drawer"},
                {"Page": "History",              "Path": "/history",     "Description": "Compliance trend, audit timeline, session delta"},
                {"Page": "Compare",              "Path": "/compare",     "Description": "Fleet heatmap, head-to-head diff, session comparison"},
                {"Page": "Report Export",        "Path": "/report",      "Description": "Generate and download PDF compliance report"},
                {"Page": "Control Catalogue",    "Path": "/catalogue",   "Description": "All 25 controls with ISO/PDPA mappings and risk factors"},
                {"Page": "Remediation Tracker",  "Path": "/remediation", "Description": "Prioritised to-do list of all active FAIL and PARTIAL controls"},
                {"Page": "About",                "Path": "/about",       "Description": "System overview, scoring model, API reference"},
            ],
        ),
    ], {"padding": "1.2rem 1.4rem"}),

    # ── Tech Stack ────────────────────────────────────────────────────────────
    _section_label("Tech Stack"),
    html.Div([
        _stack_badge("Python 3",   "Core language",         "#3b82f6"),
        _stack_badge("Dash",       "Dashboard framework",   "#7c3aed"),
        _stack_badge("Plotly",     "Interactive charts",    "#ea580c"),
        _stack_badge("Flask",      "Audit API backend",     "#16a34a"),
        _stack_badge("SQLite",     "Audit data store",      "#ca8a04"),
        _stack_badge("ReportLab",  "PDF report engine",     "#dc2626"),
        _stack_badge("Agents",     "Host audit collectors", "#2563eb"),
    ], style={
        "display": "flex", "gap": "0.75rem",
        "flexWrap": "wrap", "marginBottom": "2rem",
    }),

    # Footer
    html.Div(
        "FYP 2025/26  ·  ISO/IEC 27001 & PDPA Automated Compliance System  ·  Built with Dash + Flask + ReportLab",
        style={
            "textAlign": "center", "fontSize": "0.75rem",
            "color": _C["text_dim"], "padding": "1.5rem 0",
            "borderTop": f"1px solid {_C['border']}",
        },
    ),

], className="page")