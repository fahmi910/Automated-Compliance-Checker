import json
import os
import dash
from dash import html, dcc, callback, Input, Output, State

dash.register_page(__name__, path="/catalogue", name="Control Catalogue")

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

PLATFORM_LABELS = {
    "linux":          "Linux",
    "windows_server": "Windows Server",
    "windows10":      "Windows 10",
}

PLATFORM_COLORS = {
    "linux":          ("#16a34a", "#f0fdf4", "#86efac"),
    "windows_server": ("#2563eb", "#eff6ff", "#bfdbfe"),
    "windows10":      ("#7c3aed", "#f5f3ff", "#c4b5fd"),
}

SEV_COLORS = {
    "high":   ("#dc2626", "#fef2f2", "#fca5a5"),
    "medium": ("#ca8a04", "#fefce8", "#fde047"),
    "low":    ("#16a34a", "#f0fdf4", "#86efac"),
}

DOMAIN_COLORS = {
    "Access Control":                   ("#2563eb", "#eff6ff"),
    "Logging & Monitoring":             ("#7c3aed", "#f5f3ff"),
    "Asset & Configuration Management": ("#ca8a04", "#fefce8"),
    "Cryptography":                     ("#16a34a", "#f0fdf4"),
    "Backup & Recovery":                ("#ea580c", "#fff7ed"),
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


def _badge(text, color, bg, border):
    return html.Span(text, style={
        "fontSize": "0.68rem", "fontWeight": "700", "color": color,
        "background": bg, "border": f"1px solid {border}",
        "borderRadius": "999px", "padding": "2px 9px",
        "whiteSpace": "nowrap",
    })


def _factor_dot(value: int):
    """1–5 dot indicator for risk factors."""
    dots = []
    for i in range(1, 6):
        filled = i <= value
        dots.append(html.Span(style={
            "display":       "inline-block",
            "width":         "7px",
            "height":        "7px",
            "borderRadius":  "50%",
            "background":    _C["blue"] if filled else _C["border"],
            "marginRight":   "2px",
        }))
    return html.Div(dots, style={"display": "flex", "alignItems": "center"})


# ── Load controls ─────────────────────────────────────────────────────────────

def _load_controls():
    """Load controls.json from server/rules/controls.json relative to this file."""
    here    = os.path.dirname(os.path.abspath(__file__))
    path    = os.path.normpath(os.path.join(here, "..", "..", "server", "rules", "controls.json"))
    # Fallback: try rules/controls.json (from project root)
    if not os.path.exists(path):
        path = os.path.normpath(os.path.join(here, "..", "rules", "controls.json"))
    if not os.path.exists(path):
        path = os.path.normpath(os.path.join(here, "..", "..", "rules", "controls.json"))
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("controls", [])


# ── Summary stats strip ───────────────────────────────────────────────────────

def _summary_strip(controls):
    from collections import Counter
    total    = len(controls)
    by_dom   = Counter(c["domain"] for c in controls)
    by_plat  = Counter(c["platform"] for c in controls)
    by_sev   = Counter(c["severity"] for c in controls)

    def _stat(value, label, accent):
        return html.Div([
            html.Div(style={"height": "3px", "background": accent,
                            "borderRadius": "14px 14px 0 0", "marginBottom": "0.9rem"}),
            html.Div([
                html.Div(str(value), style={
                    "fontSize": "1.9rem", "fontWeight": "800", "color": accent,
                    "lineHeight": "1", "fontVariantNumeric": "tabular-nums",
                    "letterSpacing": "-0.02em", "marginBottom": "0.3rem",
                }),
                html.Div(label, style={
                    "fontSize": "0.75rem", "color": _C["text_dim"],
                    "fontWeight": "500", "textAlign": "center",
                }),
            ], style={"display": "flex", "flexDirection": "column",
                      "alignItems": "center", "paddingBottom": "0.9rem"}),
        ], style={
            "background": _C["card"], "border": f"1px solid {_C['border']}",
            "borderRadius": _C["radius_lg"], "boxShadow": _C["shadow_sm"],
            "overflow": "hidden", "flex": "1",
        })

    return html.Div([
        _stat(total,                     "Total Controls",   _C["blue"]),
        _stat(by_sev.get("high", 0),     "High Severity",    "#dc2626"),
        _stat(by_sev.get("medium", 0),   "Medium Severity",  "#ca8a04"),
        _stat(by_plat.get("linux", 0),   "Linux Controls",   "#16a34a"),
        _stat(by_plat.get("windows_server", 0), "Windows Server", "#2563eb"),
        _stat(by_plat.get("windows10", 0), "Windows 10",     "#7c3aed"),
    ], style={"display": "flex", "gap": "0.85rem"})


# ── Filter bar ────────────────────────────────────────────────────────────────

def _filter_bar(controls):
    domains   = ["All Domains"]   + DOMAIN_ORDER
    platforms = ["All Platforms"] + list(PLATFORM_LABELS.values())
    severities= ["All Severities","High","Medium","Low"]

    label_style = {
        "fontSize": "0.72rem", "fontWeight": "600",
        "color": _C["text_dim"], "display": "block", "marginBottom": "0.3rem",
    }
    return html.Div([
        html.Div([
            html.Label("Domain", style=label_style),
            dcc.Dropdown(
                id="cat-domain-filter",
                options=[{"label": d, "value": d} for d in domains],
                value="All Domains", clearable=False,
                className="dash-dropdown", style={"width": "240px"},
            ),
        ]),
        html.Div([
            html.Label("Platform", style=label_style),
            dcc.Dropdown(
                id="cat-platform-filter",
                options=[{"label": p, "value": p} for p in platforms],
                value="All Platforms", clearable=False,
                className="dash-dropdown", style={"width": "200px"},
            ),
        ]),
        html.Div([
            html.Label("Severity", style=label_style),
            dcc.Dropdown(
                id="cat-sev-filter",
                options=[{"label": s, "value": s} for s in severities],
                value="All Severities", clearable=False,
                className="dash-dropdown", style={"width": "180px"},
            ),
        ]),
        html.Div([
            html.Label("Search", style=label_style),
            dcc.Input(
                id="cat-search",
                type="text",
                placeholder="Search ID or title…",
                debounce=True,
                style={
                    "width": "200px", "height": "36px",
                    "padding": "0 10px", "fontSize": "0.82rem",
                    "border": f"1px solid {_C['border']}",
                    "borderRadius": "8px", "outline": "none",
                    "color": _C["text_bright"],
                },
            ),
        ]),
    ], style={
        "display": "flex", "gap": "1.25rem",
        "alignItems": "flex-end", "flexWrap": "wrap",
        "marginBottom": "1rem",
    })


# ── Control card ──────────────────────────────────────────────────────────────

def _control_card(c):
    sev       = c.get("severity", "low").lower()
    platform  = c.get("platform", "")
    domain    = c.get("domain", "")

    sev_c, sev_bg, sev_br     = SEV_COLORS.get(sev, SEV_COLORS["low"])
    plat_c, plat_bg, plat_br  = PLATFORM_COLORS.get(platform, ("#6b7280", "#f9fafb", "#d1d5db"))
    dom_c, dom_bg              = DOMAIN_COLORS.get(domain, (_C["blue"], _C["blue_dim"]))
    plat_label                 = PLATFORM_LABELS.get(platform, platform)

    iso   = c.get("iso_mapping", [])
    pdpa  = c.get("pdpa_mapping", [])
    recs  = c.get("recommendations", {})

    factors = [
        ("Business Criticality",   c.get("business_criticality",   0)),
        ("Security Impact",        c.get("security_impact",        0)),
        ("Asset Coverage",         c.get("asset_coverage",         0)),
        ("Compliance Importance",  c.get("compliance_importance",  0)),
    ]

    return _card([
        # Top accent bar
        html.Div(style={
            "height": "3px", "background": dom_c,
            "borderRadius": "14px 14px 0 0",
        }),
        html.Div([
            # ── Header row ────────────────────────────────────────────────────
            html.Div([
                html.Div([
                    html.Span(c.get("control_id", ""), style={
                        "fontSize": "0.78rem", "fontWeight": "800",
                        "color": _C["blue"], "fontFamily": "monospace",
                        "marginRight": "0.6rem",
                    }),
                    html.Span(c.get("title", ""), style={
                        "fontSize": "0.9rem", "fontWeight": "700",
                        "color": _C["text_bright"],
                    }),
                ], style={"display": "flex", "alignItems": "center",
                          "flexWrap": "wrap", "marginBottom": "0.5rem"}),
                html.Div([
                    _badge(sev.capitalize(),  sev_c,  sev_bg,  sev_br),
                    _badge(plat_label,        plat_c, plat_bg, plat_br),
                    _badge(domain,            dom_c,  dom_bg,  dom_c + "55"),
                ], style={"display": "flex", "gap": "0.4rem", "flexWrap": "wrap"}),
            ], style={
                "paddingBottom": "0.85rem",
                "borderBottom": f"1px solid {_C['border']}",
                "marginBottom": "0.85rem",
            }),

            # ── Two-column body ───────────────────────────────────────────────
            html.Div([

                # Left column: risk factors + exposure
                html.Div([
                    html.Div("Risk Factors", style={
                        "fontSize": "0.62rem", "fontWeight": "700",
                        "color": _C["text_dim"], "textTransform": "uppercase",
                        "letterSpacing": "0.08em", "marginBottom": "0.6rem",
                    }),
                    html.Div([
                        html.Div([
                            html.Div(label, style={
                                "fontSize": "0.72rem", "color": _C["text"],
                                "width": "160px", "flexShrink": "0",
                            }),
                            _factor_dot(val),
                            html.Span(f"{val}/5", style={
                                "fontSize": "0.65rem", "color": _C["text_dim"],
                                "marginLeft": "6px",
                            }),
                        ], style={"display": "flex", "alignItems": "center",
                                  "marginBottom": "5px"})
                        for label, val in factors
                    ]),
                    html.Div(style={"height": "0.75rem"}),
                    html.Div([
                        html.Span("Exposure Profile: ", style={
                            "fontSize": "0.72rem", "fontWeight": "600",
                            "color": _C["text_dim"],
                        }),
                        html.Span(c.get("exposure_profile", "—"), style={
                            "fontSize": "0.72rem", "color": _C["text_bright"],
                            "fontFamily": "monospace",
                        }),
                    ]),
                    html.Div([
                        html.Span("Base Exposure Likelihood: ", style={
                            "fontSize": "0.72rem", "fontWeight": "600",
                            "color": _C["text_dim"],
                        }),
                        html.Span(f"{c.get('exposure_likelihood_base', '—')} / 5", style={
                            "fontSize": "0.72rem", "color": _C["text_bright"],
                        }),
                    ], style={"marginTop": "3px"}),
                ], style={"flex": "1"}),

                # Middle column: ISO + PDPA mappings
                html.Div([
                    html.Div("ISO 27001 Mapping", style={
                        "fontSize": "0.62rem", "fontWeight": "700",
                        "color": _C["text_dim"], "textTransform": "uppercase",
                        "letterSpacing": "0.08em", "marginBottom": "0.5rem",
                    }),
                    html.Div([
                        html.Div(item, style={
                            "fontSize": "0.72rem", "color": _C["text"],
                            "background": _C["blue_dim"],
                            "borderRadius": "4px", "padding": "3px 8px",
                            "marginBottom": "3px",
                        }) for item in iso
                    ] if iso else html.Span("—", style={"fontSize": "0.72rem",
                                                        "color": _C["text_dim"]})),
                    html.Div(style={"height": "0.6rem"}),
                    html.Div("PDPA Mapping", style={
                        "fontSize": "0.62rem", "fontWeight": "700",
                        "color": _C["text_dim"], "textTransform": "uppercase",
                        "letterSpacing": "0.08em", "marginBottom": "0.5rem",
                    }),
                    html.Div([
                        html.Div(item, style={
                            "fontSize": "0.72rem", "color": _C["text"],
                            "background": "#f0fdf4",
                            "borderRadius": "4px", "padding": "3px 8px",
                            "marginBottom": "3px",
                        }) for item in pdpa
                    ] if pdpa else html.Span("—", style={"fontSize": "0.72rem",
                                                         "color": _C["text_dim"]})),
                ], style={"flex": "1.2", "borderLeft": f"1px solid {_C['border']}",
                          "paddingLeft": "1.2rem"}),

                # Right column: status recommendations
                html.Div([
                    html.Div("Recommendations by Status", style={
                        "fontSize": "0.62rem", "fontWeight": "700",
                        "color": _C["text_dim"], "textTransform": "uppercase",
                        "letterSpacing": "0.08em", "marginBottom": "0.5rem",
                    }),
                    html.Div([
                        _rec_row(status, recs.get(status, "—"))
                        for status in ["PASS", "PARTIAL", "FAIL", "UNKNOWN"]
                        if status in recs
                    ]),
                ], style={"flex": "1.2", "borderLeft": f"1px solid {_C['border']}",
                          "paddingLeft": "1.2rem"}),

            ], style={"display": "flex", "gap": "1.2rem", "alignItems": "flex-start"}),
        ], style={"padding": "1rem 1.3rem 1.2rem"}),
    ], {"overflow": "hidden", "marginBottom": "0.85rem"})


def _rec_row(status, text):
    STATUS_CFG = {
        "PASS":    ("#16a34a", "#f0fdf4"),
        "PARTIAL": ("#ca8a04", "#fefce8"),
        "FAIL":    ("#dc2626", "#fef2f2"),
        "UNKNOWN": ("#6b7280", "#f9fafb"),
    }
    color, bg = STATUS_CFG.get(status, ("#6b7280", "#f9fafb"))
    return html.Div([
        html.Span(status, style={
            "fontSize": "0.62rem", "fontWeight": "800", "color": color,
            "background": bg, "borderRadius": "3px",
            "padding": "1px 5px", "marginRight": "6px",
            "flexShrink": "0",
        }),
        html.Span(text, style={
            "fontSize": "0.72rem", "color": _C["text"], "lineHeight": "1.4",
        }),
    ], style={"display": "flex", "alignItems": "flex-start",
              "marginBottom": "6px"})


# ── Domain group header ───────────────────────────────────────────────────────

def _domain_header(domain, count):
    color, bg = DOMAIN_COLORS.get(domain, (_C["blue"], _C["blue_dim"]))
    return html.Div([
        html.Div(style={
            "width": "4px", "background": color,
            "borderRadius": "2px", "flexShrink": "0",
        }),
        html.Div(domain, style={
            "fontSize": "1.05rem", "fontWeight": "800",
            "color": _C["text_bright"], "letterSpacing": "-0.01em",
        }),
        html.Span(f"{count} control{'s' if count != 1 else ''}", style={
            "fontSize": "0.72rem", "fontWeight": "600",
            "color": color, "background": bg,
            "borderRadius": "999px", "padding": "2px 10px",
            "marginLeft": "0.5rem",
        }),
    ], style={
        "display": "flex", "alignItems": "center", "gap": "0.6rem",
        "marginBottom": "0.75rem", "marginTop": "0.25rem",
    })


# ── Build catalogue view ──────────────────────────────────────────────────────

def _build_catalogue(controls, domain_f, platform_f, sev_f, search):
    # Apply filters
    filtered = controls

    if domain_f and domain_f != "All Domains":
        filtered = [c for c in filtered if c["domain"] == domain_f]

    if platform_f and platform_f != "All Platforms":
        plat_rev = {v: k for k, v in PLATFORM_LABELS.items()}
        plat_key = plat_rev.get(platform_f, platform_f)
        filtered = [c for c in filtered if c["platform"] == plat_key]

    if sev_f and sev_f != "All Severities":
        filtered = [c for c in filtered if c["severity"].lower() == sev_f.lower()]

    if search:
        q = search.lower()
        filtered = [c for c in filtered
                    if q in c["control_id"].lower() or q in c["title"].lower()]

    if not filtered:
        return html.Div([
            html.Div("No controls match the current filters.", style={
                "textAlign": "center", "color": _C["text_dim"],
                "fontSize": "0.85rem", "padding": "3rem 0",
            }),
        ])

    # Group by domain in DOMAIN_ORDER
    from collections import defaultdict
    grouped = defaultdict(list)
    for c in filtered:
        grouped[c["domain"]].append(c)

    sections = []
    for domain in DOMAIN_ORDER:
        if domain not in grouped:
            continue
        domain_controls = grouped[domain]
        # Sort: high severity first, then by control_id
        domain_controls.sort(key=lambda c: (
            -{"high": 3, "medium": 2, "low": 1}.get(c.get("severity", ""), 0),
            c["control_id"],
        ))
        sections.append(html.Div([
            _domain_header(domain, len(domain_controls)),
            html.Div([_control_card(c) for c in domain_controls]),
        ], style={"marginBottom": "1.5rem"}))

    count_text = html.Div(
        f"Showing {len(filtered)} of {len(controls)} controls",
        style={"fontSize": "0.72rem", "color": _C["text_dim"],
               "marginBottom": "0.75rem"},
    )

    return html.Div([count_text, *sections])


# ── Layout ────────────────────────────────────────────────────────────────────

def _load_safe():
    try:
        return _load_controls()
    except Exception:
        return []

_controls_cache = _load_safe()

layout = html.Div([
    # Page header
    html.Div([
        html.H1("Control Catalogue", style={
            "fontSize": "1.65rem", "fontWeight": "800", "color": _C["text_bright"],
            "letterSpacing": "-0.03em", "margin": "0 0 4px 0",
        }),
        html.Div(
            "All security controls checked by this system — with ISO 27001 and PDPA mappings, "
            "risk factors, and status-specific recommendations.",
            style={"fontSize": "0.78rem", "color": _C["text_dim"]},
        ),
    ], style={"marginBottom": "1.5rem"}),

    # Summary stats
    _summary_strip(_controls_cache),

    # Filter bar
    _section_label("Browse Controls"),
    _filter_bar(_controls_cache),

    # Control cards container
    html.Div(
        id="catalogue-body",
        children=_build_catalogue(_controls_cache, "All Domains",
                                   "All Platforms", "All Severities", ""),
    ),

    # Store controls data
    dcc.Store(id="cat-controls-store", data=_controls_cache),

], className="page")


# ── Filter callback ───────────────────────────────────────────────────────────

@callback(
    Output("catalogue-body", "children"),
    Input("cat-domain-filter",   "value"),
    Input("cat-platform-filter", "value"),
    Input("cat-sev-filter",      "value"),
    Input("cat-search",          "value"),
    State("cat-controls-store",  "data"),
)
def filter_catalogue(domain_f, platform_f, sev_f, search, controls):
    if not controls:
        return html.Div("Could not load controls.json.", style={
            "textAlign": "center", "color": "#dc2626", "padding": "2rem",
        })
    return _build_catalogue(
        controls,
        domain_f    or "All Domains",
        platform_f  or "All Platforms",
        sev_f       or "All Severities",
        search      or "",
    )