import dash
from dash import html, dcc, callback, Input, Output
from helpers import (
    get_base_url, list_hosts, latest_evaluated, get_score_summary,
    normalize_controls, fmt_dt, risk_key, sev_key,
    risk_badge, empty_state, error_banner, RISK_MAP,
    get_plain_reason, get_plain_recommendation,
)

dash.register_page(__name__, path="/", name="Overview")

_C = {
    "card":        "#ffffff",
    "bg":          "#f4f6fb",
    "border":      "#e5e9f2",
    "text":        "#374151",
    "text_dim":    "#9ca3af",
    "text_bright": "#111827",
    "blue":        "#2563eb",
    "blue_dim":    "rgba(37,99,235,0.08)",
    "shadow_sm":   "0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)",
    "shadow_md":   "0 4px 12px rgba(0,0,0,0.08)",
    "radius":      "10px",
    "radius_lg":   "14px",
}

DOMAIN_ICONS = {
    "Access Control":                    "🔐",
    "Logging & Monitoring":              "📋",
    "Asset & Configuration Management":  "⚙️",
    "Cryptography":                      "🔒",
    "Backup & Recovery":                 "💾",
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
    ], style={"display": "flex", "alignItems": "center", "gap": "0.75rem", "marginBottom": "0.75rem"})


def _score_accent(score):
    if score is None:
        return "#6b7280"
    return "#16a34a" if score >= 70 else "#ca8a04" if score >= 40 else "#dc2626"


# ── Zone 1 ────────────────────────────────────────────────────────────────────

def _pulse_card(value, label, accent):
    return _card([
        # Accent top bar — full width, flush to card top
        html.Div(style={
            "height":       "4px",
            "background":   accent,
            "borderRadius": "14px 14px 0 0",
            "marginBottom": "1.4rem",
        }),
        # Content — centred
        html.Div([
            html.Div(str(value), style={
                "fontSize":           "2.6rem",
                "fontWeight":         "800",
                "color":              accent,
                "lineHeight":         "1",
                "fontVariantNumeric": "tabular-nums",
                "letterSpacing":      "-0.03em",
                "marginBottom":       "0.65rem",
            }),
            html.Div(label, style={
                "fontSize":  "0.82rem",
                "fontWeight":"500",
                "color":     _C["text_dim"],
                "lineHeight":"1.3",
            }),
        ], style={
            "display":        "flex",
            "flexDirection":  "column",
            "alignItems":     "center",
            "justifyContent": "center",
            "textAlign":      "center",
            "paddingBottom":  "1rem",
        }),
    ], {"padding": "0", "overflow": "hidden"})


def zone1_fleet_pulse(hosts, avg_score, total_fails, critical_cnt):
    accent = _score_accent(avg_score)
    return html.Div([
        _pulse_card(len(hosts),      "Total Host Monitored",      "#2563eb"),
        _pulse_card(f"{avg_score}%", "Average Compliance Score",  accent),
        _pulse_card(total_fails,     "Total Active Fail Controls","#dc2626"),
        _pulse_card(critical_cnt,    "Critical / Severe Host",    "#ea580c"),
    ], style={"display": "grid", "gridTemplateColumns": "repeat(4, 1fr)",
              "gap": "1rem", "marginBottom": "1.25rem"})


# ── Zone 2A ───────────────────────────────────────────────────────────────────

def _host_bar_row(hostname, platform, score, rk, fail_count):
    pct    = float(score) if score is not None else 0.0
    accent = RISK_MAP.get(rk, RISK_MAP["unknown"])["color"]
    return html.Div([
        html.Div([
            html.Span(hostname, style={"fontSize": "0.83rem", "fontWeight": "700",
                                       "color": _C["text_bright"]}),
        ], style={"width": "160px", "flexShrink": "0", "display": "flex", "alignItems": "center"}),
        html.Div(
            html.Div(style={"width": f"{min(pct,100)}%", "height": "100%",
                            "background": accent, "borderRadius": "4px",
                            "minWidth": "2px", "transition": "width 0.5s ease"}),
            style={"flex": "1", "height": "10px", "background": _C["bg"],
                   "borderRadius": "4px", "overflow": "hidden",
                   "margin": "0 1rem", "border": f"1px solid {_C['border']}"},
        ),
        html.Span(f"{pct:.0f}%", style={
            "fontSize": "0.82rem", "fontWeight": "700", "color": accent,
            "width": "42px", "textAlign": "right", "flexShrink": "0",
            "fontVariantNumeric": "tabular-nums",
        }),
        html.Div(risk_badge(rk), style={"marginLeft": "0.75rem", "flexShrink": "0"}),
        html.Span(
            f"{fail_count} fail{'s' if fail_count!=1 else ''}",
            style={
                "marginLeft": "0.75rem", "fontSize": "0.7rem", "fontWeight": "600",
                "color": "#dc2626" if fail_count > 0 else "#16a34a",
                "background": "#fef2f2" if fail_count > 0 else "#f0fdf4",
                "border": f"1px solid {'#fca5a5' if fail_count>0 else '#86efac'}",
                "borderRadius": "999px", "padding": "2px 8px", "flexShrink": "0",
            },
        ),
    ], style={"display": "flex", "alignItems": "center", "padding": "0.65rem 0",
              "borderBottom": f"1px solid {_C['border']}"})


def zone2a_host_bars(host_rows):
    rows = sorted(host_rows, key=lambda r: (r["score"] or 0))
    return _card([
        html.Div("Host Compliance Rate", style={
            "fontSize": "1rem", "fontWeight": "700",
            "color": _C["text_bright"],
            "paddingBottom": "0.85rem",
            "marginBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div([
            _host_bar_row(r["hostname"], r["platform"], r["score"], r["rk"], r["fails"])
            for r in rows
        ]),
    ], {"padding": "1.3rem 1.4rem"})


# ── Zone 2B ───────────────────────────────────────────────────────────────────

def _risk_item(hostname, control_id, title, domain, reason, residual_risk, severity, status):
    sev_low = (severity or "").lower()
    border_color = {"high": "#dc2626", "medium": "#ca8a04", "low": "#16a34a"}.get(sev_low, "#6b7280")
    status_colors = {"FAIL": ("#dc2626", "#fef2f2"), "PARTIAL": ("#ca8a04", "#fefce8")}
    sc = status_colors.get(status, ("#6b7280", "#f9fafb"))
    return html.Div([
        html.Div([
            html.Div([
                html.Span(title or control_id, style={
                    "fontSize": "0.82rem", "fontWeight": "700", "color": _C["text_bright"],
                }),
                html.Span(status, style={
                    "fontSize": "0.65rem", "fontWeight": "700", "color": sc[0],
                    "background": sc[1], "borderRadius": "4px", "padding": "1px 6px", "marginLeft": "6px",
                }),
            ], style={"display": "flex", "alignItems": "center", "flexWrap": "wrap", "gap": "0.2rem"}),
            html.Span(f"{residual_risk:.1f}", style={
                "fontSize": "1.1rem", "fontWeight": "800", "color": border_color,
                "fontVariantNumeric": "tabular-nums",
                "marginRight": "0.5rem", "flexShrink": "0",
            }),
        ], style={"display": "flex", "justifyContent": "space-between", "alignItems": "flex-start"}),
        html.Div([
            html.Span(hostname, style={
                "fontSize": "0.68rem", "color": _C["blue"], "fontWeight": "600",
                "background": _C["blue_dim"], "borderRadius": "4px", "padding": "1px 6px",
            }),
            html.Span("·", style={"color": _C["text_dim"], "margin": "0 3px"}),
            html.Span(domain, style={"fontSize": "0.68rem", "color": _C["text_dim"]}),
        ], style={"display": "flex", "alignItems": "center", "margin": "0.3rem 0"}),
        html.P(
            get_plain_reason(control_id, status) or reason or "",
            style={
                "fontSize":  "0.74rem", "color": _C["text"],
                "lineHeight": "1.6", "margin": "0",
                "whiteSpace": "normal", "wordBreak": "break-word",
            },
        ),
    ], style={
        "borderLeft": f"3px solid {border_color}", "paddingLeft": "0.85rem",
        "paddingTop": "0.6rem", "paddingBottom": "0.6rem", "marginBottom": "0.6rem",
        "background": _C["bg"], "borderRadius": "0 8px 8px 0",
    })


def zone2b_top_risks(all_top_risks):
    high_count = sum(1 for _, _, r in all_top_risks if (r.get("severity") or "").lower() == "high")
    items = [
        _risk_item(
            hostname=hn,
            control_id=r.get("control_id", ""),
            title=r.get("title", r.get("control_id", "")),
            domain=r.get("domain", ""),
            reason=r.get("reason", ""),
            residual_risk=float(r.get("residual_risk", 0)),
            severity=r.get("severity", ""),
            status=r.get("status", ""),
        )
        for _, hn, r in all_top_risks[:8]
    ]
    return _card([
        html.Div([
            html.Div("Top Risks — All Hosts", style={
                "fontSize": "1rem", "fontWeight": "700",
                "color": _C["text_bright"],
            }),
            html.Span(f"{high_count} HIGH", style={
                "fontSize": "0.65rem", "fontWeight": "700", "color": "#dc2626",
                "background": "#fef2f2", "border": "1px solid #fca5a5",
                "borderRadius": "4px", "padding": "2px 8px", "flexShrink": "0",
            }) if high_count > 0 else None,
        ], style={
            "display": "flex", "justifyContent": "space-between",
            "alignItems": "center",
            "paddingBottom": "0.85rem",
            "marginBottom": "0.85rem",
            "borderBottom": f"1px solid {_C['border']}",
        }),
        html.Div(
            items if items else empty_state("No active failures. ✅"),
            style={"overflowY": "auto", "maxHeight": "380px"},
        ),
    ], {"padding": "1.3rem 1.4rem"})


# ── Zone 3 ────────────────────────────────────────────────────────────────────

def _mini_bar(hostname, score, highlight, accent):
    """
    highlight — bool, True if this host is among the lowest scorers in this domain.
                Highlighted hosts show red bold name. All bars use the accent colour.
    """
    pct = float(score) if score is not None else 0.0
    name_color = "#dc2626" if highlight else _C["text_dim"]
    name_weight = "700" if highlight else "500"
    return html.Div([
        html.Div(hostname[:14], style={
            "fontSize": "0.65rem", "fontWeight": name_weight, "color": name_color,
            "width": "80px", "flexShrink": "0",
            "overflow": "hidden", "textOverflow": "ellipsis", "whiteSpace": "nowrap",
        }),
        html.Div(
            html.Div(style={"width": f"{min(pct,100)}%", "height": "100%",
                            "background": accent, "borderRadius": "3px", "minWidth": "2px"}),
            style={"flex": "1", "height": "7px", "background": _C["bg"], "borderRadius": "3px",
                   "overflow": "hidden", "border": f"1px solid {_C['border']}", "margin": "0 0.5rem"},
        ),
        html.Span(f"{pct:.0f}%", style={
            "fontSize": "0.65rem", "fontWeight": name_weight,
            "color": "#dc2626" if highlight else accent,
            "width": "30px", "textAlign": "right", "flexShrink": "0",
        }),
    ], style={
        "display": "flex", "alignItems": "center", "marginBottom": "5px",
        "background": "#fef2f2" if highlight else "transparent",
        "borderRadius": "4px", "padding": "2px 4px",
    })


def _domain_card(domain_name, per_host_data):
    # Domain-level compliance score = average across all hosts in this domain
    scores = [(hn, s) for hn, _, s, _, _ in per_host_data if s is not None]
    avg_domain = round(sum(s for _, s in scores) / len(scores), 1) if scores else None

    # Find the lowest score value, then highlight ALL hosts sharing that score
    lowest_score = min(s for _, s in scores) if scores else None
    lowest_hostnames = {hn for hn, s in scores if s == lowest_score} if lowest_score is not None else set()

    # Total control failures across all hosts in this domain
    total_fails = sum(f for _, _, _, _, f in per_host_data)

    # Card accent colour based on avg domain compliance
    worst_rk = (
        "severe"   if avg_domain is not None and avg_domain < 20  else
        "critical" if avg_domain is not None and avg_domain < 40  else
        "high"     if avg_domain is not None and avg_domain < 70  else
        "moderate" if avg_domain is not None and avg_domain < 90  else
        "low"      if avg_domain is not None else "unknown"
    )
    accent = RISK_MAP.get(worst_rk, RISK_MAP["unknown"])["color"]

    mini_bars = [
        _mini_bar(
            hostname=hostname,
            score=score,
            highlight=(hostname in lowest_hostnames),
            accent=accent,
        )
        for hostname, _, score, _, _ in per_host_data
    ]

    return _card([
        # Top accent bar
        html.Div(style={"height": "3px", "background": accent,
                        "borderRadius": "14px 14px 0 0", "marginBottom": "1rem"}),

        # Domain name — centred, no emoji
        html.Div(domain_name, style={
            "fontSize": "0.88rem", "fontWeight": "700",
            "color": _C["text_bright"], "textAlign": "center",
            "lineHeight": "1.3", "marginBottom": "0.75rem",
        }),

        # Domain compliance score — label on top, big number below
        html.Div([
            html.Div("average score", style={
                "fontSize": "0.68rem", "color": _C["text_dim"],
                "marginBottom": "0.2rem",
            }),
            html.Div(
                f"{avg_domain:.0f}%" if avg_domain is not None else "—",
                style={"fontSize": "1.8rem", "fontWeight": "800", "color": accent,
                       "fontVariantNumeric": "tabular-nums", "letterSpacing": "-0.02em"},
            ),
        ], style={"display": "flex", "flexDirection": "column", "alignItems": "center",
                  "marginBottom": "0.85rem"}),

        # Per-host mini bars
        html.Div(mini_bars, style={"marginBottom": "0.85rem"}),

        # Bottom tag — control failure count
        html.Span(
            f"{total_fails} control failure{'s' if total_fails!=1 else ''}",
            style={
                "fontSize": "0.68rem", "fontWeight": "600",
                "color": "#dc2626" if total_fails > 0 else "#16a34a",
                "background": "#fef2f2" if total_fails > 0 else "#f0fdf4",
                "border": f"1px solid {'#fca5a5' if total_fails>0 else '#86efac'}",
                "borderRadius": "999px", "padding": "2px 10px",
            },
        ),
    ], {"padding": "0 1.1rem 1.1rem", "overflow": "hidden"})


def zone3_domain_health(domain_data):
    cards = [_domain_card(d, domain_data[d]) for d in DOMAIN_ORDER if d in domain_data]
    return html.Div(cards, style={
        "display": "grid",
        "gridTemplateColumns": f"repeat({len(cards)}, 1fr)",
        "gap": "1rem", "marginTop": "0",
    })


# ── Page header ───────────────────────────────────────────────────────────────

def _page_header(avg_score):
    accent = _score_accent(avg_score)
    label  = "Good" if avg_score >= 70 else "Warning" if avg_score >= 40 else "At Risk"
    return html.Div([
        html.Div([
            html.H1("Compliance Overview", style={
                "fontSize": "1.65rem", "fontWeight": "800", "color": _C["text_bright"],
                "letterSpacing": "-0.03em", "margin": "0 0 4px 0",
            }),
            html.Div([
                html.Span("●", style={"color": "#16a34a", "fontSize": "0.55rem"}),
                html.Span(" Live · auto-refresh every 5 min",
                          style={"fontSize": "0.78rem", "color": _C["text_dim"]}),
            ], style={"display": "flex", "alignItems": "center", "gap": "0.3rem"}),
        ]),
        html.Span(f"{avg_score}%  {label}", style={
            "fontSize": "0.82rem", "fontWeight": "700", "color": accent,
            "background": "#f0fdf4" if avg_score>=70 else "#fefce8" if avg_score>=40 else "#fef2f2",
            "border": f"1px solid {'#86efac' if avg_score>=70 else '#fde047' if avg_score>=40 else '#fca5a5'}",
            "borderRadius": "999px", "padding": "5px 14px",
        }),
    ], style={"display": "flex", "justifyContent": "space-between",
              "alignItems": "center", "marginBottom": "1.25rem"})


# ── Layout ────────────────────────────────────────────────────────────────────

layout = html.Div([html.Div(id="ov-body")], className="page")


@callback(
    Output("ov-body", "children"),
    Input("global-refresh", "n_intervals"),
    Input("api-base-store", "data"),
)
def refresh_overview(_, base_url):
    base = get_base_url(base_url)
    try:
        hosts = list_hosts(base).get("hosts", [])
    except Exception as e:
        return error_banner(f"Cannot reach API — {e}")
    if not hosts:
        return empty_state("No hosts registered yet. Run your first audit agent.")

    host_rows, all_top_risks, domain_data = [], [], {}
    score_sum, score_cnt, total_fails, critical_cnt = 0, 0, 0, 0

    for h in hosts:
        hostname = h.get("hostname")
        if not hostname:
            continue
        try:
            ev       = latest_evaluated(base, hostname)
            ss       = get_score_summary(ev)
            ctrls    = normalize_controls(ev.get("results", []))
            platform = ev.get("platform", "")
            fails    = [c for c in ctrls if c["status"] == "FAIL"]
            rk       = risk_key(ss.get("risk_score"))
            score    = ss.get("compliance_score")

            if score is not None:
                score_sum += float(score); score_cnt += 1
            total_fails += len(fails)
            if rk in ("severe", "critical"):
                critical_cnt += 1

            host_rows.append({"hostname": hostname, "platform": platform,
                               "score": score, "rk": rk, "fails": len(fails)})

            sev_order = {"high": 3, "medium": 2, "low": 1}
            for r in (ss.get("top_risks") or []):
                rr = float(r.get("residual_risk", 0))
                sk = (sev_order.get((r.get("severity") or "").lower(), 0), rr)
                all_top_risks.append((sk, hostname, r))

            for dname, dinfo in (ss.get("domain_scores") or {}).items():
                d_fails = len([c for c in ctrls if c["domain"]==dname and c["status"]=="FAIL"])
                if dname not in domain_data:
                    domain_data[dname] = []
                domain_data[dname].append((
                    hostname, platform,
                    dinfo.get("compliance_score"),
                    dinfo.get("risk_score", 0),
                    d_fails,
                ))
        except Exception:
            host_rows.append({"hostname": hostname, "platform": "",
                               "score": None, "rk": "unknown", "fails": 0})

    avg_score = round(score_sum / max(1, score_cnt), 1)
    all_top_risks.sort(key=lambda x: x[0], reverse=True)

    return html.Div([
        _page_header(avg_score),
        _section_label("Fleet Pulse"),
        zone1_fleet_pulse(hosts, avg_score, total_fails, critical_cnt),
        _section_label("Host Status & Active Risks"),
        html.Div([
            zone2a_host_bars(host_rows),
            zone2b_top_risks(all_top_risks),
        ], style={"display": "grid", "gridTemplateColumns": "1fr 1fr",
                  "gap": "1rem", "alignItems": "start", "marginBottom": "1.25rem"}),
        _section_label("Domain Health — Fleet View"),
        zone3_domain_health(domain_data),
    ])