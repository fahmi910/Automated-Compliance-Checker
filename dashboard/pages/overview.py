import dash
from dash import html, dcc, callback, Input, Output
from helpers import (
    get_base_url, list_hosts, latest_evaluated, get_score_summary,
    normalize_controls, fmt_dt, risk_key, sev_key,
    kpi_card, section_header, data_table, risk_badge, empty_state, error_banner,
)

dash.register_page(__name__, path="/", name="Overview")

layout = html.Div([
    html.Div([
        html.H1("Overview"),
        html.P("Real-time compliance status across all monitored hosts.", className="page-subtitle"),
    ], className="page-header"),
    html.Div(id="ov-body"),
], className="page")


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

    host_rows, risk_rows = [], []
    score_sum, score_cnt, total_fails, critical_cnt = 0, 0, 0, 0

    for h in hosts:
        hostname = h.get("hostname")
        if not hostname: continue
        try:
            ev    = latest_evaluated(base, hostname)
            ss    = get_score_summary(ev)
            ctrls = normalize_controls(ev.get("results", []))
            fails      = [c for c in ctrls if c["status"] == "FAIL"]
            high_fails = [c for c in fails  if c["severity"] == "high"]
            top_issue  = (high_fails[0]["control_id"] + " (High)") if high_fails \
                         else (fails[0]["control_id"] if fails else "—")
            rk    = risk_key(ss.get("risk_score"))
            score = ss.get("compliance_score")
            if score is not None: score_sum += float(score); score_cnt += 1
            total_fails += len(fails)
            if rk in ("severe","critical"): critical_cnt += 1

            host_rows.append({
                "Hostname":  hostname,
                "IP":        h.get("ip_address","—"),
                "OS":        h.get("os_type","—"),
                "Last Seen": fmt_dt(h.get("last_seen")),
                "Audit ID":  str(ev.get("audit_id","—")),
                "Evaluated": fmt_dt(ev.get("received_at")),
                "Score":     html.Span(f"{score}%", style={"color":"#2563eb","fontWeight":"700"})
                             if score is not None else html.Span("—"),
                "Risk":      risk_badge(rk),
                "Fails":     str(len(fails)),
                "Top Issue": top_issue,
                "_rk": rk,
            })
            for r in ss.get("top_risks", []):
                sk = sev_key(r.get("severity",""))
                risk_rows.append({
                    "Host":           hostname,
                    "Severity":       risk_badge(sk),
                    "Control":        r.get("control_id",""),
                    "Domain":         r.get("domain",""),
                    "Evidence":       r.get("reason",""),
                    "Recommendation": r.get("recommendation",""),
                    "_rk": sk,
                    "_rank": {"high":3,"moderate":2,"low":1}.get(sk,0),
                })
        except Exception as e:
            host_rows.append({
                "Hostname": hostname,"IP":h.get("ip_address","—"),"OS":h.get("os_type","—"),
                "Last Seen":fmt_dt(h.get("last_seen")),"Audit ID":"—","Evaluated":"—",
                "Score":html.Span("—"),"Risk":html.Span("Error"),"Fails":"—",
                "Top Issue":str(e),"_rk":"unknown",
            })

    avg_score = round(score_sum / max(1, score_cnt), 1)
    accent    = "#16a34a" if avg_score >= 70 else "#ca8a04" if avg_score >= 40 else "#dc2626"

    kpis = html.Div([
        kpi_card("Hosts Monitored",   len(hosts),      "#3b82f6"),
        kpi_card("Avg Compliance",    f"{avg_score}%", accent),
        kpi_card("Total Failures",    total_fails,     "#dc2626"),
        kpi_card("Critical / Severe", critical_cnt,    "#ea580c"),
    ], className="kpi-row")

    h_cols   = ["Hostname","IP","OS","Last Seen","Audit ID","Evaluated","Score","Risk","Fails","Top Issue"]
    host_tbl = data_table(h_cols, host_rows, row_risk_key_col="_rk")

    risk_rows_sorted = sorted(risk_rows, key=lambda x: x["_rank"], reverse=True)
    r_cols   = ["Host","Severity","Control","Domain","Evidence","Recommendation"]
    risk_tbl = data_table(r_cols, risk_rows_sorted[:15], row_risk_key_col="_rk",
                          wrap_cols={"Evidence","Recommendation"})

    return html.Div([
        kpis,
        html.Div(style={"height":"1.5rem"}),
        section_header("Host Summary", "🖥"),
        host_tbl,
        html.Div(style={"height":"2rem"}),
        section_header("Top Risks — All Hosts", "⚠"),
        risk_tbl if risk_rows else empty_state("No failed findings detected."),
    ])
