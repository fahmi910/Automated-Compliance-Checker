import dash
from dash import Dash, html, dcc, Input, Output, State, callback
import dash_bootstrap_components as dbc

app = Dash(
    __name__,
    use_pages=True,
    external_stylesheets=[dbc.themes.BOOTSTRAP],
    suppress_callback_exceptions=True,
    title="ComplianceAI",
)
server = app.server

app.layout = html.Div([
    dcc.Location(id="url"),
    dcc.Store(id="api-base-store", data="http://127.0.0.1:8000"),
    dcc.Interval(id="global-refresh", interval=300_000, n_intervals=0),

    # ── Sidebar ───────────────────────────────────────────────────────────────
    html.Div([
        html.Div([
            html.Div("🛡", className="brand-icon"),
            html.Div([
                html.Div("ComplianceAI", className="brand-name"),
                html.Div("FYP · Security Dashboard", className="brand-sub"),
            ]),
        ], className="brand-block"),

        html.Hr(className="sidebar-divider"),

        html.Div("API SERVER", className="sidebar-section-title"),
        html.Div([
            dcc.Input(
                id="api-base-input", type="text",
                value="http://127.0.0.1:8000",
                placeholder="http://localhost:5000",
                className="api-input",
            ),
            html.Div(id="sidebar-conn-status", className="conn-status"),
        ], className="sidebar-server"),

        html.Hr(className="sidebar-divider"),

        html.Div("NAVIGATION", className="sidebar-section-title"),
        html.Nav([
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "Overview"],            className="nav-item"), href="/",            className="nav-link"), id="nav-overview"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "Host Details"],        className="nav-item"), href="/host",         className="nav-link"), id="nav-host"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "History"],             className="nav-item"), href="/history",      className="nav-link"), id="nav-history"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "Compare"],             className="nav-item"), href="/compare",      className="nav-link"), id="nav-compare"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "Report Export"],       className="nav-item"), href="/report",       className="nav-link"), id="nav-report"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "Control Catalogue"],   className="nav-item"), href="/catalogue",    className="nav-link"), id="nav-catalogue"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "Remediation Tracker"], className="nav-item"), href="/remediation",  className="nav-link"), id="nav-remediation"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "About"],               className="nav-item"), href="/about",        className="nav-link"), id="nav-about"),
            html.Div(dcc.Link(html.Div([html.Span(className="nav-dot"), "Unit Testing"],        className="nav-item"), href="/unit-testing", className="nav-link"), id="nav-unit-testing"),
        ], className="nav-list"),

        html.Div("FYP 2025/26", className="sidebar-footer"),
    ], className="sidebar"),

    # ── Main content ──────────────────────────────────────────────────────────
    html.Div(dash.page_container, className="main-content"),

], className="app-shell")


# ── Sync API URL input → store ────────────────────────────────────────────────
@callback(Output("api-base-store","data"), Input("api-base-input","value"))
def sync_api_url(val):
    return (val or "").rstrip("/") or "http://127.0.0.1:8000"


# ── Sidebar connection status (self-contained, no page deps) ──────────────────
@callback(
    Output("sidebar-conn-status","children"),
    Output("sidebar-conn-status","className"),
    Input("global-refresh","n_intervals"),
    Input("api-base-store","data"),
)
def check_conn(_, base_url):
    from helpers import health, get_base_url
    try:
        health(get_base_url(base_url))
        return "● Connected", "conn-status conn-ok"
    except:
        return "○ Disconnected", "conn-status conn-err"


if __name__ == "__main__":
    app.run(debug=True, port=8050)


# ── Active nav highlight ───────────────────────────────────────────────────────
_NAV_PAGES = [
    ("nav-overview",    "/",            "Overview"),
    ("nav-host",        "/host",        "Host Details"),
    ("nav-history",     "/history",     "History"),
    ("nav-compare",     "/compare",     "Compare"),
    ("nav-report",      "/report",      "Report Export"),
    ("nav-catalogue",   "/catalogue",   "Control Catalogue"),
    ("nav-remediation", "/remediation", "Remediation Tracker"),
    ("nav-about",       "/about",       "About"),
    ("nav-unit-testing", "/unit-testing", "Unit Testing"),
]

@callback(
    [Output(nav_id, "children") for nav_id, _, _ in _NAV_PAGES],
    Input("url", "pathname"),
)
def set_active_nav(pathname):
    out = []
    for nav_id, href, label in _NAV_PAGES:
        is_active = (pathname == href) or (href != "/" and (pathname or "").startswith(href))
        item = html.Div(
            [html.Span(className="nav-dot"), label],
            className="nav-item nav-active" if is_active else "nav-item",
        )
        out.append(dcc.Link(item, href=href, className="nav-link"))
    return out