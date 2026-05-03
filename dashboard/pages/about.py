import dash
from dash import html
from helpers import section_header, data_table

dash.register_page(__name__, path="/about", name="About")

layout = html.Div([
    html.Div([
        html.H1("About"),
        html.P("Automated Compliance Checker — Final Year Project", className="page-subtitle"),
    ], className="page-header"),

    html.Div([
        html.Div([
            html.Div("🛡", style={"fontSize":"3.5rem","marginBottom":"0.75rem"}),
            html.H2("ComplianceAI", style={"color":"#111827","margin":"0 0 0.5rem","fontSize":"1.5rem"}),
            html.P(
                "An automated security compliance auditing system that deploys lightweight agents "
                "across hosts, collects audit data, evaluates it against security controls, and "
                "surfaces risks through this real-time dashboard.",
                style={"color":"#6b7280","lineHeight":"1.8","maxWidth":"560px","margin":"0 auto"},
            ),
        ], style={"textAlign":"center","padding":"1.5rem 0 2rem"}),

        html.Div([
            html.Div([
                section_header("API Endpoints","🔌"),
                data_table(["Method","Endpoint","Purpose"],[
                    {"Method":"GET","Endpoint":"/health",                   "Purpose":"Server health check"},
                    {"Method":"GET","Endpoint":"/hosts",                    "Purpose":"List all registered hosts"},
                    {"Method":"GET","Endpoint":"/audits/latest/evaluated",  "Purpose":"Latest evaluated audit per host"},
                    {"Method":"GET","Endpoint":"/audits",                   "Purpose":"Audit history with limit"},
                    {"Method":"GET","Endpoint":"/audits/<id>/evaluated",    "Purpose":"Full evaluated audit detail"},
                ]),
            ], style={"flex":"1"}),
            html.Div([
                section_header("Dashboard Pages","📄"),
                data_table(["Page","Description"],[
                    {"Page":"Overview",     "Description":"Cross-host KPIs and top risk summary"},
                    {"Page":"Host Details", "Description":"Scores, domain breakdown, control drill-down"},
                    {"Page":"History",      "Description":"Audit log with trend charts"},
                    {"Page":"Compare",      "Description":"Side-by-side audit diff"},
                    {"Page":"About",        "Description":"Project info and API reference"},
                ]),
            ], style={"flex":"1"}),
        ], style={"display":"flex","gap":"2rem","alignItems":"flex-start","flexWrap":"wrap"}),

        html.Div(style={"height":"2rem"}),
        section_header("Tech Stack","⚙"),
        html.Div([
            html.Div([
                html.Div(icon, className="stack-icon"),
                html.Div(name, className="stack-name"),
                html.Div(desc, className="stack-desc"),
            ], className="stack-card")
            for icon,name,desc in [
                ("🐍","Python 3","Core language"),
                ("⚡","Dash","Dashboard framework"),
                ("📊","Plotly","Interactive charts"),
                ("🌶","Flask","Audit API backend"),
                ("🤖","Agents","Host audit collectors"),
            ]
        ], className="stack-row"),

        html.Div("FYP 2025/26  ·  Built with Dash + Plotly + Flask",
                 style={"color":"#d1d5db","fontSize":"0.78rem","marginTop":"3rem","textAlign":"center"}),
    ], className="page-body"),
], className="page")
