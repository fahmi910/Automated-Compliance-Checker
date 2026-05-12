"""
dashboard/pages/unit_testing.py
ComplianceAI — Unit Test Runner Page
Interactive test runner embedded in the dashboard.
Route: /unit-testing
"""

import time
import json
import requests
import dash
from dash import html, dcc, callback, Input, Output, State, ALL, ctx
from helpers import get_base_url, error_banner, empty_state, risk_badge

dash.register_page(__name__, path="/unit-testing", name="Unit Testing")

# ── Colour tokens (matches existing dashboard palette) ────────────────────────
_C = {
    "card":        "#ffffff",
    "bg":          "#f4f6fb",
    "border":      "#e5e9f2",
    "border_mid":  "#d0d7e8",
    "text":        "#374151",
    "text_dim":    "#9ca3af",
    "text_bright": "#111827",
    "blue":        "#2563eb",
    "blue_dim":    "rgba(37,99,235,0.08)",
    "blue_light":  "#eff6ff",
    "pass":        "#16a34a",
    "pass_bg":     "#f0fdf4",
    "pass_border": "#86efac",
    "fail":        "#dc2626",
    "fail_bg":     "#fef2f2",
    "fail_border": "#fca5a5",
    "partial":     "#b45309",
    "partial_bg":  "#fefce8",
    "partial_bdr": "#fde047",
    "unknown":     "#1d4ed8",
    "unknown_bg":  "#dbeafe",
    "unknown_bdr": "#93c5fd",
    "warn_bg":     "#fff7ed",
    "warn_border": "#fdba74",
    "warn_text":   "#9a3412",
    "mono":        "'DM Mono', 'Courier New', monospace",
}

# ── Test case definitions ─────────────────────────────────────────────────────
TEST_CASES = [
    {
        "id": "TC-A01",
        "title": "All controls PASS",
        "description": "Submits a baseline payload where all 10 Linux controls are in their fully compliant state. Verifies the scoring model returns Compliance ≥ 95% and Risk ≤ 5.",
        "accent": _C["pass"],
        "accent_bg": _C["pass_bg"],
        "accent_border": _C["pass_border"],
        "fields": [],
        "assertions": [
            {"key": "compliance", "label": "Compliance score ≥ 95%",  "op": "gte", "thresh": 95,    "path": "compliance"},
            {"key": "risk",       "label": "Risk score ≤ 5",           "op": "lte", "thresh": 5,     "path": "risk"},
            {"key": "level",      "label": "Risk level = Low",         "op": "eq",  "thresh": "Low", "path": "level"},
        ],
    },
    {
        "id": "TC-A02",
        "title": "All controls FAIL",
        "description": "Forces every Linux control to fail. Verifies Compliance ≤ 10% and Risk ≥ 80. You can tweak individual evidence values below before running.",
        "accent": _C["fail"],
        "accent_bg": _C["fail_bg"],
        "accent_border": _C["fail_border"],
        "fields": [
            {"key": "a02_root",   "label": "AC-LNX-01 SSH root login",    "options": ["yes", "no", "prohibit-password"], "default": "yes"},
            {"key": "a02_pass",   "label": "AC-LNX-02 password auth",     "options": ["yes", "no"],                      "default": "yes"},
            {"key": "a02_fw",     "label": "FW-LNX-01 UFW status",        "options": ["inactive", "active"],             "default": "inactive"},
            {"key": "a02_rsys",   "label": "LOG-LNX-01 rsyslog running",  "options": ["false", "true"],                  "default": "false"},
        ],
        "assertions": [
            {"key": "compliance", "label": "Compliance score ≤ 10%",          "op": "lte", "thresh": 10,                    "path": "compliance"},
            {"key": "risk",       "label": "Risk score ≥ 80",                  "op": "gte", "thresh": 80,                    "path": "risk"},
            {"key": "level",      "label": "Risk level = Severe or Critical",  "op": "in",  "thresh": ["Severe","Critical"],  "path": "level"},
        ],
    },
    {
        "id": "TC-A03",
        "title": "PARTIAL status — AC-LNX-01",
        "description": "Sets ssh_permit_root_login_runtime = 'prohibit-password' which the evaluator maps to PARTIAL (SF=0.5). All other controls remain PASS. Verifies the verdict and that compliance is reduced but not zero.",
        "accent": _C["partial"],
        "accent_bg": _C["partial_bg"],
        "accent_border": _C["partial_bdr"],
        "fields": [
            {"key": "a03_val", "label": "AC-LNX-01 runtime value", "options": ["prohibit-password", "without-password", "no", "yes"], "default": "prohibit-password"},
        ],
        "assertions": [
            {"key": "ac_status",  "label": "AC-LNX-01 status = PARTIAL",         "op": "ctrl_eq",  "thresh": "PARTIAL",   "ctrl": "AC-LNX-01"},
            {"key": "compliance", "label": "Compliance between 80–99%",           "op": "between",  "thresh": [80, 99],    "path": "compliance"},
            {"key": "risk",       "label": "Risk > 0 (PARTIAL contributes SF=0.5)","op": "gt",       "thresh": 0,           "path": "risk"},
        ],
    },
    {
        "id": "TC-A04",
        "title": "UNKNOWN status — LOG-LNX-01",
        "description": "Removes the rsyslog_running key entirely, forcing LOG-LNX-01 to UNKNOWN. UNKNOWN uses SF=0.7 and earns 0 compliance points — risk stays positive even though nothing explicitly failed.",
        "accent": _C["unknown"],
        "accent_bg": _C["unknown_bg"],
        "accent_border": _C["unknown_bdr"],
        "fields": [
            {"key": "a04_remove", "label": "Remove rsyslog_running key", "options": ["yes — force UNKNOWN", "no — keep key"], "default": "yes — force UNKNOWN"},
        ],
        "assertions": [
            {"key": "log_status", "label": "LOG-LNX-01 = UNKNOWN or FAIL",             "op": "ctrl_in", "thresh": ["UNKNOWN","FAIL"], "ctrl": "LOG-LNX-01"},
            {"key": "risk",       "label": "Risk > 0  (UNKNOWN is not safe, SF=0.7)",   "op": "gt",      "thresh": 0,                  "path": "risk"},
            {"key": "compliance", "label": "Compliance < 100% (UNKNOWN earns 0 points)","op": "lt",      "thresh": 100,                "path": "compliance"},
        ],
    },
    {
        "id": "TC-A05",
        "title": "Evaluator logic — AC-LNX-01 per evidence value",
        "description": "Runs 5 sub-cases, each with a different ssh_permit_root_login_runtime value. Verifies the evaluator maps every value to the correct verdict. The 'without-password' case is a known documented gap.",
        "accent": _C["blue"],
        "accent_bg": _C["blue_light"],
        "accent_border": "#bfdbfe",
        "fields": [],
        "assertions": [
            {"key": "case_no",   "label": 'value = "no"               → PASS',                    "op": "case",    "thresh": "PASS",             "caseVal": "no"},
            {"key": "case_yes",  "label": 'value = "yes"              → FAIL',                    "op": "case",    "thresh": "FAIL",             "caseVal": "yes"},
            {"key": "case_pp",   "label": 'value = "prohibit-password" → PARTIAL',                "op": "case",    "thresh": "PARTIAL",          "caseVal": "prohibit-password"},
            {"key": "case_wp",   "label": 'value = "without-password"  → UNKNOWN  (known gap)',   "op": "case",    "thresh": "UNKNOWN",          "caseVal": "without-password"},
            {"key": "case_miss", "label": "key missing                 → UNKNOWN or FAIL",         "op": "case_in", "thresh": ["UNKNOWN","FAIL"], "caseVal": "__missing__"},
        ],
    },
]


# ── Payload builder (mirrors unit_tests.py) ───────────────────────────────────

def base_linux_payload(hostname):
    return {
        "hostname": hostname, "ip_address": "10.0.0.99",
        "os_type": "Linux", "os_version": "Ubuntu 22.04",
        "platform": "linux", "timestamp": "2026-01-01T00:00:00Z",
        "results": {
            "access_control": {
                "ssh_permit_root_login_runtime":       {"value": "no",            "source": "sshd -T",                    "collected": True},
                "ssh_permit_root_login":               {"value": "no",            "source": "/etc/ssh/sshd_config",       "collected": True},
                "ssh_password_authentication_runtime": {"value": "no",            "source": "sshd -T",                    "collected": True},
                "ssh_password_authentication":         {"value": "no",            "source": "/etc/ssh/sshd_config",       "collected": True},
                "accounts_never_logged_in":            {"value": [],              "source": "lastlog",                    "collected": True},
                "shell_accounts_passwd":               {"value": [],              "source": "/etc/passwd",                "collected": True},
                "account_lockout_pam":                 {"value": "pam_faillock",  "source": "/etc/pam.d/common-auth",    "collected": True},
                "faillock_conf_deny":                  {"value": "5",             "source": "/etc/security/faillock.conf","collected": True},
            },
            "logging": {
                "rsyslog_running":           {"value": True,  "source": "systemctl",          "collected": True},
                "syslog_recent_entries":     {"value": "Jan  1 00:00:01 ubuntu rsyslogd: start", "source": "/var/log/syslog", "collected": True},
                "failed_ssh_logins_snippet": {"value": "",    "source": "/var/log/auth.log",  "collected": True},
                "auth_log_exists":           {"value": True,  "source": "/var/log/auth.log",  "collected": True},
                "sudo_usage_snippet":        {"value": "Jan  1 00:00:00 sudo session opened", "source": "/var/log/auth.log", "collected": True},
                "logrotate_installed":       {"value": True,  "source": "which logrotate",    "collected": True},
                "logrotate_d_configs":       {"value": 3,     "source": "/etc/logrotate.d/",  "collected": True},
                "logrotate_trigger":         {"value": ["logrotate.timer"], "source": "systemctl list-timers", "collected": True},
            },
            "firewall": {
                "ufw_status": {"value": "active", "source": "ufw status", "collected": True},
                "ufw_rules":  {"value": {"rules_exist": True, "rules": ["22/tcp ALLOW"]}, "source": "ufw status verbose", "collected": True},
            },
            "crypto": {
                "weak_algorithms_detected": {"value": [], "source": "sshd -T", "collected": True},
            },
            "backup": {
                "backup_tools_installed": {"value": ["rsync"],                           "source": "which",         "collected": True},
                "backup_cron_jobs":       {"value": ["0 2 * * * rsync -a /home /backup"],"source": "crontab -l",   "collected": True},
                "backup_systemd_timers":  {"value": [],                                  "source": "systemctl",     "collected": True},
            },
            "ports": {
                "listening_ports": {"value": [{"port": 22, "proto": "tcp", "process": "sshd"}], "source": "ss -tlnp", "collected": True},
            },
        }
    }


def run_test(tc_id, field_values, base_url):
    """Run a single test case. Returns (passed, log_lines, assert_results)."""
    headers = {"Content-Type": "application/json", "X-API-Key": "supersecret123"}
    logs = []
    assert_results = {}

    def _log(msg, kind="info"):
        logs.append({"msg": msg, "kind": kind})

    try:
        if tc_id == "TC-A05":
            cases = [
                ("no",               "PASS",    "single"),
                ("yes",              "FAIL",    "single"),
                ("prohibit-password","PARTIAL",  "single"),
                ("without-password", "UNKNOWN",  "single"),
                ("__missing__",      ["UNKNOWN","FAIL"], "multi"),
            ]
            case_results = {}
            for val, expected, etype in cases:
                _log(f'→ Sub-case: value = "{val if val != "__missing__" else "[key removed]"}"')
                p = base_linux_payload(f"unit-test-tc-a05-{val.replace('-','').replace('_','')}")
                if val == "__missing__":
                    # Use raw string for listening_ports so contains_port_22_listening()
                    # finds ':22' + 'LISTEN' — applicability passes and AC-LNX-01 is
                    # evaluated (returning UNKNOWN) instead of being excluded entirely.
                    p["results"]["ports"]["listening_ports"]["value"] = (
                        "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN"
                    )
                    del p["results"]["access_control"]["ssh_permit_root_login_runtime"]
                    del p["results"]["access_control"]["ssh_permit_root_login"]
                else:
                    p["results"]["access_control"]["ssh_permit_root_login_runtime"]["value"] = val
                    p["results"]["access_control"]["ssh_permit_root_login"]["value"] = val
                r = requests.post(f"{base_url}/submit", headers=headers, json=p, timeout=10)
                r.raise_for_status()
                aid = r.json()["audit_id"]
                time.sleep(0.5)
                ev = requests.get(f"{base_url}/audits/{aid}/evaluated", headers=headers, timeout=10).json()
                ctrl = next((c for c in ev.get("results", []) if c.get("control_id") == "AC-LNX-01"), None)
                actual = ctrl.get("status") if ctrl else "NOT FOUND"
                case_results[val] = actual
                ok = (actual == expected) if etype == "single" else (actual in expected)
                _log(f'  {"✓" if ok else "✗"} "{val}" → {actual} (expected {expected if isinstance(expected,str) else "/".join(expected)})', "pass" if ok else "fail")

            # build assert_results from case_results
            all_pass = True
            for a in TEST_CASES[4]["assertions"]:
                cv = a["caseVal"]
                actual = case_results.get(cv, "not run")
                if a["op"] == "case":
                    passed = actual == a["thresh"]
                else:
                    passed = actual in a["thresh"]
                if not passed:
                    all_pass = False
                assert_results[a["key"]] = {"passed": passed, "actual": actual}
            return all_pass, logs, assert_results

        # TC-A01 to TC-A04
        p = base_linux_payload(f"unit-test-{tc_id.lower()}")

        if tc_id == "TC-A02":
            root_val = field_values.get("a02_root", "yes")
            pass_val = field_values.get("a02_pass", "yes")
            fw_val   = field_values.get("a02_fw",   "inactive")
            rsys_val = field_values.get("a02_rsys",  "false") == "true"
            p["results"]["access_control"]["ssh_permit_root_login_runtime"]["value"] = root_val
            p["results"]["access_control"]["ssh_permit_root_login"]["value"]         = root_val
            p["results"]["access_control"]["ssh_password_authentication_runtime"]["value"] = pass_val
            p["results"]["access_control"]["ssh_password_authentication"]["value"]   = pass_val
            p["results"]["access_control"]["accounts_never_logged_in"]["value"]      = ["user1","user2","user3","user4","user5"]
            p["results"]["access_control"]["shell_accounts_passwd"]["value"]         = ["user1","user2","user3","user4","user5"]
            p["results"]["access_control"]["account_lockout_pam"]["value"]           = "none"
            p["results"]["access_control"]["faillock_conf_deny"]["value"]            = "not_set"
            p["results"]["logging"]["rsyslog_running"]["value"]       = rsys_val
            p["results"]["logging"]["syslog_recent_entries"]["value"] = ""
            p["results"]["logging"]["auth_log_exists"]["value"]       = False
            p["results"]["logging"]["sudo_usage_snippet"]["value"]    = ""
            p["results"]["logging"]["logrotate_installed"]["value"]   = False
            p["results"]["logging"]["logrotate_d_configs"]["value"]   = 0
            p["results"]["logging"]["logrotate_trigger"]["value"]     = []
            p["results"]["firewall"]["ufw_status"]["value"]           = fw_val
            p["results"]["firewall"]["ufw_rules"]["value"]            = {"rules_exist": False, "rules": []}
            p["results"]["crypto"]["weak_algorithms_detected"]["value"] = ["3des-cbc","hmac-md5","diffie-hellman-group1-sha1"]
            p["results"]["backup"]["backup_tools_installed"]["value"] = []
            p["results"]["backup"]["backup_cron_jobs"]["value"]       = []

        elif tc_id == "TC-A03":
            val = field_values.get("a03_val", "prohibit-password")
            p["results"]["access_control"]["ssh_permit_root_login_runtime"]["value"] = val
            p["results"]["access_control"]["ssh_permit_root_login"]["value"]         = val

        elif tc_id == "TC-A04":
            remove = field_values.get("a04_remove", "yes — force UNKNOWN").startswith("yes")
            if remove:
                del p["results"]["logging"]["rsyslog_running"]

        _log(f"→ Submitting to {base_url}/submit")
        r = requests.post(f"{base_url}/submit", headers=headers, json=p, timeout=10)
        r.raise_for_status()
        aid = r.json()["audit_id"]
        _log(f"→ Audit ID: {aid}")
        time.sleep(0.5)
        ev = requests.get(f"{base_url}/audits/{aid}/evaluated", headers=headers, timeout=10).json()
        scores  = (ev.get("scores") or {}).get("summary", {})
        comp    = scores.get("compliance_score")
        risk    = scores.get("risk_score")
        level   = scores.get("risk_level")
        _log(f"→ Compliance: {round(comp,2) if comp is not None else 'null'}%")
        _log(f"→ Risk score: {round(risk,2) if risk is not None else 'null'}")
        _log(f"→ Risk level: {level}")

        tc_def = next(t for t in TEST_CASES if t["id"] == tc_id)
        all_pass = True
        for a in tc_def["assertions"]:
            op, thresh, path = a["op"], a["thresh"], a.get("path")
            ctrl_id = a.get("ctrl")

            if op.startswith("ctrl"):
                ctrl = next((c for c in ev.get("results", []) if c.get("control_id") == ctrl_id), None)
                actual = ctrl.get("status") if ctrl else "NOT FOUND"
                _log(f"→ {ctrl_id} verdict: {actual}")
                passed = (actual == thresh) if op == "ctrl_eq" else (actual in thresh)

            else:
                val_map = {"compliance": comp, "risk": risk, "level": level}
                actual = val_map.get(path)
                try:
                    n = float(actual)
                    if op == "gte":     passed = n >= thresh
                    elif op == "lte":   passed = n <= thresh
                    elif op == "gt":    passed = n > thresh
                    elif op == "lt":    passed = n < thresh
                    elif op == "eq":    passed = str(actual) == str(thresh)
                    elif op == "in":    passed = actual in thresh or str(actual) in thresh
                    elif op == "between": passed = thresh[0] <= n <= thresh[1]
                    else:               passed = False
                except (TypeError, ValueError):
                    passed = (str(actual) == str(thresh)) if op == "eq" else (actual in thresh) if op == "in" else False

                disp = f"{round(n,2)}" if path in ("compliance","risk") else str(actual)
                _log(f"→ {a['label']}: got {disp}", "pass" if passed else "fail")

            if not passed:
                all_pass = False
            assert_results[a["key"]] = {"passed": passed, "actual": actual}

        return all_pass, logs, assert_results

    except Exception as e:
        _log(f"✗ Error: {e}", "fail")
        return False, logs, assert_results


# ── UI helpers ────────────────────────────────────────────────────────────────

def _card(children, extra_style=None):
    s = {
        "background": _C["card"],
        "border": f"1px solid {_C['border']}",
        "borderRadius": "14px",
        "boxShadow": "0 1px 3px rgba(0,0,0,0.06)",
    }
    if extra_style:
        s.update(extra_style)
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


def _badge(text, color, bg, border):
    return html.Span(text, style={
        "background": bg, "color": color, "border": f"1px solid {border}",
        "borderRadius": "999px", "padding": "3px 10px",
        "fontSize": "0.7rem", "fontWeight": "700", "whiteSpace": "nowrap",
    })


def _status_dot(status):
    colors = {
        "pass":    _C["pass"],
        "fail":    _C["fail"],
        "running": _C["partial"],
        "idle":    _C["text_dim"],
    }
    labels = {"pass": "PASSED", "fail": "FAILED", "running": "RUNNING", "idle": "PENDING"}
    c = colors.get(status, _C["text_dim"])
    return html.Span([
        html.Span("●", style={"color": c, "marginRight": "5px", "fontSize": "0.65rem"}),
        html.Span(labels.get(status, "PENDING"), style={"color": c, "fontSize": "0.72rem", "fontWeight": "700"}),
    ])


def _assert_row(label, result=None):
    if result is None:
        icon  = "○"
        color = _C["text_dim"]
        actual_str = ""
    elif result["passed"]:
        icon  = "✓"
        color = _C["pass"]
        actual_str = f"  got: {result['actual']}"
    else:
        icon  = "✗"
        color = _C["fail"]
        actual_str = f"  got: {result['actual']}"

    return html.Div([
        html.Span(icon, style={"color": color, "fontWeight": "700", "marginRight": "8px", "flexShrink": "0"}),
        html.Span(label, style={"flex": "1", "fontSize": "0.82rem", "color": _C["text"]}),
        html.Span(actual_str, style={"fontSize": "0.75rem", "color": _C["text_dim"], "fontFamily": _C["mono"], "marginLeft": "8px"}),
    ], style={"display": "flex", "alignItems": "center", "padding": "5px 0",
              "borderBottom": f"1px solid {_C['border']}"})


def _log_box(tc_id):
    return html.Div(id={"type": "log-box", "tc": tc_id}, style={
        "background": _C["text_bright"],
        "borderRadius": "8px",
        "padding": "10px 12px",
        "fontFamily": _C["mono"],
        "fontSize": "0.78rem",
        "lineHeight": "1.7",
        "maxHeight": "150px",
        "overflowY": "auto",
        "marginTop": "10px",
        "color": "#94a3b8",
    })


def _field_row(tc_id, field):
    return html.Div([
        html.Label(field["label"], style={
            "fontSize": "0.78rem", "color": _C["text_dim"],
            "minWidth": "200px", "flexShrink": "0",
        }),
        dcc.Dropdown(
            id={"type": "field-drop", "tc": tc_id, "key": field["key"]},
            options=[{"label": o, "value": o} for o in field["options"]],
            value=field["default"],
            clearable=False,
            style={"minWidth": "200px", "fontSize": "0.82rem"},
        ),
        html.Span("exploratory", style={
            "fontSize": "0.65rem", "color": _C["partial"],
            "background": _C["partial_bg"],
            "border": f"1px solid {_C['partial_bdr']}",
            "borderRadius": "4px", "padding": "2px 7px",
            "marginLeft": "8px",
        }),
    ], style={"display": "flex", "alignItems": "center", "gap": "10px", "marginBottom": "8px"})


def _build_tc_card(tc):
    tc_id = tc["id"]

    assertions_div = html.Div(
        [_assert_row(a["label"]) for a in tc["assertions"]],
        id={"type": "assert-div", "tc": tc_id},
    )

    fields_section = []
    if tc["fields"]:
        fields_section = [
            _section_label("Payload controls (exploratory)"),
            html.Div([_field_row(tc_id, f) for f in tc["fields"]], style={"marginBottom": "10px"}),
            html.Div([
                html.Span("⚠", style={"marginRight": "6px"}),
                "Changes here are for exploratory testing only — results must NOT be recorded in the official observation table. ",
                html.A("Use interactive runner for full exploratory session.", href="#",
                       style={"color": _C["blue"], "textDecoration": "underline"}),
            ], style={
                "background": _C["warn_bg"], "border": f"1px solid {_C['warn_border']}",
                "color": _C["warn_text"], "borderRadius": "8px",
                "padding": "8px 12px", "fontSize": "0.78rem",
                "marginBottom": "12px", "lineHeight": "1.5",
            }),
        ]

    return _card([
        # Card header
        html.Div([
            html.Div([
                html.Span(tc_id, style={
                    "background": tc["accent_bg"],
                    "color": tc["accent"],
                    "border": f"1px solid {tc['accent_border']}",
                    "borderRadius": "6px",
                    "padding": "3px 10px",
                    "fontSize": "0.78rem",
                    "fontWeight": "700",
                    "marginRight": "12px",
                    "flexShrink": "0",
                }),
                html.Span(tc["title"], style={
                    "fontSize": "0.95rem", "fontWeight": "700",
                    "color": _C["text_bright"], "flex": "1",
                }),
            ], style={"display": "flex", "alignItems": "center", "flex": "1"}),
            html.Div(
                id={"type": "tc-status", "tc": tc_id},
                children=_status_dot("idle"),
            ),
            html.Button([
                html.Span("▶", style={"marginRight": "6px", "fontSize": "0.75rem"}),
                f"Run {tc_id}",
            ], id={"type": "run-btn", "tc": tc_id},
               n_clicks=0,
               style={
                   "background": tc["accent_bg"],
                   "color": tc["accent"],
                   "border": f"1px solid {tc['accent_border']}",
                   "borderRadius": "8px",
                   "padding": "6px 14px",
                   "fontSize": "0.82rem",
                   "fontWeight": "600",
                   "cursor": "pointer",
                   "marginLeft": "12px",
               }),
        ], style={"display": "flex", "alignItems": "center", "justifyContent": "space-between",
                  "padding": "1rem 1.25rem",
                  "borderBottom": f"1px solid {_C['border']}"}),

        # Card body
        html.Div([
            # Description
            html.P(tc["description"], style={
                "fontSize": "0.82rem", "color": _C["text_dim"],
                "lineHeight": "1.6", "marginBottom": "14px",
            }),

            # Fields (exploratory)
            *fields_section,

            # Assertions
            _section_label("Assertions"),
            assertions_div,

            # Log
            _log_box(tc_id),
        ], style={"padding": "1rem 1.25rem"}),

    ], {"marginBottom": "12px"})


# ── Summary KPI row ───────────────────────────────────────────────────────────

def _kpi(value, label, accent):
    return html.Div([
        html.Div(style={"height": "3px", "background": accent,
                        "borderRadius": "14px 14px 0 0", "marginBottom": "0.9rem"}),
        html.Div(str(value), style={
            "fontSize": "1.9rem", "fontWeight": "800",
            "color": accent, "lineHeight": "1",
            "fontVariantNumeric": "tabular-nums", "letterSpacing": "-0.02em",
            "marginBottom": "0.4rem",
        }),
        html.Div(label, style={"fontSize": "0.72rem", "color": _C["text_dim"],
                               "fontWeight": "600", "textTransform": "uppercase",
                               "letterSpacing": "0.08em"}),
    ], style={
        "background": _C["card"],
        "border": f"1px solid {_C['border']}",
        "borderRadius": "14px",
        "padding": "0 1.1rem 1.1rem",
        "textAlign": "center",
        "boxShadow": "0 1px 3px rgba(0,0,0,0.06)",
        "overflow": "hidden",
    })


# ── Page layout ───────────────────────────────────────────────────────────────

layout = html.Div([
    # Page header
    html.Div([
        html.Div([
            html.H1("Unit Testing", style={
                "fontSize": "1.65rem", "fontWeight": "800",
                "color": _C["text_bright"], "letterSpacing": "-0.03em",
                "margin": "0 0 4px 0",
            }),
            html.Div("Scoring model & evaluator logic — TC-A01 to TC-A05", style={
                "fontSize": "0.875rem", "color": _C["text_dim"],
            }),
        ]),
        html.Div([
            html.Button([
                html.Span("▶▶", style={"marginRight": "6px", "fontSize": "0.75rem"}),
                "Run all tests",
            ], id="run-all-btn", n_clicks=0, style={
                "background": _C["blue"], "color": "#fff",
                "border": "none", "borderRadius": "8px",
                "padding": "8px 18px", "fontSize": "0.875rem",
                "fontWeight": "600", "cursor": "pointer",
                "marginRight": "8px",
            }),
            html.Button("↺  Reset all", id="reset-all-btn", n_clicks=0, style={
                "background": _C["card"], "color": _C["text"],
                "border": f"1px solid {_C['border']}",
                "borderRadius": "8px", "padding": "8px 14px",
                "fontSize": "0.875rem", "cursor": "pointer",
            }),
        ], style={"display": "flex", "alignItems": "center"}),
    ], style={"display": "flex", "justifyContent": "space-between",
              "alignItems": "flex-start", "marginBottom": "1.25rem"}),

    # Disclaimer banner
    html.Div([
        html.Span("📋", style={"marginRight": "8px", "fontSize": "1rem"}),
        html.Strong("Evaluator instructions: "),
        "Do not modify payload values during the official test run. Run ",
        html.Code("unit_tests.py", style={"fontFamily": _C["mono"], "fontSize": "0.82rem",
                                           "background": _C["bg"], "padding": "1px 5px",
                                           "borderRadius": "4px"}),
        " first to record official results. Use the dropdowns on TC-A02/A03/A04 only for exploratory testing — label those results separately.",
    ], style={
        "background": _C["blue_light"],
        "border": f"1px solid #bfdbfe",
        "color": "#1e40af",
        "borderRadius": "10px",
        "padding": "10px 16px",
        "fontSize": "0.82rem",
        "lineHeight": "1.6",
        "marginBottom": "1.25rem",
    }),

    # Summary KPIs
    html.Div(id="summary-kpis", children=html.Div([
        _kpi(5,  "Total",   _C["blue"]),
        _kpi(0,  "Passed",  _C["pass"]),
        _kpi(0,  "Failed",  _C["fail"]),
        _kpi(5,  "Pending", _C["text_dim"]),
    ], style={"display": "grid", "gridTemplateColumns": "repeat(4,1fr)", "gap": "1rem"}),
    style={"marginBottom": "1.25rem"}),

    # Hidden stores
    dcc.Store(id="tc-results-store", data={}),
    dcc.Store(id="run-trigger", data=None),

    # Test case cards
    _section_label("Test Cases"),
    html.Div([_build_tc_card(tc) for tc in TEST_CASES], id="tc-cards-container"),

], className="page")


# ── Callbacks ─────────────────────────────────────────────────────────────────

# Run individual test
@callback(
    Output({"type": "tc-status",  "tc": ALL}, "children"),
    Output({"type": "assert-div", "tc": ALL}, "children"),
    Output({"type": "log-box",    "tc": ALL}, "children"),
    Output("tc-results-store", "data"),
    Output("summary-kpis", "children"),
    Input({"type": "run-btn", "tc": ALL}, "n_clicks"),
    Input("run-all-btn",   "n_clicks"),
    Input("reset-all-btn", "n_clicks"),
    State("api-base-store", "data"),
    State("tc-results-store", "data"),
    State({"type": "field-drop", "tc": ALL, "key": ALL}, "value"),
    State({"type": "field-drop", "tc": ALL, "key": ALL}, "id"),
    prevent_initial_call=True,
)
def handle_test_run(run_clicks, run_all, reset_all, base_url, stored_results,
                    field_vals, field_ids):
    triggered = ctx.triggered_id
    base = get_base_url(base_url)

    # Build field value map: {tc_id: {key: value}}
    fv_map = {}
    for val, fid in zip(field_vals or [], field_ids or []):
        tc_id = fid["tc"]
        key   = fid["key"]
        if tc_id not in fv_map:
            fv_map[tc_id] = {}
        fv_map[tc_id][key] = val

    results = dict(stored_results or {})

    # Determine which tests to run
    to_run = []
    if triggered == "reset-all-btn":
        results = {}
        return _build_outputs(results)

    elif triggered == "run-all-btn":
        to_run = [tc["id"] for tc in TEST_CASES]

    elif isinstance(triggered, dict) and triggered.get("type") == "run-btn":
        to_run = [triggered["tc"]]

    for tc_id in to_run:
        try:
            passed, logs, assert_res = run_test(
                tc_id, fv_map.get(tc_id, {}), base
            )
            results[tc_id] = {
                "status": "pass" if passed else "fail",
                "logs": logs,
                "assert_results": assert_res,
            }
        except Exception as e:
            results[tc_id] = {
                "status": "fail",
                "logs": [{"msg": f"✗ Unexpected error: {e}", "kind": "fail"}],
                "assert_results": {},
            }

    return _build_outputs(results)


def _build_outputs(results):
    """Build the output arrays for all 5 test case sections."""
    tc_ids = [tc["id"] for tc in TEST_CASES]

    status_outs  = []
    assert_outs  = []
    log_outs     = []

    n_pass = 0
    n_fail = 0

    for tc in TEST_CASES:
        tc_id = tc["id"]
        res   = results.get(tc_id)

        if res is None:
            status_outs.append(_status_dot("idle"))
            assert_outs.append(html.Div([_assert_row(a["label"]) for a in tc["assertions"]]))
            log_outs.append([])
        else:
            s = res["status"]
            if s == "pass": n_pass += 1
            elif s == "fail": n_fail += 1

            status_outs.append(_status_dot(s))

            ar = res.get("assert_results", {})
            assert_outs.append(html.Div([
                _assert_row(a["label"], ar.get(a["key"]))
                for a in tc["assertions"]
            ]))

            log_children = []
            for entry in res.get("logs", []):
                color_map = {
                    "pass": "#4ade80",
                    "fail": "#f87171",
                    "info": "#94a3b8",
                    "warn": "#fbbf24",
                }
                log_children.append(html.Div(entry["msg"], style={
                    "color": color_map.get(entry["kind"], "#94a3b8"),
                }))
            log_outs.append(log_children)

    n_pend = 5 - n_pass - n_fail
    summary = html.Div([
        _kpi(5,      "Total",   _C["blue"]),
        _kpi(n_pass, "Passed",  _C["pass"]),
        _kpi(n_fail, "Failed",  _C["fail"]),
        _kpi(n_pend, "Pending", _C["text_dim"]),
    ], style={"display": "grid", "gridTemplateColumns": "repeat(4,1fr)", "gap": "1rem"})

    return status_outs, assert_outs, log_outs, results, summary