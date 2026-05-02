import os
import pandas as pd
import streamlit as st
import json
from datetime import datetime

from api_client import (
    health,
    list_hosts,
    latest_evaluated,
    list_audits,
    evaluated_audit,
    get_base_url,
)

st.set_page_config(page_title="Security Audit Dashboard", layout="wide")


def fmt_dt(s: str) -> str:
    if not s:
        return "-"
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(s)


def severity_rank(sev: str) -> int:
    sev = (sev or "").lower()
    if sev == "high":
        return 3
    if sev == "medium":
        return 2
    if sev == "low":
        return 1
    return 0


def risk_label(score_val):
    try:
        s = float(score_val)
    except Exception:
        return ("Unknown", "⚪")

    if s >= 80:
        return ("Severe", "🔴")
    if s >= 60:
        return ("Critical", "🟥")
    if s >= 40:
        return ("High", "🟠")
    if s >= 20:
        return ("Moderate", "🟡")
    return ("Low", "🟢")


def compute_counts(df_controls: pd.DataFrame):
    total = len(df_controls)
    if total == 0:
        return (0, 0, 0, 0)

    status_upper = df_controls["status"].astype(str).str.upper()
    pass_count = int((status_upper == "PASS").sum())
    fail_count = int((status_upper == "FAIL").sum())
    high_fail = int(
        ((status_upper == "FAIL") & (df_controls["severity"].astype(str).str.lower() == "high")).sum()
    )
    return (total, pass_count, fail_count, high_fail)


@st.cache_data(ttl=10)
def cached_hosts():
    return list_hosts()


@st.cache_data(ttl=10)
def cached_latest_eval(hostname: str):
    return latest_evaluated(hostname)


@st.cache_data(ttl=10)
def cached_audits(hostname: str, limit: int):
    return list_audits(hostname, limit=limit)


@st.cache_data(ttl=10)
def cached_evaluated_by_id(audit_id: int):
    return evaluated_audit(audit_id)


def sidebar_server_status():
    st.sidebar.subheader("Server")
    base_url = st.sidebar.text_input("AUDIT_API_BASE_URL", value=get_base_url())
    st.sidebar.caption("Tip: set env var AUDIT_API_BASE_URL to avoid typing each time.")
    os.environ["AUDIT_API_BASE_URL"] = base_url.rstrip("/")

    try:
        h = health()
        st.sidebar.success(f"Connected: {h.get('status', 'ok')}")
    except Exception as e:
        st.sidebar.error(f"Not connected: {e}")


def normalize_control_results(control_results: list) -> pd.DataFrame:
    if not control_results:
        return pd.DataFrame(
            columns=[
                "control_id", "title", "domain", "status", "severity",
                "residual_risk", "evidence", "recommendation"
            ]
        )

    df = pd.DataFrame(control_results)

    for col in ["control_id", "title", "domain", "status", "severity", "recommendation", "reason"]:
        if col not in df.columns:
            df[col] = None

    def get_residual_risk(row):
        try:
            return row.get("risk", {}).get("calculation", {}).get("residual_risk_final", 0.0)
        except Exception:
            return 0.0

    def build_evidence(row):
        reason = row.get("reason")
        decision_source = row.get("decision_source")
        fallback_note = row.get("fallback_note")

        primary = row.get("primary_evidence") or {}
        secondary = row.get("secondary_evidence") or {}

        if decision_source == "primary":
            ev = primary
        elif decision_source == "secondary":
            ev = secondary
        else:
            ev = primary or secondary

        value = ev.get("value")
        source = ev.get("source")
        raw = ev.get("raw_snippet")

        parts = []
        if reason:
            parts.append(str(reason))
        if value is not None:
            parts.append(f"Value: {value}")
        if source:
            parts.append(f"Source: {source}")
        if raw:
            parts.append(f"Evidence: {raw}")
        if fallback_note:
            parts.append(f"Fallback: {fallback_note}")

        return " | ".join(parts)

    df["residual_risk"] = df.apply(get_residual_risk, axis=1)
    df["evidence"] = df.apply(build_evidence, axis=1)

    return df[
        [
            "control_id",
            "title",
            "domain",
            "status",
            "severity",
            "residual_risk",
            "evidence",
            "recommendation",
        ]
    ]

def get_score_summary(ev: dict) -> dict:
    if not ev:
        return {}

    scores = ev.get("scores", {})
    summary = scores.get("summary", {})
    compliance = scores.get("compliance", {})
    risk = scores.get("risk", {})
    domains = scores.get("domains", {})

    return {
        "compliance_score": summary.get("compliance_score"),
        "risk_score": summary.get("risk_score"),
        "risk_level": summary.get("risk_level"),
        "earned_points": compliance.get("earned_points"),
        "max_points": compliance.get("max_points"),
        "domain_scores": domains,
        "top_risks": ev.get("top_risks") or scores.get("top_risks", []),
        "raw": scores,
    }

def page_overview():
    st.title("Overview")

    try:
        hosts_payload = cached_hosts()
        hosts = hosts_payload.get("hosts", [])
    except Exception as e:
        st.error(f"Failed to load hosts: {e}")
        return

    if not hosts:
        st.warning("No hosts found yet. Submit at least one agent audit first.")
        return

    rows = []
    top_risks = []

    for h in hosts:
        hostname = h.get("hostname")
        if not hostname:
            continue

        try:
            ev = cached_latest_eval(hostname)
            score_summary = get_score_summary(ev)
            df_controls = normalize_control_results(ev.get("results", []))

            fail_df = df_controls[df_controls["status"].astype(str).str.upper() == "FAIL"]
            fail_count = int(len(fail_df))

            high_fails = fail_df[fail_df["severity"].astype(str).str.lower() == "high"]
            top_issue = "-"
            if len(high_fails) > 0:
                top_issue = str(high_fails.iloc[0]["control_id"]) + " (High)"
            elif fail_count > 0:
                top_issue = str(fail_df.iloc[0]["control_id"])

            risk_txt, risk_icon = risk_label(score_summary.get("risk_score"))

            rows.append(
                {
                    "hostname": hostname,
                    "ip_address": h.get("ip_address"),
                    "os_type": h.get("os_type"),
                    "last_seen": fmt_dt(h.get("last_seen")),
                    "audit_id": ev.get("audit_id"),
                    "received_at": fmt_dt(ev.get("received_at")),
                    "overall_score": score_summary.get("compliance_score"),
                    "risk": f"{risk_icon or ''} {risk_txt}".strip(),
                    "fail_count": fail_count,
                    "top_issue": top_issue,
                }
            )

            # Collect risks across hosts
            for r in score_summary.get("top_risks", []):
                top_risks.append({
                    "hostname": hostname,
                    "severity": r.get("severity"),
                    "control_id": r.get("control_id"),
                    "domain": r.get("domain"),
                    "evidence": r.get("reason"),
                    "recommendation": r.get("recommendation"),
                    "sev_rank": severity_rank(str(r.get("severity"))),
                })

        except Exception as e:
            rows.append(
                {
                    "hostname": hostname,
                    "ip_address": h.get("ip_address"),
                    "os_type": h.get("os_type"),
                    "last_seen": fmt_dt(h.get("last_seen")),
                    "audit_id": None,
                    "received_at": "-",
                    "overall_score": None,
                    "risk": "Unknown",
                    "fail_count": None,
                    "top_issue": f"Error: {e}",
                }
            )

    df_overview = pd.DataFrame(rows)

    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("Hosts summary (latest evaluated)")
        st.dataframe(df_overview, use_container_width=True, hide_index=True)

    with c2:
        st.subheader("Top risks (all hosts)")
        if top_risks:
            risks_df = (
                pd.DataFrame(top_risks)
                .sort_values(["sev_rank"], ascending=False)
                .drop(columns=["sev_rank"])
            )
            cols = ["hostname", "severity", "control_id", "domain", "evidence", "recommendation"]
            cols = [c for c in cols if c in risks_df.columns]
            st.dataframe(risks_df[cols].head(10), use_container_width=True, hide_index=True)
        else:
            st.info("No FAIL findings found across hosts.")


def page_host_detail():
    st.title("Host details")

    try:
        hosts_payload = cached_hosts()
        hosts = hosts_payload.get("hosts", [])
    except Exception as e:
        st.error(f"Failed to load hosts: {e}")
        return

    if not hosts:
        st.warning("No hosts found yet.")
        return

    hostnames = [h.get("hostname") for h in hosts if h.get("hostname")]
    selected = st.selectbox("Select host", hostnames)

    try:
        ev = cached_latest_eval(selected)
    except Exception as e:
        st.error(f"Failed to load latest evaluated audit for {selected}: {e}")
        return

    score_summary = get_score_summary(ev)
    df_controls = normalize_control_results(ev.get("results", []))

    st.caption(f"Audit ID: {ev.get('audit_id')}  |  Received at: {fmt_dt(ev.get('received_at'))}")

    # Summary metrics
    total, pass_count, fail_count, high_fail = compute_counts(df_controls)
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total controls", total)
    with m2:
        st.metric("PASS", pass_count)
    with m3:
        st.metric("FAIL", fail_count)
    with m4:
        st.metric("High FAIL", high_fail)

    # Score area
    c1, c2 = st.columns([1, 2])
    with c1:
        compliance_score = score_summary.get("compliance_score")
        risk_score = score_summary.get("risk_score")
        risk_level = score_summary.get("risk_level")

        st.metric("Compliance Score", f"{compliance_score}%" if compliance_score is not None else "-")
        st.metric("Risk Score", f"{risk_score:.2f}" if risk_score is not None else "-")

        risk_txt, risk_icon = risk_label(risk_score)
        st.info(f"Risk Level: {risk_icon} {risk_level or risk_txt}")

    with c2:
        domain_scores = score_summary.get("domain_scores", {})
        if domain_scores:
            st.subheader("Domain scores")
            rows = []
            for dname, info in domain_scores.items():
                rows.append({
                    "domain": dname,
                    "compliance_score": info.get("compliance_score"),
                    "risk_score": info.get("risk_score"),
                    "risk_level": info.get("risk_level"),
                    "earned_points": info.get("compliance_earned_points"),
                    "max_points": info.get("compliance_max_points"),
                    "high_fail_count": info.get("high_fail_count"),
                    "unknown_count": info.get("unknown_count"),
                    "domain_escalated": info.get("domain_escalated"),
                })
            ds_df = pd.DataFrame(rows).sort_values(["risk_score"], ascending=False)
            st.dataframe(ds_df, use_container_width=True, hide_index=True)
            chart_df = ds_df[["domain", "risk_score"]].set_index("domain")
            st.bar_chart(chart_df, use_container_width=True)
        else:
            st.info("No domain scores found.")

    # ---------- TOP RISKS ----------
    st.subheader("Top Risks")

    top_risks = sorted(
        score_summary.get("top_risks", []),
        key=lambda x: x.get("residual_risk", 0),
        reverse=True
    )

    if top_risks:
        for r in top_risks[:5]:
            msg = (
                f"[{str(r.get('severity', '')).upper()}] {r.get('title')}\n"
                f"Domain: {r.get('domain')} | Residual Risk: {r.get('residual_risk')}\n\n"
                f"{r.get('reason')}\n\n"
                f"Recommendation: {r.get('recommendation')}"
            )

            sev = str(r.get("severity", "")).lower()

            if sev == "high":
                st.error(msg)
            elif sev == "medium":
                st.warning(msg)
            else:
                st.info(msg)
    else:
        st.info("No major risks detected.")

    # ---------- CONTROL TABLE ----------
    # Filters
    st.subheader("Control results")
    left, mid, right = st.columns([1, 1, 1])

    with left:
        fail_only = st.checkbox("Show FAIL only", value=True)
    with mid:
        domains = sorted([d for d in df_controls["domain"].dropna().unique().tolist()])
        domain_choice = st.selectbox("Domain", ["All"] + domains)
    with right:
        severities = ["All", "high", "medium", "low"]
        sev_choice = st.selectbox("Severity", severities)

    filtered = df_controls.copy()

    if fail_only:
        filtered = filtered[filtered["status"].astype(str).str.upper() == "FAIL"]

    if domain_choice != "All":
        filtered = filtered[filtered["domain"].astype(str) == domain_choice]

    if sev_choice != "All":
        filtered = filtered[filtered["severity"].astype(str).str.lower() == sev_choice]

    if len(filtered) > 0:
        filtered = filtered.assign(sev_rank=filtered["severity"].apply(lambda x: severity_rank(str(x))))
        filtered = filtered.sort_values(["sev_rank", "control_id"], ascending=[False, True]).drop(columns=["sev_rank"])

    st.dataframe(filtered, use_container_width=True, hide_index=True)


def page_history():
    st.title("History")

    try:
        hosts_payload = cached_hosts()
        hosts = hosts_payload.get("hosts", [])
    except Exception as e:
        st.error(f"Failed to load hosts: {e}")
        return

    hostnames = [h.get("hostname") for h in hosts if h.get("hostname")]
    if not hostnames:
        st.warning("No hosts found.")
        return

    selected = st.selectbox("Select host", hostnames)
    limit = st.slider("Number of audits", 5, 50, 20)

    try:
        payload = cached_audits(selected, limit)
        audits = payload.get("audits", [])
    except Exception as e:
        st.error(f"Failed to load audit history: {e}")
        return

    if not audits:
        st.info("No audits available.")
        return

    rows = []
    for a in audits:
        ev = cached_evaluated_by_id(a.get("audit_id"))
        score_summary = get_score_summary(ev)
        overall = score_summary.get("compliance_score")

        rows.append(
            {
                "audit_id": a.get("audit_id"),
                "received_at": fmt_dt(a.get("received_at")),
                "agent_timestamp": a.get("agent_timestamp"),
                "overall_score": overall,
            }
        )

    df = pd.DataFrame(rows)

    st.subheader("Audit list")
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Trend chart
    try:
        df2 = df.copy()
        df2["overall_score"] = pd.to_numeric(df2["overall_score"], errors="coerce")
        df2 = df2.dropna(subset=["overall_score"])
        if len(df2) >= 2:
            st.subheader("Overall score trend")
            st.line_chart(df2.set_index("received_at")["overall_score"])
        else:
            st.info("Not enough numeric score values to plot trend.")
    except Exception:
        st.info("Trend chart unavailable for current score format.")


def page_compare():
    st.title("Compare audits")

    try:
        hosts_payload = cached_hosts()
        hosts = hosts_payload.get("hosts", [])
    except Exception as e:
        st.error(f"Failed to load hosts: {e}")
        return

    hostnames = [h.get("hostname") for h in hosts if h.get("hostname")]
    if not hostnames:
        st.warning("No hosts found.")
        return

    selected = st.selectbox("Select host", hostnames)

    try:
        payload = cached_audits(selected, 30)
        audits = payload.get("audits", [])
    except Exception as e:
        st.error(f"Failed to load audits: {e}")
        return

    if len(audits) < 2:
        st.info("Need at least 2 audits to compare.")
        return

    audit_ids = [a.get("audit_id") for a in audits if a.get("audit_id") is not None]
    audit_ids = [int(x) for x in audit_ids]

    c1, c2 = st.columns(2)
    with c1:
        a_id = st.selectbox("Audit A (older)", sorted(audit_ids), index=0)
    with c2:
        b_id = st.selectbox("Audit B (newer)", sorted(audit_ids), index=len(audit_ids) - 1)

    if a_id == b_id:
        st.warning("Pick two different audits.")
        return

    try:
        A = cached_evaluated_by_id(a_id)
        B = cached_evaluated_by_id(b_id)
    except Exception as e:
        st.error(f"Failed to load evaluated audits: {e}")
        return

    def overall_from(obj):
        summary = get_score_summary(obj)
        return summary.get("compliance_score")

    a_score = overall_from(A)
    b_score = overall_from(B)

    st.subheader("Score comparison")
    cA, cB = st.columns(2)
    with cA:
        st.metric("Audit A score", a_score if a_score is not None else "-")
    with cB:
        st.metric("Audit B score", b_score if b_score is not None else "-")

    dfA = normalize_control_results(A.get("results", []))
    dfB = normalize_control_results(B.get("results", []))

    mapA = {r["control_id"]: r for _, r in dfA.iterrows()}
    mapB = {r["control_id"]: r for _, r in dfB.iterrows()}

    changed = []
    all_ids = sorted(set(mapA.keys()) | set(mapB.keys()))
    for cid in all_ids:
        sA = str(mapA.get(cid, {}).get("status", "")).upper()
        sB = str(mapB.get(cid, {}).get("status", "")).upper()
        if sA != sB:
            changed.append(
                {
                    "control_id": cid,
                    "from": sA or "-",
                    "to": sB or "-",
                    "domain": mapB.get(cid, {}).get("domain") or mapA.get(cid, {}).get("domain"),
                    "severity": mapB.get(cid, {}).get("severity") or mapA.get(cid, {}).get("severity"),
                    "evidence_B": mapB.get(cid, {}).get("evidence"),
                    "recommendation": mapB.get(cid, {}).get("recommendation")
                    or mapA.get(cid, {}).get("recommendation"),
                }
            )

    st.subheader("Changed controls")
    if changed:
        st.dataframe(pd.DataFrame(changed), use_container_width=True, hide_index=True)
    else:
        st.info("No control status changes between these two audits.")


def page_about():
    st.title("About")
    st.write(
        """
This dashboard displays evaluated audit results from your Flask audit server.

Endpoints used:
- GET /hosts
- GET /audits/latest/evaluated?hostname=...
- GET /audits?hostname=...&limit=...
- GET /audits/<audit_id>/evaluated

Features:
- Overview summary across hosts
- Host drill-down with filters and evidence
- History trend
- Compare audits

Next upgrades:
- Export PDF/CSV reports (Week 8)
"""
    )


def main():
    sidebar_server_status()

    st.sidebar.subheader("Navigation")
    page = st.sidebar.radio("Go to", ["Overview", "Host details", "History", "Compare", "About"])

    if page == "Overview":
        page_overview()
    elif page == "Host details":
        page_host_detail()
    elif page == "History":
        page_history()
    elif page == "Compare":
        page_compare()
    else:
        page_about()


if __name__ == "__main__":
    main()