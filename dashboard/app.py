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
        return ("Unknown", None)

    if s >= 80:
        return ("Good", "🟢")
    if s >= 50:
        return ("Moderate", "🟡")
    return ("High Risk", "🔴")


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
            columns=["control_id", "domain", "status", "severity", "evidence", "recommendation"]
        )

    df = pd.DataFrame(control_results)

    # Ensure core columns exist
    for col in ["control_id", "domain", "status", "severity", "recommendation"]:
        if col not in df.columns:
            df[col] = None

    # Build evidence from available fields in your API/DB
    # Priority: reason -> evidence_value_json -> evidence_path
    reason = df["reason"] if "reason" in df.columns else None
    ev_json = df["evidence_value_json"] if "evidence_value_json" in df.columns else None
    ev_path = df["evidence_path"] if "evidence_path" in df.columns else None

    def build_evidence_row(i: int) -> str:
        r = str(reason.iloc[i]).strip() if reason is not None and pd.notna(reason.iloc[i]) else ""
        v = str(ev_json.iloc[i]).strip() if ev_json is not None and pd.notna(ev_json.iloc[i]) else ""
        p = str(ev_path.iloc[i]).strip() if ev_path is not None and pd.notna(ev_path.iloc[i]) else ""

        if r:
            return r
        if v and p:
            return f"{p} = {v}"
        if v:
            return v
        if p:
            return p
        return ""

    df["evidence"] = [build_evidence_row(i) for i in range(len(df))]

    return df[["control_id", "domain", "status", "severity", "evidence", "recommendation"]]


def get_score_summary(score_obj: dict) -> dict:
    """
    score_obj from API:
    {
      audit_id,
      received_at,
      score: { ... row from audit_scores ... },
      control_results: [...]
    }

    Your audit_scores contains:
      - overall_score
      - overall_level
      - any_high_fail
      - domain_scores_json (JSON string)
    """
    if not score_obj:
        return {}

    score = score_obj.get("score") or {}

    # Overall score: your DB uses overall_score
    overall = score.get("overall_score")
    if overall is None:
        # fallback if name differs
        for k in ["overall", "total_score", "score"]:
            if k in score:
                overall = score.get(k)
                break

    # Domain scores: parse domain_scores_json if present
    domains_raw = {}
    domain_scores_json = score.get("domain_scores_json")

    if domain_scores_json:
        try:
            domains_raw = json.loads(domain_scores_json)
        except Exception:
            domains_raw = {}

    # Convert domain raw object into simple summary dict:
    # {
    #   "Access Control": {"score": 29.41, "level": "...", ...},
    #   ...
    # }
    domain_scores = {}
    for domain_name, info in (domains_raw or {}).items():
        if isinstance(info, dict):
            domain_scores[domain_name] = {
                "score": info.get("score"),
                "level": info.get("level"),
                "earned_points": info.get("earned_points"),
                "max_points": info.get("max_points"),
                "high_fail_count": info.get("high_fail_count"),
            }

    return {
        "overall": overall,
        "domain_scores": domain_scores,   # now contains per-domain scores!
        "raw": score,
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
            df_controls = normalize_control_results(ev.get("control_results", []))

            fail_df = df_controls[df_controls["status"].astype(str).str.upper() == "FAIL"]
            fail_count = int(len(fail_df))

            high_fails = fail_df[fail_df["severity"].astype(str).str.lower() == "high"]
            top_issue = "-"
            if len(high_fails) > 0:
                top_issue = str(high_fails.iloc[0]["control_id"]) + " (High)"
            elif fail_count > 0:
                top_issue = str(fail_df.iloc[0]["control_id"])

            risk_txt, risk_icon = risk_label(score_summary.get("overall"))

            rows.append(
                {
                    "hostname": hostname,
                    "ip_address": h.get("ip_address"),
                    "os_type": h.get("os_type"),
                    "last_seen": fmt_dt(h.get("last_seen")),
                    "audit_id": ev.get("audit_id"),
                    "received_at": fmt_dt(ev.get("received_at")),
                    "overall_score": score_summary.get("overall"),
                    "risk": f"{risk_icon or ''} {risk_txt}".strip(),
                    "fail_count": fail_count,
                    "top_issue": top_issue,
                }
            )

            # Collect risks across hosts
            for _, r in fail_df.iterrows():
                top_risks.append(
                    {
                        "hostname": hostname,
                        "severity": r.get("severity"),
                        "control_id": r.get("control_id"),
                        "domain": r.get("domain"),
                        "evidence": r.get("evidence"),
                        "recommendation": r.get("recommendation"),
                        "sev_rank": severity_rank(str(r.get("severity"))),
                    }
                )

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
    df_controls = normalize_control_results(ev.get("control_results", []))

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
        overall_val = score_summary.get("overall")
        st.metric("Overall score", value=overall_val if overall_val is not None else "-")
        risk_txt, risk_icon = risk_label(overall_val)
        st.info(f"Risk status: {risk_icon or ''} {risk_txt}".strip())

    with c2:
        domain_scores = score_summary.get("domain_scores", {})
        if domain_scores:
            st.subheader("Domain scores")
            rows = []
            for dname, info in domain_scores.items():
                rows.append({
                    "domain": dname,
                    "score": info.get("score"),
                    "level": info.get("level"),
                    "earned_points": info.get("earned_points"),
                    "max_points": info.get("max_points"),
                    "high_fail_count": info.get("high_fail_count"),
                })
            ds_df = pd.DataFrame(rows).sort_values(["score"], ascending=False)
            st.dataframe(ds_df, use_container_width=True, hide_index=True)
        else:
            st.info("No domain scores found.")

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
        score = a.get("score") or {}
        overall = score.get("overall_score") or score.get("overall") or score.get("total_score") or score.get("score")

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
        score = obj.get("score") or {}
        return score.get("overall_score") or score.get("overall") or score.get("total_score") or score.get("score")

    a_score = overall_from(A)
    b_score = overall_from(B)

    st.subheader("Score comparison")
    cA, cB = st.columns(2)
    with cA:
        st.metric("Audit A score", a_score if a_score is not None else "-")
    with cB:
        st.metric("Audit B score", b_score if b_score is not None else "-")

    dfA = normalize_control_results(A.get("control_results", []))
    dfB = normalize_control_results(B.get("control_results", []))

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