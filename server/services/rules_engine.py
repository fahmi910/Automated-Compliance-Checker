import argparse
import json
from typing import Any, Dict, List, Tuple, Optional

# Keep current scorer for now.
# Note: current scoring.py is still v1-style, so PARTIAL/UNKNOWN
# are only temporary until Step 3 refactor.
from server.services.scoring import compute_scores, SEVERITY_WEIGHTS


# -----------------------------
# Platform detection
# -----------------------------
def detect_platform(os_type: str, os_version: str) -> str:
    os_type = (os_type or "").lower()
    os_version = (os_version or "").lower()

    if "linux" in os_type:
        return "linux"

    if "windows" in os_type:
        if "server" in os_version:
            return "windows_server"
        return "windows10"

    return "unknown"


# -----------------------------
# Generic path helpers
# -----------------------------
def get_by_path(data: Dict[str, Any], path: str) -> Tuple[bool, Any]:
    cur: Any = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def get_check_value(audit: Dict[str, Any], path: str) -> Tuple[bool, Any]:
    return get_by_path(audit, path)


def get_check_object(audit: Dict[str, Any], path: str) -> Tuple[bool, Dict[str, Any]]:
    exists, obj = get_by_path(audit, path)
    if not exists or not isinstance(obj, dict):
        return False, {}
    return True, obj


def normalize_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def contains_port_22_listening(raw_text: str) -> bool:
    text = raw_text or ""
    return ":22" in text and "LISTEN" in text.upper()


# -----------------------------
# Result builders
# -----------------------------
def build_base_result(control: Dict[str, Any], platform: str) -> Dict[str, Any]:
    return {
        "control_id": control.get("control_id"),
        "title": control.get("title"),
        "domain": control.get("domain", "Unknown"),
        "platform": platform,
        "severity": control.get("severity", "low"),

        # final decision
        "status": "UNKNOWN",
        "reason": "",
        "decision_source": None,
        "fallback_note": None,

        # evidence and validation
        "supporting_validation": {},
        "primary_evidence": None,
        "secondary_evidence": None,

        # mappings
        "iso_mapping": control.get("iso_mapping"),
        "pdpa_mapping": control.get("pdpa_mapping"),

        # recommendation
        "recommendation": get_recommendation_for_status(control, "UNKNOWN"),

        # temporary compatibility fields for existing persistence / views
        "evidence_path": control.get("evidence_path", ""),
        "evidence_value": None,

        # compliance block placeholder
        "compliance": {
            "weight": severity_to_weight(control.get("severity", "low")),
            "points_multiplier": 0.0,
            "earned_points": 0.0,
            "max_points": float(severity_to_weight(control.get("severity", "low"))),
        },

        # risk block placeholder
        "risk": {
            "factors": {
                "business_criticality": control.get("business_criticality", 3),
                "security_impact": control.get("security_impact", 3),
                "asset_coverage": control.get("asset_coverage", 3),
                "compliance_importance": control.get("compliance_importance", 3),
            },
            "exposure": {
                "profile": control.get("exposure_profile"),
                "base": control.get("exposure_likelihood_base", 3),
                "rule_hits": [],
                "rule_misses": [],
                "final_exposure_likelihood": control.get("exposure_likelihood_base", 3),
            },
            "mitigation": {
                "hits": [],
                "percent": 0.0,
                "cap": 0.30,
            },
            "calculation": {
                "impact_score": None,
                "inherent_risk_weight": None,
                "status_factor": None,
                "residual_risk_before_mitigation": None,
                "residual_risk_final": None,
            },
        },
    }


def build_evidence_block(
    collected: bool,
    path: Optional[str],
    value: Any,
    source: Optional[str],
    raw_snippet: Any,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "collected": collected,
        "path": path,
        "value": value,
        "source": source,
        "raw_snippet": raw_snippet,
        "note": note,
    }


def build_validation_block(
    collected: bool,
    value: Any,
    status: str,
    source: Optional[str],
    note: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "collected": collected,
        "value": value,
        "status": status,
        "source": source,
        "note": note,
    }


def severity_to_weight(severity: str) -> int:
    sev = normalize_str(severity)
    return SEVERITY_WEIGHTS.get(sev, 1)


def status_to_points_multiplier(status: str) -> float:
    s = normalize_str(status)
    if s == "pass":
        return 1.0
    if s == "partial":
        return 0.5
    return 0.0


def get_recommendation_for_status(control: Dict[str, Any], status: str) -> Any:
    recs = control.get("recommendations")
    if isinstance(recs, dict):
        return recs.get(status.upper()) or recs.get(status.lower()) or recs.get("default")
    return control.get("recommendation")


def finalize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    weight = severity_to_weight(result.get("severity", "low"))
    pm = status_to_points_multiplier(result.get("status", "UNKNOWN"))

    result["compliance"] = {
        "weight": weight,
        "points_multiplier": pm,
        "earned_points": round(weight * pm, 2),
        "max_points": float(weight),
    }

    result["recommendation"] = (
        result.get("recommendation")
        if result.get("recommendation") is not None
        else get_recommendation_for_status(result, result.get("status", "UNKNOWN"))
    )

    # Keep compatibility fields populated for existing repo/db code paths
    primary = result.get("primary_evidence") or {}
    secondary = result.get("secondary_evidence") or {}

    if result.get("decision_source") == "primary":
        result["evidence_value"] = primary.get("value")
        result["evidence_path"] = primary.get("path") or result.get("evidence_path", "")
    elif result.get("decision_source") == "secondary":
        result["evidence_value"] = secondary.get("value")
        result["evidence_path"] = secondary.get("path") or result.get("evidence_path", "")

    return result


# -----------------------------
# Legacy generic rule evaluator
# -----------------------------
def eval_rule(evidence: Any, rule: Dict[str, Any]) -> Tuple[bool, str]:
    rtype = rule.get("type")

    if rtype == "must_equal":
        expected = rule.get("value")
        ok = evidence == expected
        return ok, f"expected {expected!r}, got {evidence!r}"

    if rtype == "must_be_true":
        ok = (evidence is True)
        return ok, f"expected True, got {evidence!r}"

    if rtype == "must_be_empty_list":
        if not isinstance(evidence, list):
            return False, f"expected empty list, got {type(evidence).__name__}"
        ok = len(evidence) == 0
        return ok, f"expected empty list, got length={len(evidence)}"

    if rtype == "all_objects_field_equals":
        field = rule.get("field")
        expected = rule.get("value")

        if not isinstance(evidence, list):
            return False, f"expected list of objects, got {type(evidence).__name__}"
        if len(evidence) == 0:
            return False, "expected non-empty list of objects"

        for obj in evidence:
            if not isinstance(obj, dict):
                return False, "list contains non-object item"
            if field not in obj:
                return False, f"missing field {field!r} in one item"

            actual = obj.get(field)
            if isinstance(actual, bool) and isinstance(expected, int):
                actual_norm = 1 if actual else 0
            else:
                actual_norm = actual

            if actual_norm != expected:
                return (
                    False,
                    f"item {obj.get('Name', 'unknown')} has {field}={actual!r} (expected {expected!r})",
                )

        return True, f"all items have {field}={expected!r}"

    return False, f"unsupported rule type: {rtype}"


# -----------------------------
# Applicability hooks
# -----------------------------
def check_control_applicability(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Returns:
      (is_applicable, applicability_context)

    For now:
    - generic controls are applicable if platform matches
    - custom controls can implement special applicability logic
    """
    if control.get("platform") != platform:
        return False, {"reason": "platform mismatch"}

    evaluator_name = control.get("evaluator")

    if evaluator_name == "evaluate_ac_lnx_01":
        return check_applicability_ac_lnx_01(audit)

    return True, {"reason": "default applicable"}


def check_applicability_ac_lnx_01(audit: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """
    Current raw audit limitations:
    - port 22 listening can be inferred from results.ports.listening_ports
    - explicit ssh service status is not yet collected by the agent

    Current conservative approach:
    - if port 22 is clearly listening => applicable
    - else if SSH config evidence exists => applicable
    - else not applicable

    This should be tightened later when the agent collects:
    - systemctl is-active ssh
    - sshd -T permitrootlogin
    """
    ctx: Dict[str, Any] = {}

    port_path = "results.ports.listening_ports"
    exists_ports, ports_obj = get_check_object(audit, port_path)
    port_listening = False

    if exists_ports:
        raw_ports = str(ports_obj.get("evidence", "") or ports_obj.get("value", ""))
        port_listening = contains_port_22_listening(raw_ports)
        ctx["supporting_validation"] = {
            "port_22_listening": build_validation_block(
                collected=True,
                value=port_listening,
                status="HIT" if port_listening else "MISS",
                source=ports_obj.get("source"),
                note=None,
            )
        }
    else:
        ctx["supporting_validation"] = {
            "port_22_listening": build_validation_block(
                collected=False,
                value=None,
                status="UNKNOWN",
                source=None,
                note="ports evidence missing",
            )
        }

    exists_cfg, cfg_obj = get_check_object(audit, "results.access_control.ssh_permit_root_login")

    if port_listening or exists_cfg:
        ctx["reason"] = "SSH appears present based on listening port or config evidence"
        return True, ctx

    ctx["reason"] = "SSH not evidenced as active/applicable"
    return False, ctx


# -----------------------------
# Generic evaluator
# -----------------------------
def evaluate_control_generic(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    if applicability_context and applicability_context.get("supporting_validation"):
        result["supporting_validation"] = applicability_context["supporting_validation"]

    evidence_path = control.get("evidence_path", "")
    exists, evidence = get_check_value(audit, evidence_path)

    if not exists:
        result["status"] = "UNKNOWN"
        result["reason"] = f"missing evidence at path: {evidence_path}"
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False,
            path=evidence_path,
            value=None,
            source=None,
            raw_snippet=None,
            note="evidence path not found",
        )
        return finalize_result(result)

    ok, reason = eval_rule(evidence, control.get("rule", {}))
    result["status"] = "PASS" if ok else "FAIL"
    result["reason"] = reason
    result["decision_source"] = "primary"
    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path=evidence_path,
        value=evidence,
        source=control.get("source"),
        raw_snippet=evidence,
        note=None,
    )
    result["recommendation"] = get_recommendation_for_status(control, result["status"])

    return finalize_result(result)


# -----------------------------
# Custom evaluator: AC-LNX-01
# -----------------------------
def evaluate_ac_lnx_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    if applicability_context and applicability_context.get("supporting_validation"):
        result["supporting_validation"] = applicability_context["supporting_validation"]

    # Supporting validation: firewall status
    exists_fw, fw_obj = get_check_object(audit, "results.firewall.ufw_status")
    firewall_disabled = False
    if exists_fw:
        fw_value = normalize_str(fw_obj.get("value"))
        firewall_disabled = (fw_value == "inactive")
        result["supporting_validation"]["firewall_status"] = build_validation_block(
            collected=True,
            value=fw_obj.get("value"),
            status="HIT" if firewall_disabled else "MISS",
            source=fw_obj.get("source"),
            note="Used as exposure signal, not direct decision evidence.",
        )

    # Supporting validation: failed SSH logins
    exists_failed, failed_obj = get_check_object(audit, "results.logging.failed_ssh_logins_snippet")
    failed_ssh_logins = False
    if exists_failed:
        failed_value = normalize_str(failed_obj.get("value"))
        failed_ssh_logins = failed_value not in ("", "none", "no failed ssh logins found")
        result["supporting_validation"]["failed_ssh_logins"] = build_validation_block(
            collected=True,
            value=failed_obj.get("value"),
            status="HIT" if failed_ssh_logins else "MISS",
            source=failed_obj.get("source"),
            note="Used as exposure signal, not direct decision evidence.",
        )

    # Supporting validation: logging enabled
    exists_log, log_obj = get_check_object(audit, "results.logging.rsyslog_running")
    logging_enabled = False
    if exists_log:
        logging_enabled = bool(log_obj.get("value") is True)
        result["supporting_validation"]["logging_enabled"] = build_validation_block(
            collected=True,
            value=log_obj.get("value"),
            status="HIT" if logging_enabled else "MISS",
            source=log_obj.get("source"),
            note="Used as mitigation signal.",
        )

    # -------------------------
    # Primary evidence (future-ready)
    # Current agent does not yet collect this.
    # Planned field example:
    # results.access_control.ssh_permit_root_login_runtime
    # -------------------------
    primary_path = "results.access_control.ssh_permit_root_login_runtime"
    exists_primary, primary_obj = get_check_object(audit, primary_path)

    if exists_primary:
        primary_value = normalize_str(primary_obj.get("value"))
        result["primary_evidence"] = build_evidence_block(
            collected=True,
            path=primary_path,
            value=primary_obj.get("value"),
            source=primary_obj.get("source"),
            raw_snippet=primary_obj.get("evidence"),
            note=None,
        )

        result["decision_source"] = "primary"
        if primary_value == "no":
            result["status"] = "PASS"
            result["reason"] = "Primary runtime evidence shows permitrootlogin no."
        elif primary_value == "prohibit-password":
            result["status"] = "PARTIAL"
            result["reason"] = "Primary runtime evidence shows permitrootlogin prohibit-password."
        elif primary_value == "yes":
            result["status"] = "FAIL"
            result["reason"] = "Primary runtime evidence shows permitrootlogin yes."
        else:
            result["status"] = "UNKNOWN"
            result["reason"] = f"Primary runtime evidence could not be interpreted: {primary_obj.get('value')!r}"

    else:
        # -------------------------
        # Secondary fallback evidence
        # This matches current raw audit shape.
        # -------------------------
        secondary_path = "results.access_control.ssh_permit_root_login"
        exists_secondary, secondary_obj = get_check_object(audit, secondary_path)

        result["primary_evidence"] = build_evidence_block(
            collected=False,
            path=primary_path,
            value=None,
            source=None,
            raw_snippet=None,
            note="Primary runtime evidence not yet collected by current agent.",
        )

        if exists_secondary:
            secondary_value = normalize_str(secondary_obj.get("value"))
            result["secondary_evidence"] = build_evidence_block(
                collected=True,
                path=secondary_path,
                value=secondary_obj.get("value"),
                source=secondary_obj.get("source"),
                raw_snippet=secondary_obj.get("evidence"),
                note="Fallback decision evidence used because primary evidence is unavailable.",
            )
            result["decision_source"] = "secondary"
            result["fallback_note"] = "Primary evidence unavailable, secondary evidence used."

            if secondary_value == "no":
                result["status"] = "PASS"
                result["reason"] = "Secondary config evidence shows PermitRootLogin no."
            elif secondary_value == "prohibit-password":
                result["status"] = "PARTIAL"
                result["reason"] = "Secondary config evidence shows PermitRootLogin prohibit-password."
            elif secondary_value == "yes":
                result["status"] = "FAIL"
                result["reason"] = "Secondary config evidence shows PermitRootLogin yes."
            else:
                result["status"] = "UNKNOWN"
                result["reason"] = f"Secondary config evidence could not be interpreted: {secondary_obj.get('value')!r}"
        else:
            result["secondary_evidence"] = build_evidence_block(
                collected=False,
                path=secondary_path,
                value=None,
                source=None,
                raw_snippet=None,
                note="Secondary config evidence missing.",
            )
            result["decision_source"] = "secondary"
            result["fallback_note"] = "Primary evidence unavailable and secondary evidence missing."
            result["status"] = "UNKNOWN"
            result["reason"] = "Applicable SSH control could not collect reliable primary or secondary evidence."

    # -------------------------
    # Risk exposure placeholders
    # -------------------------
    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el
    rule_hits: List[str] = []
    rule_misses: List[str] = []

    # port_22_listening from applicability context if present
    port_block = result["supporting_validation"].get("port_22_listening", {})
    port_hit = bool(port_block.get("value") is True)
    if port_hit:
        final_el += 1
        rule_hits.append("port_22_listening")
    else:
        rule_misses.append("port_22_listening")

    # ssh_active not yet collected
    rule_misses.append("ssh_active")

    if firewall_disabled:
        final_el += 1
        rule_hits.append("firewall_disabled")
    else:
        rule_misses.append("firewall_disabled")

    if failed_ssh_logins:
        final_el += 1
        rule_hits.append("failed_ssh_logins")
    else:
        rule_misses.append("failed_ssh_logins")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "remote_auth"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    # -------------------------
    # Mitigation placeholders
    # -------------------------
    mitigation_hits: List[str] = []
    mitigation_percent = 0.0

    if logging_enabled:
        mitigation_hits.append("logging_enabled")
        mitigation_percent += 0.05

    # future: firewall_enabled, ssh_password_auth_disabled
    mitigation_percent = min(0.30, mitigation_percent)

    result["risk"]["mitigation"] = {
        "hits": mitigation_hits,
        "percent": mitigation_percent,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------
# Evaluator registry + dispatch
# -----------------------------
CUSTOM_EVALUATORS = {
    "evaluate_ac_lnx_01": evaluate_ac_lnx_01,
}


def evaluate_control(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evaluator_name = control.get("evaluator")
    if evaluator_name and evaluator_name in CUSTOM_EVALUATORS:
        return CUSTOM_EVALUATORS[evaluator_name](audit, control, platform, applicability_context)

    return evaluate_control_generic(audit, control, platform, applicability_context)


# -----------------------------
# Compatibility helper for current scoring.py
# -----------------------------
def build_scoring_compat_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Current scoring.py is still v1-oriented.
    Temporary mapping:
      PASS -> PASS
      PARTIAL -> FAIL
      FAIL -> FAIL
      UNKNOWN -> FAIL

    This is only until Step 3 refactors scoring.py properly.
    """
    compat: List[Dict[str, Any]] = []

    for r in results:
        status = str(r.get("status", "UNKNOWN")).upper()
        compat_status = "PASS" if status == "PASS" else "FAIL"

        compat.append({
            "control_id": r.get("control_id"),
            "title": r.get("title"),
            "status": compat_status,
            "severity": r.get("severity", "low"),
            "domain": r.get("domain", "Unknown"),
            "platform": r.get("platform", "unknown"),
            "reason": r.get("reason"),
            "recommendation": r.get("recommendation"),
            "iso_mapping": r.get("iso_mapping"),
            "pdpa_mapping": r.get("pdpa_mapping"),
            "evidence_path": r.get("evidence_path", ""),
            "evidence_value": r.get("evidence_value"),
        })

    return compat


def severity_rank(sev: str) -> int:
    sev = normalize_str(sev)
    return {"high": 3, "medium": 2, "low": 1}.get(sev, 0)


# -----------------------------
# Main orchestrator
# -----------------------------
def evaluate_audit(
    audit: Dict[str, Any],
    controls: List[Dict[str, Any]],
    severity_weights: Dict[str, int],
) -> Dict[str, Any]:
    platform = detect_platform(audit.get("os_type"), audit.get("os_version"))

    platform_controls = [c for c in controls if c.get("platform") == platform]

    results: List[Dict[str, Any]] = []
    excluded_controls = 0

    for control in platform_controls:
        is_applicable, applicability_context = check_control_applicability(audit, control, platform)

        if not is_applicable:
            excluded_controls += 1
            continue

        evaluated = evaluate_control(
            audit=audit,
            control=control,
            platform=platform,
            applicability_context=applicability_context,
        )
        results.append(evaluated)

    # Temporary compatibility scoring until Step 3
    scoring_compat_results = build_scoring_compat_results(results)
    scores = compute_scores(scoring_compat_results, severity_weights)

    # Temporary top risks placeholder using severity/status ordering
    non_pass = [r for r in results if str(r.get("status", "")).upper() != "PASS"]
    top_risks = sorted(
        non_pass,
        key=lambda r: severity_rank(r.get("severity", "low")),
        reverse=True,
    )[:5]

    top_risks_summary = [
        {
            "control_id": r.get("control_id"),
            "title": r.get("title"),
            "domain": r.get("domain"),
            "severity": r.get("severity"),
            "status": r.get("status"),
            "reason": r.get("reason"),
        }
        for r in top_risks
    ]

    return {
        "hostname": audit.get("hostname"),
        "ip_address": audit.get("ip_address"),
        "os_type": audit.get("os_type"),
        "os_version": audit.get("os_version"),
        "timestamp_utc": audit.get("timestamp_utc"),
        "platform": platform,
        "evaluated_controls": len(results),
        "excluded_controls": excluded_controls,
        "scores": scores,  # temporary until Step 3
        "top_risks": top_risks_summary,
        "results": results,
    }


# -----------------------------
# CLI runner
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", required=True, help="Path to audit JSON")
    ap.add_argument("--controls", default="rules/controls.json", help="Path to controls.json")
    ap.add_argument("--out", default="", help="Optional output file path (writes JSON)")
    args = ap.parse_args()

    with open(args.controls, "r", encoding="utf-8") as f:
        controls_doc = json.load(f)
        controls = controls_doc["controls"]
        severity_weights = controls_doc.get("severity_weights", SEVERITY_WEIGHTS)

    with open(args.audit, "r", encoding="utf-8") as f:
        audit = json.load(f)

    out = evaluate_audit(
        audit=audit,
        controls=controls,
        severity_weights=severity_weights,
    )

    output_json = json.dumps(out, indent=2)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"Wrote: {args.out}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()