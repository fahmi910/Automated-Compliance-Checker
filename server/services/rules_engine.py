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

    if evaluator_name in ("evaluate_ac_lnx_01", "evaluate_ac_lnx_02"):
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

    primary_value_raw = primary_obj.get("value") if exists_primary else None
    primary_value = normalize_str(primary_value_raw)

    if exists_primary and primary_value not in ("", "unknown", "error"):
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
            note=f"Primary runtime evidence unavailable or invalid: {primary_value_raw!r}"
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
# Custom evaluator: AC-LNX-02
# -----------------------------
def evaluate_ac_lnx_02(
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
    firewall_enabled = False

    if exists_fw:
        fw_value = normalize_str(fw_obj.get("value"))
        firewall_disabled = fw_value == "inactive"
        firewall_enabled = fw_value == "active"

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

    # Primary evidence: runtime PasswordAuthentication
    primary_path = "results.access_control.ssh_password_authentication_runtime"
    exists_primary, primary_obj = get_check_object(audit, primary_path)

    primary_value_raw = primary_obj.get("value") if exists_primary else None
    primary_value = normalize_str(primary_value_raw)

    if exists_primary and primary_value not in ("", "unknown", "error"):
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
            result["reason"] = "Primary runtime evidence shows passwordauthentication no."
        elif primary_value == "yes":
            result["status"] = "FAIL"
            result["reason"] = "Primary runtime evidence shows passwordauthentication yes."
        else:
            result["status"] = "UNKNOWN"
            result["reason"] = f"Primary runtime evidence could not be interpreted: {primary_value_raw!r}"

    else:
        # Secondary fallback evidence
        secondary_path = "results.access_control.ssh_password_authentication"
        exists_secondary, secondary_obj = get_check_object(audit, secondary_path)

        result["primary_evidence"] = build_evidence_block(
            collected=False,
            path=primary_path,
            value=None,
            source=None,
            raw_snippet=None,
            note=f"Primary runtime evidence unavailable or invalid: {primary_value_raw!r}",
        )

        if exists_secondary:
            secondary_value_raw = secondary_obj.get("value")
            secondary_value = normalize_str(secondary_value_raw)

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
                result["reason"] = "Secondary config evidence shows PasswordAuthentication no."
            elif secondary_value == "yes":
                result["status"] = "FAIL"
                result["reason"] = "Secondary config evidence shows PasswordAuthentication yes."
            else:
                result["status"] = "UNKNOWN"
                result["reason"] = f"Secondary config evidence could not be interpreted: {secondary_value_raw!r}"

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
            result["reason"] = "Applicable SSH password authentication control could not collect reliable primary or secondary evidence."

    # Exposure likelihood
    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el
    rule_hits: List[str] = []
    rule_misses: List[str] = []

    port_block = result["supporting_validation"].get("port_22_listening", {})
    port_hit = bool(port_block.get("value") is True)

    if port_hit:
        final_el += 1
        rule_hits.append("port_22_listening")
    else:
        rule_misses.append("port_22_listening")

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

    # Mitigation
    mitigation_hits: List[str] = []
    mitigation_percent = 0.0

    if firewall_enabled:
        mitigation_hits.append("firewall_enabled")
        mitigation_percent += 0.10

    if logging_enabled:
        mitigation_hits.append("logging_enabled")
        mitigation_percent += 0.05

    mitigation_percent = min(0.30, mitigation_percent)

    result["risk"]["mitigation"] = {
        "hits": mitigation_hits,
        "percent": mitigation_percent,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)

# -----------------------------
# Custom evaluator: FW-LNX-01
# -----------------------------
def evaluate_fw_lnx_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    result = build_base_result(control, platform)

    # -------------------------
    # Primary evidence
    # -------------------------
    status_path = "results.firewall.ufw_status"
    rules_path = "results.firewall.ufw_rules"

    exists_status, status_obj = get_check_object(audit, status_path)
    exists_rules, rules_obj = get_check_object(audit, rules_path)

    status_value = normalize_str(status_obj.get("value")) if exists_status else None
    rules_value = rules_obj.get("value") if exists_rules else None

    rules_exist = False
    if isinstance(rules_value, dict):
        rules_exist = bool(rules_value.get("rules_exist"))

    # Build primary evidence
    result["primary_evidence"] = build_evidence_block(
        collected=exists_status,
        path=status_path,
        value=status_obj.get("value") if exists_status else None,
        source=status_obj.get("source") if exists_status else None,
        raw_snippet=status_obj.get("evidence") if exists_status else None,
        note=None,
    )

    result["decision_source"] = "primary"

    # -------------------------
    # Decision logic
    # -------------------------
    if not exists_status:
        result["status"] = "UNKNOWN"
        result["reason"] = "Firewall status could not be determined."

    elif status_value != "active":
        result["status"] = "FAIL"
        result["reason"] = f"Firewall is not active (status={status_value})."

    elif not rules_exist:
        result["status"] = "FAIL"
        result["reason"] = "Firewall is active but no rules are configured."

    else:
        result["status"] = "PASS"
        result["reason"] = "Firewall is active with rules configured."

    # -------------------------
    # Supporting validation (logging)
    # -------------------------
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
    # Exposure calculation
    # -------------------------
    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el

    rule_hits = []
    rule_misses = []

    if status_value != "active":
        final_el += 2
        rule_hits.append("firewall_inactive")
    else:
        rule_misses.append("firewall_inactive")

    # optional: reuse port 22 if exists
    exists_port, port_obj = get_check_object(audit, "results.ports.listening_ports")
    port_22_listening = False

    if exists_port:
        raw_ports = str(port_obj.get("evidence", "") or port_obj.get("value", ""))
        port_22_listening = contains_port_22_listening(raw_ports)

    if port_22_listening:
        final_el += 1
        rule_hits.append("port_22_listening")
    else:
        rule_misses.append("port_22_listening")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "network_defense"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    # -------------------------
    # Mitigation
    # -------------------------
    mitigation_hits = []
    mitigation_percent = 0.0

    if logging_enabled:
        mitigation_hits.append("logging_enabled")
        mitigation_percent += 0.05

    mitigation_percent = min(0.30, mitigation_percent)

    result["risk"]["mitigation"] = {
        "hits": mitigation_hits,
        "percent": mitigation_percent,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])

    return finalize_result(result)

# -----------------------------
# Custom evaluator: LOG-LNX-01
# -----------------------------
def evaluate_log_lnx_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    # -------------------------
    # Primary evidence: rsyslog status
    # -------------------------
    status_path = "results.logging.rsyslog_running"
    exists_status, status_obj = get_check_object(audit, status_path)

    rsyslog_running = False
    if exists_status:
        rsyslog_running = bool(status_obj.get("value") is True)

    result["primary_evidence"] = build_evidence_block(
        collected=exists_status,
        path=status_path,
        value=status_obj.get("value") if exists_status else None,
        source=status_obj.get("source") if exists_status else None,
        raw_snippet=status_obj.get("evidence") if exists_status else None,
        note=None,
    )

    result["decision_source"] = "primary"

    # -------------------------
    # Supporting validation: syslog entries
    # -------------------------
    entries_path = "results.logging.syslog_recent_entries"
    exists_entries, entries_obj = get_check_object(audit, entries_path)

    syslog_entries_value = entries_obj.get("value") if exists_entries else None
    syslog_entries_text = normalize_str(syslog_entries_value)

    logs_generated = (
        exists_entries
        and syslog_entries_text not in ("", "none", "n/a", "syslog not found")
    )

    result["supporting_validation"]["syslog_recent_entries"] = build_validation_block(
        collected=exists_entries,
        value=syslog_entries_value,
        status="HIT" if logs_generated else "MISS",
        source=entries_obj.get("source") if exists_entries else None,
        note="Used to confirm logs are actively generated.",
    )

    # -------------------------
    # Decision logic
    # -------------------------
    if not exists_status:
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to determine rsyslog service status."

    elif not rsyslog_running:
        result["status"] = "FAIL"
        result["reason"] = "rsyslog service is not running."

    elif not exists_entries:
        result["status"] = "UNKNOWN"
        result["reason"] = "rsyslog is running but syslog evidence could not be collected."

    elif not logs_generated:
        result["status"] = "FAIL"
        result["reason"] = "rsyslog is running but no recent syslog entries were found."

    else:
        result["status"] = "PASS"
        result["reason"] = "rsyslog is running and recent syslog entries are present."

    # -------------------------
    # Exposure calculation
    # EL = base + remote_access_enabled + firewall_disabled + suspicious_events_present
    # -------------------------
    base_el = int(control.get("exposure_likelihood_base", 2))
    final_el = base_el

    rule_hits: List[str] = []
    rule_misses: List[str] = []

    # remote_access_enabled: infer from port 22 listening
    exists_ports, ports_obj = get_check_object(audit, "results.ports.listening_ports")
    remote_access_enabled = False
    if exists_ports:
        raw_ports = str(ports_obj.get("evidence", "") or ports_obj.get("value", ""))
        remote_access_enabled = contains_port_22_listening(raw_ports)

    if remote_access_enabled:
        final_el += 1
        rule_hits.append("remote_access_enabled")
    else:
        rule_misses.append("remote_access_enabled")

    # firewall_disabled
    exists_fw, fw_obj = get_check_object(audit, "results.firewall.ufw_status")
    firewall_disabled = False
    if exists_fw:
        firewall_disabled = normalize_str(fw_obj.get("value")) == "inactive"

    if firewall_disabled:
        final_el += 1
        rule_hits.append("firewall_disabled")
    else:
        rule_misses.append("firewall_disabled")

    # suspicious_events_present: failed SSH logins
    exists_failed, failed_obj = get_check_object(audit, "results.logging.failed_ssh_logins_snippet")
    suspicious_events_present = False
    if exists_failed:
        failed_value = normalize_str(failed_obj.get("value"))
        suspicious_events_present = failed_value not in ("", "none", "n/a", "no failed ssh logins found")

    if suspicious_events_present:
        final_el += 1
        rule_hits.append("suspicious_events_present")
    else:
        rule_misses.append("suspicious_events_present")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "monitoring_visibility"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    # -------------------------
    # Mitigation
    # For this control, if it passes, the main visibility risk is already reduced through status_factor.
    # Keep mitigation empty unless central logging or alerting is added later.
    # -------------------------
    result["risk"]["mitigation"] = {
        "hits": [],
        "percent": 0.0,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)

# -----------------------------
# Custom evaluator: LOG-LNX-02
# -----------------------------
def evaluate_log_lnx_02(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    result = build_base_result(control, platform)

    # -------------------------
    # Primary evidence
    # -------------------------
    path = "results.logging.auth_log_exists"
    exists, obj = get_check_object(audit, path)

    auth_exists = False
    if exists:
        auth_exists = bool(obj.get("value") is True)

    result["primary_evidence"] = build_evidence_block(
        collected=exists,
        path=path,
        value=obj.get("value") if exists else None,
        source=obj.get("source") if exists else None,
        raw_snippet=obj.get("evidence") if exists else None,
        note=None,
    )

    result["decision_source"] = "primary"

    # -------------------------
    # Supporting validation
    # -------------------------
    exists_failed, failed_obj = get_check_object(audit, "results.logging.failed_ssh_logins_snippet")
    exists_sudo, sudo_obj = get_check_object(audit, "results.logging.sudo_usage_snippet")

    failed_val = normalize_str(failed_obj.get("value")) if exists_failed else None
    sudo_val = normalize_str(sudo_obj.get("value")) if exists_sudo else None

    meaningful_logs = False

    if failed_val and failed_val not in ("none", "n/a", ""):
        meaningful_logs = True

    if sudo_val and sudo_val not in ("none", "n/a", ""):
        meaningful_logs = True

    result["supporting_validation"]["auth_log_activity"] = build_validation_block(
        collected=(exists_failed or exists_sudo),
        value={
            "failed_ssh": failed_obj.get("value") if exists_failed else None,
            "sudo_usage": sudo_obj.get("value") if exists_sudo else None,
        },
        status="HIT" if meaningful_logs else "MISS",
        source="auth.log snippets",
        note="Used to determine if logs contain meaningful activity.",
    )

    # -------------------------
    # Decision logic
    # -------------------------
    if not exists:
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to determine authentication log existence."

    elif not auth_exists:
        result["status"] = "FAIL"
        result["reason"] = "Authentication log file does not exist."

    elif not meaningful_logs:
        result["status"] = "PARTIAL"
        result["reason"] = "Authentication log exists but no meaningful activity detected."

    else:
        result["status"] = "PASS"
        result["reason"] = "Authentication log exists and contains activity."

    # -------------------------
    # Exposure
    # -------------------------
    base_el = int(control.get("exposure_likelihood_base", 2))
    final_el = base_el

    rule_hits = []
    rule_misses = []

    # remote access
    exists_ports, ports_obj = get_check_object(audit, "results.ports.listening_ports")
    remote_access = False

    if exists_ports:
        raw_ports = str(ports_obj.get("evidence", "") or ports_obj.get("value", ""))
        remote_access = contains_port_22_listening(raw_ports)

    if remote_access:
        final_el += 1
        rule_hits.append("remote_access_enabled")
    else:
        rule_misses.append("remote_access_enabled")

    # suspicious activity
    if meaningful_logs:
        final_el += 1
        rule_hits.append("activity_detected")
    else:
        rule_misses.append("activity_detected")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "monitoring_visibility"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    # -------------------------
    # Mitigation
    # -------------------------
    result["risk"]["mitigation"] = {
        "hits": [],
        "percent": 0.0,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])

    return finalize_result(result)

# -------------------------------
# Custom evaluator: CRYPTO-LNX-01
# -------------------------------
def evaluate_crypto_lnx_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    result = build_base_result(control, platform)

    # -------------------------
    # Primary evidence
    # -------------------------
    path = "results.crypto.weak_algorithms_detected"
    exists, obj = get_check_object(audit, path)

    weak_list = obj.get("value") if exists else None

    result["primary_evidence"] = build_evidence_block(
        collected=exists,
        path=path,
        value=weak_list,
        source=obj.get("source") if exists else None,
        raw_snippet=obj.get("evidence") if exists else None,
        note=None,
    )

    result["decision_source"] = "primary"

    # -------------------------
    # Decision logic
    # -------------------------
    if not exists:
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to determine SSH algorithm configuration."

    elif isinstance(weak_list, list) and len(weak_list) == 0:
        result["status"] = "PASS"
        result["reason"] = "No weak SSH algorithms detected."

    elif isinstance(weak_list, list):
        result["status"] = "FAIL"
        result["reason"] = f"Weak SSH algorithms detected: {', '.join(weak_list)}"

    else:
        result["status"] = "UNKNOWN"
        result["reason"] = "Unexpected format in weak algorithm detection."

    # -------------------------
    # Exposure calculation
    # -------------------------
    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el

    rule_hits = []
    rule_misses = []

    # remote access → port 22
    exists_ports, ports_obj = get_check_object(audit, "results.ports.listening_ports")
    remote_access = False

    if exists_ports:
        raw_ports = str(ports_obj.get("evidence", "") or ports_obj.get("value", ""))
        remote_access = contains_port_22_listening(raw_ports)

    if remote_access:
        final_el += 1
        rule_hits.append("remote_access_enabled")
    else:
        rule_misses.append("remote_access_enabled")

    # firewall disabled
    exists_fw, fw_obj = get_check_object(audit, "results.firewall.ufw_status")
    firewall_disabled = False

    if exists_fw:
        firewall_disabled = normalize_str(fw_obj.get("value")) == "inactive"

    if firewall_disabled:
        final_el += 1
        rule_hits.append("firewall_disabled")
    else:
        rule_misses.append("firewall_disabled")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "secure_communication"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    # -------------------------
    # Mitigation
    # -------------------------
    result["risk"]["mitigation"] = {
        "hits": [],
        "percent": 0.0,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])

    return finalize_result(result)

# -------------------------------
# Custom evaluator: EP-W10-01
# -------------------------------
def evaluate_ep_w10_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    path = "results.antivirus.defender_status"
    exists, obj = get_check_object(audit, path)

    defender = obj.get("value") if exists else None

    result["primary_evidence"] = build_evidence_block(
        collected=exists,
        path=path,
        value=defender,
        source=obj.get("source") if exists else None,
        raw_snippet=obj.get("evidence") if exists else None,
        note=None,
    )
    result["decision_source"] = "primary"

    if not exists or not isinstance(defender, dict):
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to retrieve Microsoft Defender status."
    else:
        realtime_enabled = defender.get("RealTimeProtectionEnabled")
        signature_age = defender.get("AntivirusSignatureAge")

        signatures_outdated = False
        try:
            signatures_outdated = int(signature_age) > 7
        except Exception:
            signatures_outdated = False

        result["supporting_validation"]["signature_age"] = build_validation_block(
            collected=signature_age is not None,
            value=signature_age,
            status="HIT" if not signatures_outdated else "MISS",
            source=obj.get("source"),
            note="Used to determine whether antivirus signatures are current.",
        )

        if realtime_enabled is True and not signatures_outdated:
            result["status"] = "PASS"
            result["reason"] = "Microsoft Defender real-time protection is enabled and signatures are current."
        elif realtime_enabled is True and signatures_outdated:
            result["status"] = "PARTIAL"
            result["reason"] = "Real-time protection is enabled but antivirus signatures are outdated."
        elif realtime_enabled is False:
            result["status"] = "FAIL"
            result["reason"] = "Microsoft Defender real-time protection is disabled."
        else:
            result["status"] = "UNKNOWN"
            result["reason"] = f"Unexpected Defender real-time protection value: {realtime_enabled!r}"

    # Exposure
    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el
    rule_hits: List[str] = []
    rule_misses: List[str] = []

    if isinstance(defender, dict):
        realtime_enabled = defender.get("RealTimeProtectionEnabled")
        signature_age = defender.get("AntivirusSignatureAge")

        if realtime_enabled is False:
            final_el += 2
            rule_hits.append("realtime_disabled")
        else:
            rule_misses.append("realtime_disabled")

        try:
            if int(signature_age) > 7:
                final_el += 1
                rule_hits.append("signatures_outdated")
            else:
                rule_misses.append("signatures_outdated")
        except Exception:
            rule_misses.append("signatures_outdated")
    else:
        rule_misses.extend(["realtime_disabled", "signatures_outdated"])

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "endpoint_protection"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    # Mitigation placeholder
    result["risk"]["mitigation"] = {
        "hits": [],
        "percent": 0.0,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)

# -------------------------------
# Custom evaluator: UPD-Windows-01
# -------------------------------
def evaluate_upd_windows_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    service_path = "results.updates.windows_update_service"
    hotfix_path = "results.updates.latest_hotfix"

    exists_service, service_obj = get_check_object(audit, service_path)
    exists_hotfix, hotfix_obj = get_check_object(audit, hotfix_path)

    service_value = service_obj.get("value") if exists_service else None
    hotfix_value = hotfix_obj.get("value") if exists_hotfix else None

    result["primary_evidence"] = build_evidence_block(
        collected=exists_service,
        path=service_path,
        value=service_value,
        source=service_obj.get("source") if exists_service else None,
        raw_snippet=service_obj.get("evidence") if exists_service else None,
        note=None,
    )

    result["supporting_validation"]["latest_hotfix"] = build_validation_block(
        collected=exists_hotfix,
        value=hotfix_value,
        status="HIT" if isinstance(hotfix_value, dict) else "MISS",
        source=hotfix_obj.get("source") if exists_hotfix else None,
        note="Used to verify whether update activity exists.",
    )

    result["decision_source"] = "primary"

    if not exists_service or not isinstance(service_value, dict):
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to retrieve Windows Update service status."
    else:
        status = normalize_str(service_value.get("Status"))
        start_type = normalize_str(service_value.get("StartType"))

        hotfix_present = isinstance(hotfix_value, dict)

        # --- Patch age check ---
        patch_age_days = None
        patch_stale = False
        STALE_THRESHOLD_DAYS = 90

        if hotfix_present:
            installed_on = hotfix_value.get("InstalledOn", {})
            # InstalledOn is a WMI date object: {"value": "/Date(ms)/", "DateTime": "..."}
            ms_str = None
            if isinstance(installed_on, dict):
                ms_str = installed_on.get("value", "")
            elif isinstance(installed_on, str):
                ms_str = installed_on
            if ms_str and "/Date(" in str(ms_str):
                try:
                    import re as _re
                    match = _re.search(r"/Date\((\d+)\)/", str(ms_str))
                    if match:
                        from datetime import datetime, timezone
                        epoch_ms = int(match.group(1))
                        installed_dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
                        now_dt = datetime.now(tz=timezone.utc)
                        patch_age_days = (now_dt - installed_dt).days
                        patch_stale = patch_age_days > STALE_THRESHOLD_DAYS
                except Exception:
                    pass

        # --- Verdict ---
        not_auto = start_type not in ("automatic",)

        if status != "running":
            result["status"] = "FAIL"
            result["reason"] = f"Windows Update service is not running (status={service_value.get('Status')})."
        elif not hotfix_present:
            result["status"] = "PARTIAL"
            result["reason"] = "Windows Update service is running but no patch history found."
        elif patch_stale:
            result["status"] = "PARTIAL"
            result["reason"] = (
                f"Windows Update service is running but latest patch is {patch_age_days} days old "
                f"(KB: {hotfix_value.get('HotFixID', 'unknown')}). "
                f"Patches older than {STALE_THRESHOLD_DAYS} days indicate update automation may be broken."
            )
            if not_auto:
                result["reason"] += f" StartType is '{service_value.get('StartType')}' — set to Automatic."
        elif not_auto:
            result["status"] = "PARTIAL"
            result["reason"] = (
                f"Windows Update service is running but StartType='{service_value.get('StartType')}'. "
                f"Set to Automatic to ensure updates run without manual intervention. "
                f"Latest patch: {hotfix_value.get('HotFixID', 'unknown')} "
                f"({patch_age_days} days ago)."
            )
        else:
            result["status"] = "PASS"
            result["reason"] = (
                f"Windows Update service is running (Automatic). "
                f"Latest patch: {hotfix_value.get('HotFixID', 'unknown')} "
                f"({patch_age_days} days ago)."
            )

        result["supporting_validation"]["startup_type"] = build_validation_block(
            collected=True,
            value=service_value.get("StartType"),
            status="HIT" if not not_auto else "MISS",
            source=service_obj.get("source"),
            note="Used as supporting context for update service configuration.",
        )

        result["supporting_validation"]["patch_age"] = build_validation_block(
            collected=patch_age_days is not None,
            value=f"{patch_age_days} days" if patch_age_days is not None else "unknown",
            status="MISS" if patch_stale else "HIT",
            source="InstalledOn field from Get-HotFix",
            note=f"Patches older than {STALE_THRESHOLD_DAYS} days are flagged as stale.",
        )

    # Exposure
    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el
    rule_hits: List[str] = []
    rule_misses: List[str] = []

    if isinstance(service_value, dict) and normalize_str(service_value.get("Status")) != "running":
        final_el += 1
        rule_hits.append("wuauserv_stopped")
    else:
        rule_misses.append("wuauserv_stopped")

    if not isinstance(hotfix_value, dict):
        final_el += 1
        rule_hits.append("patch_evidence_missing")
    else:
        rule_misses.append("patch_evidence_missing")

    # Stale patch raises exposure — attacker window grows with age
    if patch_stale:
        final_el = min(5, final_el + 1)
        rule_hits.append("patch_stale")
    elif patch_age_days is not None:
        rule_misses.append("patch_stale")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "vulnerability_management"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    result["risk"]["mitigation"] = {
        "hits": [],
        "percent": 0.0,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)

# -------------------------------
# Custom evaluator: FW-Windows-01
# -------------------------------
def evaluate_fw_windows_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    path = "results.firewall.windows_firewall_profiles"
    exists, obj = get_check_object(audit, path)
    profiles = obj.get("value") if exists else None

    result["primary_evidence"] = build_evidence_block(
        collected=exists,
        path=path,
        value=profiles,
        source=obj.get("source") if exists else None,
        raw_snippet=obj.get("evidence") if exists else None,
        note=None,
    )
    result["decision_source"] = "primary"

    if isinstance(profiles, dict):
        profiles = [profiles]

    any_disabled = False
    any_inbound_allow = False
    all_enabled = False
    all_inbound_block = False

    if not exists or not isinstance(profiles, list) or len(profiles) == 0:
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to retrieve Windows Firewall profile information."
    else:
        valid_profiles = [p for p in profiles if isinstance(p, dict)]

        if not valid_profiles:
            result["status"] = "UNKNOWN"
            result["reason"] = "Windows Firewall profile evidence has an unexpected format."
        else:
            any_disabled = any(
                p.get("Enabled") in (False, 0)
                for p in valid_profiles
            )

            any_inbound_allow = any(
                normalize_str(p.get("DefaultInboundAction")) == "allow"
                or p.get("DefaultInboundAction") == 1
                for p in valid_profiles
            )

            all_enabled = all(
                p.get("Enabled") in (True, 1)
                for p in valid_profiles
            )

            all_inbound_block = all(
                normalize_str(p.get("DefaultInboundAction")) == "block"
                or p.get("DefaultInboundAction") == 0
                for p in valid_profiles
            )

            result["supporting_validation"]["firewall_profiles"] = build_validation_block(
                collected=True,
                value={
                    "all_enabled": all_enabled,
                    "all_inbound_block": all_inbound_block,
                    "any_disabled": any_disabled,
                    "any_inbound_allow": any_inbound_allow,
                },
                status="HIT" if all_enabled and all_inbound_block else "MISS",
                source=obj.get("source"),
                note="Used to validate firewall profile enablement and default inbound action.",
            )

            if any_disabled:
                result["status"] = "FAIL"
                result["reason"] = "One or more Windows Firewall profiles are disabled."
            elif any_inbound_allow:
                result["status"] = "PARTIAL"
                result["reason"] = "Windows Firewall profiles are enabled, but one or more default inbound actions are permissive."
            elif all_enabled and all_inbound_block:
                result["status"] = "PASS"
                result["reason"] = "Windows Firewall is enabled and default inbound action is restrictive."
            else:
                result["status"] = "UNKNOWN"
                result["reason"] = "Windows Firewall profile state could not be interpreted."

    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el
    rule_hits: List[str] = []
    rule_misses: List[str] = []

    if any_disabled:
        final_el += 2
        rule_hits.append("any_profile_disabled")
    else:
        rule_misses.append("any_profile_disabled")

    if any_inbound_allow:
        final_el += 1
        rule_hits.append("default_inbound_allow")
    else:
        rule_misses.append("default_inbound_allow")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "network_defense"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    mitigation_hits = []
    mitigation_percent = 0.0

    if all_enabled:
        mitigation_hits.append("profiles_all_enabled")
        mitigation_percent += 0.10

    if all_inbound_block:
        mitigation_hits.append("default_inbound_block")
        mitigation_percent += 0.10

    mitigation_percent = min(0.30, mitigation_percent)

    result["risk"]["mitigation"] = {
        "hits": mitigation_hits,
        "percent": mitigation_percent,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)

# -------------------------------
# Custom evaluator: AC-Windows-01
# -------------------------------
def evaluate_ac_windows_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    path = "results.access_control.password_complexity_policy"
    exists, obj = get_check_object(audit, path)
    policy = obj.get("value") if exists else None

    result["primary_evidence"] = build_evidence_block(
        collected=exists,
        path=path,
        value=policy,
        source=obj.get("source") if exists else None,
        raw_snippet=obj.get("evidence") if exists else None,
        note=None,
    )
    result["decision_source"] = "primary"

    complexity_line = ""
    if isinstance(policy, dict):
        complexity_line = str(policy.get("password_complexity", "") or "")
    elif isinstance(policy, str):
        complexity_line = policy

    complexity_enabled = "PasswordComplexity = 1" in complexity_line
    complexity_disabled = "PasswordComplexity = 0" in complexity_line

    if not exists or policy == "error":
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to retrieve password complexity policy."
    elif complexity_enabled:
        result["status"] = "PASS"
        result["reason"] = "Password complexity policy is enabled."
    elif complexity_disabled:
        result["status"] = "FAIL"
        result["reason"] = "Password complexity policy is disabled."
    else:
        result["status"] = "UNKNOWN"
        result["reason"] = f"Password complexity policy could not be interpreted: {complexity_line!r}"

    # Supporting validation: account policy text
    exists_net, net_obj = get_check_object(audit, "results.access_control.net_accounts_policy")
    if exists_net:
        result["supporting_validation"]["net_accounts_policy"] = build_validation_block(
            collected=True,
            value=net_obj.get("value"),
            status="HIT",
            source=net_obj.get("source"),
            note="Used as supporting account policy context.",
        )

    # Exposure
    base_el = int(control.get("exposure_likelihood_base", 3))
    final_el = base_el
    rule_hits: List[str] = []
    rule_misses: List[str] = []

    # Weak account policy increases exposure
    if result["status"] == "FAIL":
        final_el += 1
        rule_hits.append("password_complexity_disabled")
    else:
        rule_misses.append("password_complexity_disabled")

    # Failed logons present
    exists_failed, failed_obj = get_check_object(audit, "results.logging.failed_logins_4625")
    failed_events = failed_obj.get("value") if exists_failed else None
    failed_logons_present = isinstance(failed_events, list) and len(failed_events) > 0

    if failed_logons_present:
        final_el += 1
        rule_hits.append("failed_logons_present")
    else:
        rule_misses.append("failed_logons_present")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "remote_auth"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    result["risk"]["mitigation"] = {
        "hits": [],
        "percent": 0.0,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)

# -------------------------------
# Custom evaluator: LOG-Windows-01
# -------------------------------
def evaluate_log_windows_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    service_path = "results.logging.eventlog_service"
    event_path = "results.logging.last_security_event"

    exists_service, service_obj = get_check_object(audit, service_path)
    exists_event, event_obj = get_check_object(audit, event_path)

    service = service_obj.get("value") if exists_service else None
    last_event = event_obj.get("value") if exists_event else None

    result["primary_evidence"] = build_evidence_block(
        collected=exists_service,
        path=service_path,
        value=service,
        source=service_obj.get("source") if exists_service else None,
        raw_snippet=service_obj.get("evidence") if exists_service else None,
        note=None,
    )
    result["decision_source"] = "primary"

    security_log_available = isinstance(last_event, dict)

    result["supporting_validation"]["last_security_event"] = build_validation_block(
        collected=exists_event,
        value=last_event,
        status="HIT" if security_log_available else "MISS",
        source=event_obj.get("source") if exists_event else None,
        note="Used to confirm Security log events are readable.",
    )

    if not exists_service or not isinstance(service, dict):
        result["status"] = "UNKNOWN"
        result["reason"] = "Unable to retrieve Windows Event Log service status."
    else:
        status = normalize_str(service.get("Status"))

        if status == "running" and security_log_available:
            result["status"] = "PASS"
            result["reason"] = "Windows Event Log service is running and Security logs are readable."
        elif status == "running" and not security_log_available:
            result["status"] = "FAIL"
            result["reason"] = "Windows Event Log service is running but Security log events could not be read."
        elif status in ("stopped", "stop pending", "paused"):
            result["status"] = "FAIL"
            result["reason"] = f"Windows Event Log service is not running (status={service.get('Status')})."
        else:
            result["status"] = "UNKNOWN"
            result["reason"] = f"Unexpected Event Log service status: {service.get('Status')!r}."

    # Exposure
    base_el = int(control.get("exposure_likelihood_base", 2))
    final_el = base_el
    rule_hits: List[str] = []
    rule_misses: List[str] = []

    if isinstance(service, dict) and normalize_str(service.get("Status")) != "running":
        final_el += 1
        rule_hits.append("logging_service_down")
    else:
        rule_misses.append("logging_service_down")

    exists_failed, failed_obj = get_check_object(audit, "results.logging.failed_logins_4625")
    failed_events = failed_obj.get("value") if exists_failed else None
    suspicious_events_present = isinstance(failed_events, list) and len(failed_events) > 0

    if suspicious_events_present:
        final_el += 1
        rule_hits.append("suspicious_events_present")
    else:
        rule_misses.append("suspicious_events_present")

    final_el = max(1, min(5, final_el))

    result["risk"]["exposure"] = {
        "profile": control.get("exposure_profile", "monitoring_visibility"),
        "base": base_el,
        "rule_hits": rule_hits,
        "rule_misses": rule_misses,
        "final_exposure_likelihood": final_el,
    }

    result["risk"]["mitigation"] = {
        "hits": [],
        "percent": 0.0,
        "cap": 0.30,
    }

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)

# -----------------------------
# Evaluator registry + dispatch
# -----------------------------


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


# =============================================================================
# NEW EVALUATORS — BKP-LNX-01, BKP-WINSVR-01/BKP-W10-01,
#                  AC-LNX-03, AC-LNX-04, AC-WINSVR-02/AC-W10-02,
#                  CRYPTO-WINSVR-01, CRYPTO-W10-01, LOG-LNX-03
# =============================================================================


# -----------------------------------------------------------------------------
# BKP-LNX-01: Backup tool installed and scheduled (Linux)
# PASS   = tool installed AND (cron jobs OR systemd timers found)
# PARTIAL = tool installed but no schedule detected
# FAIL   = no backup tool found
# -----------------------------------------------------------------------------
def evaluate_bkp_lnx_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    # Primary: backup tools installed
    exists_tools, tools_obj = get_check_object(audit, "results.backup.backup_tools_installed")
    # Secondary signals: cron jobs and systemd timers
    exists_cron, cron_obj = get_check_object(audit, "results.backup.backup_cron_jobs")
    exists_timers, timers_obj = get_check_object(audit, "results.backup.backup_systemd_timers")

    if not exists_tools:
        result["status"] = "UNKNOWN"
        result["reason"] = "Backup tools evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.backup.backup_tools_installed",
            value=None, source=None, raw_snippet=None,
            note="evidence path not found in audit payload",
        )
        return finalize_result(result)

    tools_value = tools_obj.get("value")
    tools_found = isinstance(tools_value, list) and len(tools_value) > 0

    cron_hits = cron_obj.get("value", []) if exists_cron else []
    timer_hits = timers_obj.get("value", []) if exists_timers else []
    schedule_found = (
        (isinstance(cron_hits, list) and len(cron_hits) > 0) or
        (isinstance(timer_hits, list) and len(timer_hits) > 0)
    )

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.backup.backup_tools_installed",
        value=tools_value,
        source=tools_obj.get("source"),
        raw_snippet=tools_obj.get("evidence"),
    )
    result["secondary_evidence"] = build_evidence_block(
        collected=exists_cron or exists_timers,
        path="results.backup.backup_cron_jobs / backup_systemd_timers",
        value={"cron_hits": cron_hits, "timer_hits": timer_hits},
        source="crontab + systemctl list-timers",
        raw_snippet=cron_obj.get("evidence", "") if exists_cron else "",
    )
    result["decision_source"] = "primary"

    if tools_found and schedule_found:
        result["status"] = "PASS"
        result["reason"] = (
            f"Backup tool(s) installed: {tools_value}. "
            f"Schedule detected: cron={len(cron_hits)} hit(s), timers={len(timer_hits)} hit(s)."
        )
    elif tools_found and not schedule_found:
        result["status"] = "PARTIAL"
        result["reason"] = (
            f"Backup tool(s) installed ({tools_value}) but no cron job or systemd timer "
            f"for backup was detected. Configure automated backup scheduling."
        )
    else:
        result["status"] = "FAIL"
        result["reason"] = "No backup tool installed and no backup schedule detected."

    # Exposure: check if logging is active (mild mitigation — at least failures are logged)
    exists_log, log_obj = get_check_object(audit, "results.logging.rsyslog_running")
    if exists_log and log_obj.get("value") is True:
        result["risk"]["mitigation"]["hits"].append("rsyslog_running")
        result["risk"]["mitigation"]["percent"] = 0.05

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------------------------------------------------------
# BKP-WINSVR-01 / BKP-W10-01: VSS enabled + shadow copies present (Windows)
# PASS    = VSS Running AND shadow copies exist (or wbadmin available for Server)
# PARTIAL = VSS Running but no shadow copies found
# FAIL    = VSS not running
# -----------------------------------------------------------------------------
def evaluate_bkp_windows_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    exists_vss, vss_obj = get_check_object(audit, "results.backup.vss_service")
    exists_shadows, shadows_obj = get_check_object(audit, "results.backup.shadow_copies")
    exists_wbadmin, wbadmin_obj = get_check_object(audit, "results.backup.wbadmin_status")
    exists_fh, fh_obj = get_check_object(audit, "results.backup.file_history_service")

    if not exists_vss:
        result["status"] = "UNKNOWN"
        result["reason"] = "VSS service evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.backup.vss_service",
            value=None, source=None, raw_snippet=None,
            note="evidence path not found",
        )
        return finalize_result(result)

    vss_value = vss_obj.get("value", {})
    vss_status = ""
    if isinstance(vss_value, dict):
        vss_status = normalize_str(vss_value.get("Status", ""))
    vss_running = vss_status == "running"

    # Shadow copies evidence
    shadows_value = shadows_obj.get("value", {}) if exists_shadows else {}
    shadows_present = False
    if isinstance(shadows_value, list) and len(shadows_value) > 0:
        shadows_present = True
    elif isinstance(shadows_value, dict):
        count = shadows_value.get("count", -1)
        shadows_present = count != 0

    # wbadmin available? (Server only signal)
    wbadmin_available = False
    if exists_wbadmin and isinstance(wbadmin_obj.get("value"), dict):
        wbadmin_available = bool(wbadmin_obj["value"].get("wbadmin_available", False))

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.backup.vss_service",
        value=vss_value,
        source=vss_obj.get("source"),
        raw_snippet=vss_obj.get("evidence"),
    )
    result["secondary_evidence"] = build_evidence_block(
        collected=exists_shadows,
        path="results.backup.shadow_copies",
        value=shadows_value,
        source=shadows_obj.get("source") if exists_shadows else None,
        raw_snippet=shadows_obj.get("evidence") if exists_shadows else None,
    )
    result["decision_source"] = "primary"

    if vss_running and (shadows_present or wbadmin_available):
        result["status"] = "PASS"
        result["reason"] = (
            f"VSS service is running. "
            f"Shadow copies present: {shadows_present}. "
            f"wbadmin available: {wbadmin_available}."
        )
    elif vss_running:
        result["status"] = "PARTIAL"
        result["reason"] = (
            "VSS service is running but no shadow copies found and wbadmin is unavailable. "
            "Configure a backup schedule to produce shadow copies."
        )
    else:
        result["status"] = "FAIL"
        result["reason"] = f"VSS service status: '{vss_status}'. Backup infrastructure is not running."

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------------------------------------------------------
# AC-LNX-03: Inactive local accounts identified (Linux)
# PASS    = no shell accounts have 'never logged in' status
# PARTIAL = some never-logged-in accounts but count is low (1-2)
# FAIL    = 3+ accounts have never logged in with active login shells
# -----------------------------------------------------------------------------
def evaluate_ac_lnx_03(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    exists_nli, nli_obj = get_check_object(audit, "results.access_control.accounts_never_logged_in")
    exists_shell, shell_obj = get_check_object(audit, "results.access_control.shell_accounts_passwd")

    if not exists_nli:
        result["status"] = "UNKNOWN"
        result["reason"] = "lastlog evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.access_control.accounts_never_logged_in",
            value=None, source=None, raw_snippet=None, note="evidence path not found",
        )
        return finalize_result(result)

    never_logged = nli_obj.get("value", [])
    shell_accounts = shell_obj.get("value", []) if exists_shell else []

    # Cross-reference: accounts that never logged in AND have a login shell
    at_risk = [a for a in (never_logged if isinstance(never_logged, list) else [])
               if a in (shell_accounts if isinstance(shell_accounts, list) else [])]

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.access_control.accounts_never_logged_in",
        value=never_logged,
        source=nli_obj.get("source"),
        raw_snippet=nli_obj.get("evidence"),
    )
    result["secondary_evidence"] = build_evidence_block(
        collected=exists_shell,
        path="results.access_control.shell_accounts_passwd",
        value=shell_accounts,
        source=shell_obj.get("source") if exists_shell else None,
        raw_snippet=shell_obj.get("evidence") if exists_shell else None,
    )
    result["decision_source"] = "primary"

    if len(at_risk) == 0:
        result["status"] = "PASS"
        result["reason"] = "No human accounts with login shells have 'never logged in' status."
    elif len(at_risk) <= 2:
        result["status"] = "PARTIAL"
        result["reason"] = (
            f"{len(at_risk)} account(s) with login shells have never logged in: "
            f"{', '.join(at_risk)}. Review and disable if no longer needed."
        )
    else:
        result["status"] = "FAIL"
        result["reason"] = (
            f"{len(at_risk)} accounts with login shells have never logged in: "
            f"{', '.join(at_risk)}. Disable or remove unused accounts."
        )

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------------------------------------------------------
# AC-LNX-04: Account lockout policy configured via PAM (Linux)
# PASS = pam_faillock or pam_tally2 found in PAM + deny threshold set
# FAIL = no lockout mechanism found
# -----------------------------------------------------------------------------
def evaluate_ac_lnx_04(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    exists_pam, pam_obj = get_check_object(audit, "results.access_control.account_lockout_pam")
    exists_deny, deny_obj = get_check_object(audit, "results.access_control.faillock_conf_deny")

    if not exists_pam:
        result["status"] = "UNKNOWN"
        result["reason"] = "PAM lockout configuration evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.access_control.account_lockout_pam",
            value=None, source=None, raw_snippet=None, note="evidence path not found",
        )
        return finalize_result(result)

    pam_mechanism = normalize_str(pam_obj.get("value", "none"))
    deny_value = normalize_str(deny_obj.get("value", "not_set")) if exists_deny else "not_set"

    # Check if a deny threshold is configured
    deny_configured = deny_value not in ("not_set", "unknown", "error", "")

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.access_control.account_lockout_pam",
        value=pam_obj.get("value"),
        source=pam_obj.get("source"),
        raw_snippet=pam_obj.get("evidence"),
    )
    result["secondary_evidence"] = build_evidence_block(
        collected=exists_deny,
        path="results.access_control.faillock_conf_deny",
        value=deny_obj.get("value") if exists_deny else None,
        source=deny_obj.get("source") if exists_deny else None,
        raw_snippet=deny_obj.get("evidence") if exists_deny else None,
    )
    result["decision_source"] = "primary"

    # Exposure: if SSH is active, brute-force risk is higher
    exists_fw, fw_obj = get_check_object(audit, "results.firewall.ufw_status")
    if exists_fw:
        fw_active = normalize_str(fw_obj.get("value")) == "active"
        result["supporting_validation"]["firewall_status"] = build_validation_block(
            collected=True,
            value=fw_obj.get("value"),
            status="MISS" if fw_active else "HIT",
            source=fw_obj.get("source"),
            note="Firewall active reduces brute-force exposure.",
        )
        if fw_active:
            result["risk"]["mitigation"]["hits"].append("ufw_active")
            result["risk"]["mitigation"]["percent"] = 0.10

    if pam_mechanism in ("pam_faillock", "pam_tally2") and deny_configured:
        result["status"] = "PASS"
        result["reason"] = (
            f"Account lockout configured via {pam_mechanism}. "
            f"Deny threshold: {deny_value}."
        )
    elif pam_mechanism in ("pam_faillock", "pam_tally2"):
        result["status"] = "PASS"
        result["reason"] = (
            f"Account lockout module {pam_mechanism} present in PAM. "
            f"Deny threshold not confirmed in faillock.conf — verify configuration."
        )
    else:
        result["status"] = "FAIL"
        result["reason"] = (
            "No account lockout module (pam_faillock or pam_tally2) found in PAM configuration. "
            "Brute-force attacks on local accounts are unrestricted."
        )

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------------------------------------------------------
# AC-WINSVR-02 / AC-W10-02: Guest account disabled (Windows)
# PASS   = Guest account Enabled = False
# FAIL   = Guest account Enabled = True
# UNKNOWN = evidence error or account not found
# -----------------------------------------------------------------------------
def evaluate_ac_guest_windows(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    exists_guest, guest_obj = get_check_object(audit, "results.access_control.guest_account")

    if not exists_guest:
        result["status"] = "UNKNOWN"
        result["reason"] = "Guest account evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.access_control.guest_account",
            value=None, source=None, raw_snippet=None, note="evidence path not found",
        )
        return finalize_result(result)

    guest_value = guest_obj.get("value", {})

    if isinstance(guest_value, dict) and guest_value.get("note"):
        # Account not found on system — treat as PASS (account doesn't exist = not a risk)
        result["status"] = "PASS"
        result["reason"] = f"Guest account not found on this system: {guest_value.get('note')}"
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=True,
            path="results.access_control.guest_account",
            value=guest_value,
            source=guest_obj.get("source"),
            raw_snippet=guest_obj.get("evidence"),
        )
        result["recommendation"] = get_recommendation_for_status(control, "PASS")
        return finalize_result(result)

    if not isinstance(guest_value, dict) or guest_value == "error":
        result["status"] = "UNKNOWN"
        result["reason"] = "Guest account data could not be parsed."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=True,
            path="results.access_control.guest_account",
            value=guest_value,
            source=guest_obj.get("source"),
            raw_snippet=guest_obj.get("evidence"),
        )
        return finalize_result(result)

    guest_enabled = guest_value.get("Enabled")

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.access_control.guest_account",
        value=guest_value,
        source=guest_obj.get("source"),
        raw_snippet=guest_obj.get("evidence"),
    )
    result["decision_source"] = "primary"

    if guest_enabled is False:
        result["status"] = "PASS"
        result["reason"] = "Guest account exists but is disabled (Enabled=False)."
    elif guest_enabled is True:
        result["status"] = "FAIL"
        result["reason"] = "Guest account is enabled. This allows unauthenticated access."
    else:
        result["status"] = "UNKNOWN"
        result["reason"] = f"Guest account Enabled field could not be interpreted: {guest_enabled!r}"

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------------------------------------------------------
# CRYPTO-WINSVR-01: TLS 1.0/1.1 disabled, TLS 1.2/1.3 enforced (Windows Server)
# PASS    = TLS 1.0 disabled AND TLS 1.1 disabled AND TLS 1.2 not disabled
# PARTIAL = TLS 1.2 present but weak versions not explicitly disabled
# FAIL    = TLS 1.0 or 1.1 explicitly enabled
# -----------------------------------------------------------------------------
def evaluate_crypto_winsvr_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    exists_tls, tls_obj = get_check_object(audit, "results.crypto.tls_registry")

    if not exists_tls:
        result["status"] = "UNKNOWN"
        result["reason"] = "TLS registry evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.crypto.tls_registry",
            value=None, source=None, raw_snippet=None, note="evidence path not found",
        )
        return finalize_result(result)

    tls_value = tls_obj.get("value", {})

    if not isinstance(tls_value, dict) or tls_value == "error":
        result["status"] = "UNKNOWN"
        result["reason"] = "TLS registry data could not be parsed."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=True,
            path="results.crypto.tls_registry",
            value=tls_value,
            source=tls_obj.get("source"),
            raw_snippet=tls_obj.get("evidence"),
        )
        return finalize_result(result)

    def _is_disabled(ver_key: str) -> Optional[bool]:
        """None = key not present (no explicit setting). True = disabled. False = explicitly enabled."""
        ver_data = tls_value.get(ver_key, {})
        if not isinstance(ver_data, dict):
            return None
        server_enabled = ver_data.get("server_enabled")
        server_path = ver_data.get("server_path_exists", False)
        if not server_path or server_enabled is None:
            return None  # no explicit registry setting
        # Enabled=0 means disabled, Enabled=1 means enabled
        return server_enabled == 0

    tls10_disabled = _is_disabled("TLS_1.0")
    tls11_disabled = _is_disabled("TLS_1.1")
    tls12_data = tls_value.get("TLS_1.2", {})
    tls12_path_exists = tls12_data.get("server_path_exists", False) if isinstance(tls12_data, dict) else False
    tls12_server_enabled = tls12_data.get("server_enabled") if isinstance(tls12_data, dict) else None
    tls12_explicitly_disabled = (tls12_server_enabled == 0) if tls12_server_enabled is not None else False

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.crypto.tls_registry",
        value=tls_value,
        source=tls_obj.get("source"),
        raw_snippet=tls_obj.get("evidence"),
    )
    result["decision_source"] = "primary"

    # Determine status
    weak_enabled = (tls10_disabled is False) or (tls11_disabled is False)
    weak_disabled = (tls10_disabled is True) and (tls11_disabled is True)
    no_explicit_setting = (tls10_disabled is None) and (tls11_disabled is None)

    if tls12_explicitly_disabled:
        result["status"] = "FAIL"
        result["reason"] = "TLS 1.2 is explicitly disabled in the registry. This breaks secure connections."
    elif weak_enabled:
        result["status"] = "FAIL"
        problems = []
        if tls10_disabled is False:
            problems.append("TLS 1.0 explicitly enabled")
        if tls11_disabled is False:
            problems.append("TLS 1.1 explicitly enabled")
        result["reason"] = f"Weak TLS versions still enabled: {', '.join(problems)}."
    elif weak_disabled:
        result["status"] = "PASS"
        result["reason"] = "TLS 1.0 and 1.1 are explicitly disabled. TLS 1.2 is available."
    elif no_explicit_setting:
        result["status"] = "PARTIAL"
        result["reason"] = (
            "No explicit SCHANNEL registry entries found for TLS versions. "
            "Windows defaults may allow TLS 1.0/1.1. Explicitly disable them in the registry."
        )
    else:
        result["status"] = "PARTIAL"
        result["reason"] = (
            f"TLS 1.0 disabled: {tls10_disabled}, TLS 1.1 disabled: {tls11_disabled}. "
            "Not all weak versions are explicitly disabled."
        )

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------------------------------------------------------
# CRYPTO-W10-01: BitLocker enabled on OS drive (Windows 10)
# PASS    = Protection Status = "Protection On"
# PARTIAL = BitLocker configured but suspended
# FAIL    = Not encrypted / protection off
# -----------------------------------------------------------------------------
def evaluate_crypto_w10_01(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    exists_bl, bl_obj = get_check_object(audit, "results.crypto.bitlocker_status")

    if not exists_bl:
        result["status"] = "UNKNOWN"
        result["reason"] = "BitLocker status evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.crypto.bitlocker_status",
            value=None, source=None, raw_snippet=None, note="evidence path not found",
        )
        return finalize_result(result)

    bl_value = bl_obj.get("value", {})

    if not isinstance(bl_value, dict) or bl_value == "error":
        result["status"] = "UNKNOWN"
        result["reason"] = "BitLocker data could not be parsed or collected."
        result["primary_evidence"] = build_evidence_block(
            collected=True,
            path="results.crypto.bitlocker_status",
            value=bl_value,
            source=bl_obj.get("source"),
            raw_snippet=bl_obj.get("evidence"),
        )
        result["decision_source"] = "primary"
        return finalize_result(result)

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.crypto.bitlocker_status",
        value=bl_value,
        source=bl_obj.get("source"),
        raw_snippet=bl_obj.get("evidence"),
    )
    result["decision_source"] = "primary"

    # Handle both manage-bde and Get-BitLockerVolume output shapes
    source_tool = normalize_str(bl_value.get("source", ""))

    if source_tool == "manage-bde":
        protection_raw = normalize_str(bl_value.get("protection_status", ""))
        if "protection on" in protection_raw:
            result["status"] = "PASS"
            result["reason"] = f"BitLocker protection is ON. {protection_raw}"
        elif "protection off" in protection_raw:
            # Check conversion status — might be encrypting
            conversion_raw = normalize_str(bl_value.get("conversion_status", ""))
            if "encrypting" in conversion_raw or "encryption in progress" in conversion_raw:
                result["status"] = "PARTIAL"
                result["reason"] = "BitLocker encryption is in progress but protection is not yet fully active."
            else:
                result["status"] = "FAIL"
                result["reason"] = f"BitLocker protection is OFF. Drive is not encrypted. {protection_raw}"
        else:
            result["status"] = "UNKNOWN"
            result["reason"] = f"BitLocker protection status could not be interpreted: {protection_raw!r}"

    elif source_tool == "get-bitlockervolume":
        protection_status = normalize_str(bl_value.get("protection_status", ""))
        volume_status = normalize_str(bl_value.get("volume_status", ""))
        if protection_status == "on":
            result["status"] = "PASS"
            result["reason"] = f"BitLocker ProtectionStatus=On. VolumeStatus={volume_status}."
        elif "suspended" in protection_status:
            result["status"] = "PARTIAL"
            result["reason"] = f"BitLocker is suspended (ProtectionStatus={protection_status}). Resume protection."
        elif protection_status == "off":
            result["status"] = "FAIL"
            result["reason"] = "BitLocker ProtectionStatus=Off. Drive encryption is disabled."
        else:
            result["status"] = "UNKNOWN"
            result["reason"] = f"BitLocker ProtectionStatus could not be interpreted: {protection_status!r}"
    else:
        result["status"] = "UNKNOWN"
        result["reason"] = "BitLocker data format not recognised."

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


# -----------------------------------------------------------------------------
# LOG-LNX-03: Log rotation configured (Linux)
# PASS    = logrotate installed + conf files exist + trigger found
# PARTIAL = logrotate installed + conf files exist but no trigger
# FAIL    = logrotate not installed
# -----------------------------------------------------------------------------
def evaluate_log_lnx_03(
    audit: Dict[str, Any],
    control: Dict[str, Any],
    platform: str,
    applicability_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = build_base_result(control, platform)

    exists_inst, inst_obj = get_check_object(audit, "results.logging.logrotate_installed")
    exists_conf, conf_obj = get_check_object(audit, "results.logging.logrotate_d_configs")
    exists_trigger, trigger_obj = get_check_object(audit, "results.logging.logrotate_trigger")

    if not exists_inst:
        result["status"] = "UNKNOWN"
        result["reason"] = "logrotate installation evidence could not be collected."
        result["decision_source"] = "primary"
        result["primary_evidence"] = build_evidence_block(
            collected=False, path="results.logging.logrotate_installed",
            value=None, source=None, raw_snippet=None, note="evidence path not found",
        )
        return finalize_result(result)

    installed = bool(inst_obj.get("value") is True)
    conf_count = int(conf_obj.get("value", 0)) if exists_conf else 0
    trigger_list = trigger_obj.get("value", []) if exists_trigger else []
    trigger_found = isinstance(trigger_list, list) and len(trigger_list) > 0

    result["primary_evidence"] = build_evidence_block(
        collected=True,
        path="results.logging.logrotate_installed",
        value=inst_obj.get("value"),
        source=inst_obj.get("source"),
        raw_snippet=inst_obj.get("evidence"),
    )
    result["secondary_evidence"] = build_evidence_block(
        collected=exists_conf,
        path="results.logging.logrotate_d_configs",
        value=conf_obj.get("value") if exists_conf else None,
        source=conf_obj.get("source") if exists_conf else None,
        raw_snippet=conf_obj.get("evidence") if exists_conf else None,
    )
    result["decision_source"] = "primary"

    result["supporting_validation"]["logrotate_trigger"] = build_validation_block(
        collected=exists_trigger,
        value=trigger_list,
        status="HIT" if trigger_found else "MISS",
        source=trigger_obj.get("source") if exists_trigger else None,
        note="systemd timer or cron.daily trigger for logrotate.",
    )

    if installed and conf_count > 0 and trigger_found:
        result["status"] = "PASS"
        result["reason"] = (
            f"logrotate installed, {conf_count} config file(s) in /etc/logrotate.d. "
            f"Trigger: {'; '.join(trigger_list)}."
        )
    elif installed and conf_count > 0:
        result["status"] = "PARTIAL"
        result["reason"] = (
            f"logrotate installed with {conf_count} config file(s) but no trigger found "
            f"(no systemd timer or /etc/cron.daily/logrotate). Logs may not rotate automatically."
        )
    elif installed:
        result["status"] = "PARTIAL"
        result["reason"] = "logrotate installed but no config files found in /etc/logrotate.d."
    else:
        result["status"] = "FAIL"
        result["reason"] = "logrotate is not installed. Log files will grow without bound."

    result["recommendation"] = get_recommendation_for_status(control, result["status"])
    return finalize_result(result)


CUSTOM_EVALUATORS = {
    # --- existing ---
    "evaluate_ac_lnx_01": evaluate_ac_lnx_01,
    "evaluate_ac_lnx_02": evaluate_ac_lnx_02,
    "evaluate_fw_lnx_01": evaluate_fw_lnx_01,
    "evaluate_log_lnx_01": evaluate_log_lnx_01,
    "evaluate_log_lnx_02": evaluate_log_lnx_02,
    "evaluate_crypto_lnx_01": evaluate_crypto_lnx_01,
    "evaluate_ep_w10_01": evaluate_ep_w10_01,
    "evaluate_upd_windows_01": evaluate_upd_windows_01,
    "evaluate_fw_windows_01": evaluate_fw_windows_01,
    "evaluate_ac_windows_01": evaluate_ac_windows_01,
    "evaluate_log_windows_01": evaluate_log_windows_01,
    # --- new: Backup & Recovery ---
    "evaluate_bkp_lnx_01": evaluate_bkp_lnx_01,
    "evaluate_bkp_windows_01": evaluate_bkp_windows_01,
    # --- new: Access Control ---
    "evaluate_ac_lnx_03": evaluate_ac_lnx_03,
    "evaluate_ac_lnx_04": evaluate_ac_lnx_04,
    "evaluate_ac_guest_windows": evaluate_ac_guest_windows,
    # --- new: Cryptography ---
    "evaluate_crypto_winsvr_01": evaluate_crypto_winsvr_01,
    "evaluate_crypto_w10_01": evaluate_crypto_w10_01,
    # --- new: Logging ---
    "evaluate_log_lnx_03": evaluate_log_lnx_03,
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
    scores = compute_scores(results, severity_weights)

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
        "top_risks": scores.get("top_risks", []),
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