from __future__ import annotations
from typing import Any, Dict, List


SEVERITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3}

STATUS_POINT_MULTIPLIER = {
    "PASS": 1.0,
    "PARTIAL": 0.5,
    "FAIL": 0.0,
    "UNKNOWN": 0.0,
}

STATUS_RISK_FACTOR = {
    "PASS": 0.0,
    "PARTIAL": 0.5,
    "FAIL": 1.0,
    "UNKNOWN": 0.7,
}

RISK_LEVELS = [
    ("Low", 0, 19),
    ("Moderate", 20, 39),
    ("High", 40, 59),
    ("Critical", 60, 79),
    ("Severe", 80, 100),
]

RISK_LEVEL_ORDER = ["Low", "Moderate", "High", "Critical", "Severe"]


def normalize_status(status: Any) -> str:
    return str(status or "UNKNOWN").strip().upper()


def normalize_severity(severity: Any) -> str:
    return str(severity or "low").strip().lower()


def risk_score_to_level(score: float) -> str:
    s = round(score, 2)
    for name, lo, hi in RISK_LEVELS:
        if lo <= s <= hi:
            return name
    if s < 0:
        return "Low"
    return "Severe"


def escalate_risk_level(level: str, steps: int = 1) -> str:
    if level not in RISK_LEVEL_ORDER:
        return level
    idx = RISK_LEVEL_ORDER.index(level)
    idx = min(len(RISK_LEVEL_ORDER) - 1, idx + steps)
    return RISK_LEVEL_ORDER[idx]


def get_nested(result: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    cur: Any = result
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return default
    return cur if cur is not None else default


def calculate_impact_score(si: float, bc: float, ac: float, ci: float) -> float:
    return (0.35 * si) + (0.20 * bc) + (0.20 * ac) + (0.25 * ci)


def calculate_control_scores(result: Dict[str, Any], severity_weights: Dict[str, int]) -> Dict[str, Any]:
    status = normalize_status(result.get("status"))
    severity = normalize_severity(result.get("severity"))

    weight = severity_weights.get(severity, 1)
    point_multiplier = STATUS_POINT_MULTIPLIER.get(status, 0.0)
    earned_points = weight * point_multiplier
    max_points = weight

    factors = get_nested(result, ["risk", "factors"], {}) or {}
    bc = float(factors.get("business_criticality", 3))
    si = float(factors.get("security_impact", 3))
    ac = float(factors.get("asset_coverage", 3))
    ci = float(factors.get("compliance_importance", 3))

    exposure_likelihood = float(
        get_nested(result, ["risk", "exposure", "final_exposure_likelihood"], 3)
    )

    impact_score = calculate_impact_score(si=si, bc=bc, ac=ac, ci=ci)
    inherent_risk_weight = impact_score * exposure_likelihood

    status_factor = STATUS_RISK_FACTOR.get(status, 0.7)

    mitigation_percent = float(
        get_nested(result, ["risk", "mitigation", "percent"], 0.0)
    )
    mitigation_percent = max(0.0, min(0.30, mitigation_percent))

    residual_before_mitigation = inherent_risk_weight * status_factor
    residual_final = residual_before_mitigation * (1 - mitigation_percent)

    result["compliance"] = {
        "weight": weight,
        "points_multiplier": point_multiplier,
        "earned_points": round(earned_points, 2),
        "max_points": round(max_points, 2),
    }

    if "risk" not in result or not isinstance(result["risk"], dict):
        result["risk"] = {}

    result["risk"]["calculation"] = {
        "impact_score": round(impact_score, 2),
        "inherent_risk_weight": round(inherent_risk_weight, 2),
        "status_factor": status_factor,
        "residual_risk_before_mitigation": round(residual_before_mitigation, 2),
        "residual_risk_final": round(residual_final, 2),
    }

    return result


def compute_scores(
    evaluated_results: List[Dict[str, Any]],
    severity_weights: Dict[str, int] | None = None,
    apply_domain_escalation: bool = True,
    unknown_warning_threshold: int = 2,
) -> Dict[str, Any]:
    weights = severity_weights or SEVERITY_WEIGHTS

    scored_results = [
        calculate_control_scores(r, weights)
        for r in evaluated_results
    ]

    total_earned = 0.0
    total_max = 0.0

    total_residual_risk = 0.0
    total_inherent_risk = 0.0

    domains: Dict[str, Dict[str, Any]] = {}

    for r in scored_results:
        domain = r.get("domain", "Unknown")
        status = normalize_status(r.get("status"))
        severity = normalize_severity(r.get("severity"))

        comp = r.get("compliance", {})
        risk_calc = get_nested(r, ["risk", "calculation"], {}) or {}

        earned = float(comp.get("earned_points", 0.0))
        maxp = float(comp.get("max_points", 0.0))
        residual = float(risk_calc.get("residual_risk_final", 0.0))
        inherent = float(risk_calc.get("inherent_risk_weight", 0.0))

        total_earned += earned
        total_max += maxp
        total_residual_risk += residual
        total_inherent_risk += inherent

        if domain not in domains:
            domains[domain] = {
                "compliance_earned_points": 0.0,
                "compliance_max_points": 0.0,
                "residual_risk": 0.0,
                "inherent_risk": 0.0,
                "high_fail_count": 0,
                "unknown_count": 0,
                "control_count": 0,
            }

        d = domains[domain]
        d["compliance_earned_points"] += earned
        d["compliance_max_points"] += maxp
        d["residual_risk"] += residual
        d["inherent_risk"] += inherent
        d["control_count"] += 1

        if severity == "high" and status == "FAIL":
            d["high_fail_count"] += 1

        if status == "UNKNOWN":
            d["unknown_count"] += 1

    overall_compliance_score = (total_earned / total_max * 100) if total_max else 0.0
    overall_risk_score = (
        total_residual_risk / total_inherent_risk * 100
    ) if total_inherent_risk else 0.0

    domain_out: Dict[str, Any] = {}
    assurance_gaps: List[Dict[str, Any]] = []

    for domain, d in domains.items():
        compliance_score = (
            d["compliance_earned_points"] / d["compliance_max_points"] * 100
        ) if d["compliance_max_points"] else 0.0

        risk_score = (
            d["residual_risk"] / d["inherent_risk"] * 100
        ) if d["inherent_risk"] else 0.0

        risk_level = risk_score_to_level(risk_score)

        escalated = False
        if apply_domain_escalation and d["high_fail_count"] >= 2:
            risk_level = escalate_risk_level(risk_level, steps=1)
            escalated = True

        if d["unknown_count"] >= unknown_warning_threshold:
            assurance_gaps.append({
                "domain": domain,
                "unknown_count": d["unknown_count"],
                "message": "Insufficient evidence warning: multiple controls are UNKNOWN in this domain.",
            })

        domain_out[domain] = {
            "compliance_score": round(compliance_score, 2),
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "compliance_earned_points": round(d["compliance_earned_points"], 2),
            "compliance_max_points": round(d["compliance_max_points"], 2),
            "residual_risk": round(d["residual_risk"], 2),
            "inherent_risk": round(d["inherent_risk"], 2),
            "control_count": d["control_count"],
            "high_fail_count": d["high_fail_count"],
            "unknown_count": d["unknown_count"],
            "domain_escalated": escalated,
        }

    top_risks = sorted(
        scored_results,
        key=lambda r: float(get_nested(r, ["risk", "calculation", "residual_risk_final"], 0.0)),
        reverse=True,
    )[:5]

    top_risks_out = [
        {
            "control_id": r.get("control_id"),
            "title": r.get("title"),
            "domain": r.get("domain"),
            "severity": r.get("severity"),
            "status": r.get("status"),
            "residual_risk": get_nested(r, ["risk", "calculation", "residual_risk_final"], 0.0),
            "recommendation": r.get("recommendation"),
            "reason": r.get("reason"),
        }
        for r in top_risks
        if normalize_status(r.get("status")) != "PASS"
    ]

    return {
        "summary": {
            "compliance_score": round(overall_compliance_score, 2),
            "risk_score": round(overall_risk_score, 2),
            "risk_level": risk_score_to_level(overall_risk_score),
        },
        "compliance": {
            "earned_points": round(total_earned, 2),
            "max_points": round(total_max, 2),
            "score": round(overall_compliance_score, 2),
        },
        "risk": {
            "residual_risk": round(total_residual_risk, 2),
            "inherent_risk": round(total_inherent_risk, 2),
            "score": round(overall_risk_score, 2),
            "level": risk_score_to_level(overall_risk_score),
        },
        "domains": domain_out,
        "top_risks": top_risks_out,
        "assurance_gaps": assurance_gaps,
    }


def severity_rank(sev: str) -> int:
    sev = normalize_severity(sev)
    return {"high": 3, "medium": 2, "low": 1}.get(sev, 0)