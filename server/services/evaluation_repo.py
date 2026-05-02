import json
from datetime import datetime, timezone
from typing import Any, Dict
from server.db import get_conn


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def save_evaluation(audit_id: int, evaluated: Dict[str, Any]) -> None:
    """
    Save full evaluated output from rules_engine.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        created_at = now_utc_iso()

        # 0) Store full evaluated JSON on the audit row
        cur.execute(
            """
            UPDATE audits
            SET evaluated_json = ?
            WHERE id = ?
            """,
            (to_json(evaluated), audit_id),
        )

        # 1) Save audit_scores using v2 summary
        platform = evaluated.get("platform", "unknown")
        scores = evaluated.get("scores", {})
        summary = scores.get("summary", {})
        domains = scores.get("domains", {})
        top_risks = scores.get("top_risks", [])
        assurance_gaps = scores.get("assurance_gaps", [])

        overall_score = float(summary.get("compliance_score", 0.0))
        overall_level = str(summary.get("risk_level", "Unknown"))

        any_high_fail = any(
            str(r.get("severity", "")).lower() == "high"
            and str(r.get("status", "")).upper() == "FAIL"
            for r in evaluated.get("results", [])
        )

        domain_scores_payload = {
            "summary": summary,
            "domains": domains,
            "risk": scores.get("risk", {}),
            "compliance": scores.get("compliance", {}),
            "top_risks": top_risks,
            "assurance_gaps": assurance_gaps,
        }

        cur.execute(
            """
            INSERT OR REPLACE INTO audit_scores
              (audit_id, platform, overall_score, overall_level, any_high_fail, domain_scores_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                platform,
                overall_score,
                overall_level,
                1 if any_high_fail else 0,
                to_json(domain_scores_payload),
                created_at,
            ),
        )

        # 2) Save control_results
        cur.execute("DELETE FROM control_results WHERE audit_id = ?", (audit_id,))

        for r in evaluated.get("results", []):
            evidence_value_payload = {
                "evidence_value": r.get("evidence_value"),
                "decision_source": r.get("decision_source"),
                "fallback_note": r.get("fallback_note"),
                "supporting_validation": r.get("supporting_validation"),
                "primary_evidence": r.get("primary_evidence"),
                "secondary_evidence": r.get("secondary_evidence"),
                "compliance": r.get("compliance"),
                "risk": r.get("risk"),
            }

            cur.execute(
                """
                INSERT INTO control_results
                  (audit_id, control_id, title, domain, platform, status, severity,
                   evidence_path, evidence_value_json, reason, recommendation, iso_mapping, pdpa_mapping, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    r.get("control_id"),
                    r.get("title"),
                    r.get("domain", "Unknown"),
                    r.get("platform", platform),
                    r.get("status", "FAIL"),
                    r.get("severity", "low"),
                    r.get("evidence_path", ""),
                    to_json(evidence_value_payload),
                    r.get("reason"),
                    to_json(r.get("recommendation")),
                    to_json(r.get("iso_mapping")),
                    to_json(r.get("pdpa_mapping")),
                    created_at,
                ),
            )

        conn.commit()
    finally:
        conn.close()