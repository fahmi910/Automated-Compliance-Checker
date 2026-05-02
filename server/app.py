from flask import Flask, jsonify, request
from datetime import datetime, timezone
import os
import json

from server.db import init_db, get_conn
from pathlib import Path
from dotenv import load_dotenv
from server.services.rules_engine import evaluate_audit
from server.services.evaluation_repo import save_evaluation

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


init_db()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB

@app.get("/health")
def health():
    return jsonify(status="ok")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def bad_request(msg: str, details: dict | None = None):
    payload = {"error": msg}
    if details:
        payload["details"] = details
    return jsonify(payload), 400


@app.post("/submit")
def submit():
    expected = os.environ.get("AGENT_API_KEY", "")
    provided = request.headers.get("X-API-Key", "")
    if not expected or provided != expected:
        return jsonify(error="Unauthorized"), 401

    payload = request.get_json(silent=True)
    if payload is None:
        return bad_request("Invalid or missing JSON body")

    required = ["hostname", "ip_address", "os_type", "results"]
    missing = [k for k in required if k not in payload]
    if missing:
        return bad_request("Missing required fields", {"missing": missing})

    hostname = str(payload.get("hostname", "")).strip()
    ip_address = str(payload.get("ip_address", "")).strip()
    os_type = str(payload.get("os_type", "")).strip()
    os_version = str(payload.get("os_version", "unknown")).strip()

    agent_timestamp = payload.get("timestamp") or payload.get("timestamp_utc") or "unknown"
    agent_timestamp = str(agent_timestamp)

    received_at = now_utc_iso()

    conn = get_conn()
    try:
        cur = conn.cursor()

        # Upsert host
        cur.execute("SELECT id FROM hosts WHERE hostname = ?", (hostname,))
        row = cur.fetchone()

        if row is None:
            cur.execute(
                """
                INSERT INTO hosts (hostname, ip_address, os_type, os_version, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (hostname, ip_address, os_type, os_version, received_at, received_at),
            )
            host_id = cur.lastrowid
        else:
            host_id = row["id"]
            cur.execute(
                """
                UPDATE hosts
                SET ip_address = ?, os_type = ?, os_version = ?, last_seen = ?
                WHERE id = ?
                """,
                (ip_address, os_type, os_version, received_at, host_id),
            )

        # Insert audit
        raw_json_str = json.dumps(payload, ensure_ascii=False)
        cur.execute(
            """
            INSERT INTO audits (host_id, agent_timestamp, received_at, raw_json)
            VALUES (?, ?, ?, ?)
            """,
            (host_id, agent_timestamp, received_at, raw_json_str),
        )
        audit_id = cur.lastrowid

        conn.commit()
        # After conn.commit() or before return, evaluate and store
        try:
            with open("rules/controls.json", "r", encoding="utf-8") as f:
                controls_doc = json.load(f)
                controls = controls_doc["controls"]
                severity_weights = controls_doc.get(
                    "severity_weights", {"low": 1, "medium": 2, "high": 3}
                )

            evaluated = evaluate_audit(payload, controls, severity_weights)
            save_evaluation(audit_id, evaluated)

        except Exception as e:
            print(f"[EVAL_ERROR] audit_id={audit_id} error={e}")

        return jsonify(status="ok", audit_id=audit_id, received_at=received_at)

    finally:
        conn.close()

@app.post("/audits/<int:audit_id>/evaluate")
def evaluate_audit_endpoint(audit_id: int):
    # auth optional: reuse same API key or make admin key
    conn = get_conn()
    try:
        cur = conn.cursor()
        row = cur.execute(
            "SELECT id, raw_json FROM audits WHERE id = ?",
            (audit_id,),
        ).fetchone()

        if row is None:
            return jsonify(error="Audit not found", audit_id=audit_id), 404

        audit_json = json.loads(row["raw_json"])
    finally:
        conn.close()

    # load controls
    with open("rules/controls.json", "r", encoding="utf-8") as f:
        controls_doc = json.load(f)
        controls = controls_doc["controls"]
        severity_weights = controls_doc.get("severity_weights", {"low": 1, "medium": 2, "high": 3})

    evaluated = evaluate_audit(audit_json, controls, severity_weights)

    # store into DB
    save_evaluation(audit_id, evaluated)

    return jsonify(status="ok", audit_id=audit_id, platform=evaluated.get("platform"), scores=evaluated.get("scores"))

@app.get("/hosts")
def list_hosts():
    conn = get_conn()
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT id, hostname, ip_address, os_type, os_version, first_seen, last_seen
        FROM hosts
        ORDER BY last_seen DESC
        """
    ).fetchall()
    conn.close()

    hosts = [dict(r) for r in rows]
    return jsonify(hosts=hosts)


@app.get("/audits/latest")
def latest_audit():
    hostname = request.args.get("hostname")
    if not hostname:
        return bad_request("Missing query param: hostname")

    conn = get_conn()
    cur = conn.cursor()

    host = cur.execute("SELECT id, hostname FROM hosts WHERE hostname = ?", (hostname,)).fetchone()
    if host is None:
        conn.close()
        return jsonify(error="Host not found", hostname=hostname), 404

    audit = cur.execute(
        """
        SELECT id, host_id, agent_timestamp, received_at, raw_json
        FROM audits
        WHERE host_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (host["id"],),
    ).fetchone()

    conn.close()

    if audit is None:
        return jsonify(error="No audits for host", hostname=hostname), 404

    # raw_json is stored as text, convert back to JSON object for convenience
    audit_dict = dict(audit)
    audit_dict["raw_json"] = json.loads(audit_dict["raw_json"])
    return jsonify(audit=audit_dict)

@app.get("/audits/latest/evaluated")
def latest_evaluated():
    hostname = request.args.get("hostname")
    if not hostname:
        return bad_request("Missing query param: hostname")

    conn = get_conn()
    try:
        cur = conn.cursor()

        host = cur.execute(
            "SELECT id FROM hosts WHERE hostname = ?",
            (hostname,),
        ).fetchone()

        if host is None:
            return jsonify(error="Host not found", hostname=hostname), 404

        audit = cur.execute(
            """
            SELECT id, received_at, evaluated_json
            FROM audits
            WHERE host_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (host["id"],),
        ).fetchone()

        if audit is None:
            return jsonify(error="No audits for host", hostname=hostname), 404

        if not audit["evaluated_json"]:
            return jsonify(error="Evaluation not available", audit_id=audit["id"]), 500

        evaluated = json.loads(audit["evaluated_json"])
        evaluated["audit_id"] = audit["id"]
        evaluated["received_at"] = audit["received_at"]

        return jsonify(evaluated)

    finally:
        conn.close()

@app.get("/audits")
def list_audits_for_host():
    hostname = request.args.get("hostname")
    limit = int(request.args.get("limit", "20"))

    if not hostname:
        return bad_request("Missing query param: hostname")

    conn = get_conn()
    try:
        cur = conn.cursor()
        host = cur.execute("SELECT id FROM hosts WHERE hostname = ?", (hostname,)).fetchone()
        if host is None:
            return jsonify(error="Host not found", hostname=hostname), 404

        audits = cur.execute(
            """
            SELECT a.id AS audit_id, a.agent_timestamp, a.received_at
            FROM audits a
            WHERE a.host_id = ?
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (host["id"], limit),
        ).fetchall()

        # Attach scores if available
        out = []
        for a in audits:
            score = cur.execute(
                "SELECT * FROM audit_scores WHERE audit_id = ?",
                (a["audit_id"],),
            ).fetchone()
            item = dict(a)
            item["score"] = dict(score) if score else None
            out.append(item)

        return jsonify(hostname=hostname, audits=out)
    finally:
        conn.close()


@app.get("/audits/<int:audit_id>/evaluated")
def evaluated_by_audit_id(audit_id: int):
    conn = get_conn()
    try:
        cur = conn.cursor()

        audit = cur.execute(
            "SELECT id, received_at FROM audits WHERE id = ?",
            (audit_id,),
        ).fetchone()
        if audit is None:
            return jsonify(error="Audit not found", audit_id=audit_id), 404

        score = cur.execute(
            "SELECT * FROM audit_scores WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()

        results = cur.execute(
            "SELECT * FROM control_results WHERE audit_id = ?",
            (audit_id,),
        ).fetchall()

        out = {
            "audit_id": audit_id,
            "received_at": audit["received_at"],
            "score": dict(score) if score else None,
            "control_results": [dict(r) for r in results],
        }
        return jsonify(out)
    finally:
        conn.close()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
