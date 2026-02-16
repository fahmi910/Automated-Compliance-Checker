from flask import Flask, jsonify, request
from datetime import datetime, timezone
import os
import json

from db import init_db, get_conn
from pathlib import Path
from dotenv import load_dotenv

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
    
    # 1) Parse JSON
    payload = request.get_json(silent=True)
    if payload is None:
        return bad_request("Invalid or missing JSON body")

    # 2) Validate minimum required fields (adjust keys if your agent uses different names)
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

    # 3) Store in DB
    conn = get_conn()
    try:
        cur = conn.cursor()

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
    finally:
        conn.close()



    # 3a) Upsert host
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

    # 3b) Insert audit record (store raw json string)
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
    conn.close()

    return jsonify(status="ok", audit_id=audit_id, received_at=received_at)

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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
