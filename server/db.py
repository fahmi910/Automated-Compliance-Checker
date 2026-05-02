import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "audit.db"


def get_conn() -> sqlite3.Connection:
    """
    Always returns a NEW sqlite connection.
    Never cache/store connections globally.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initializes the database schema using a short-lived connection.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE NOT NULL,
                ip_address TEXT NOT NULL,
                os_type TEXT NOT NULL,
                os_version TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                agent_timestamp TEXT NOT NULL,
                received_at TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                evaluated_json TEXT,
                FOREIGN KEY(host_id) REFERENCES hosts(id)
            );

            CREATE TABLE IF NOT EXISTS audit_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL UNIQUE,
            platform TEXT NOT NULL,
            overall_score REAL NOT NULL,
            overall_level TEXT NOT NULL,
            any_high_fail INTEGER NOT NULL,
            domain_scores_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (audit_id) REFERENCES audits(id)
            );

            CREATE TABLE IF NOT EXISTS control_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            control_id TEXT NOT NULL,
            title TEXT,
            domain TEXT NOT NULL,
            platform TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence_path TEXT NOT NULL,
            evidence_value_json TEXT,
            reason TEXT,
            recommendation TEXT,
            iso_mapping TEXT,
            pdpa_mapping TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (audit_id) REFERENCES audits(id)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()
