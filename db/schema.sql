CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT NOT NULL UNIQUE,
  ip_address TEXT,
  os_type TEXT,
  os_version TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  agent_timestamp TEXT,
  received_at TEXT NOT NULL,
  raw_json TEXT NOT NULL,
  FOREIGN KEY (host_id) REFERENCES hosts(id)
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

CREATE INDEX IF NOT EXISTS idx_audits_host_id ON audits(host_id);
CREATE INDEX IF NOT EXISTS idx_audits_received_at ON audits(received_at);
CREATE INDEX IF NOT EXISTS idx_control_results_audit_id ON control_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_audit_scores_audit_id ON audit_scores(audit_id);