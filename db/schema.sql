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

CREATE INDEX IF NOT EXISTS idx_audits_host_id ON audits(host_id);
CREATE INDEX IF NOT EXISTS idx_audits_received_at ON audits(received_at);
