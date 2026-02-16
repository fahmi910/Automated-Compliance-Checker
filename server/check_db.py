from db import get_conn

conn = get_conn()
cur = conn.cursor()

print("Hosts:")
for r in cur.execute("SELECT id, hostname, ip_address, os_type, last_seen FROM hosts"):
    print(dict(r))

print("\nAudits:")
for r in cur.execute("SELECT id, host_id, agent_timestamp, received_at FROM audits ORDER BY id DESC LIMIT 5"):
    print(dict(r))

conn.close()
