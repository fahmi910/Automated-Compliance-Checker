# Week 6 Demo Steps (2 minutes)

1) Start server:
   python server/app.py

2) Run agent on VM (secure/insecure)

3) Confirm server response includes audit_id

4) Open sqlite:
   sqlite3 server/data/audit.db

5) Show:
   - table exist
    .tables

   - latest audit
    SELECT a.id AS audit_id, h.hostname, h.os_type, a.received_at
    FROM audits a
    JOIN hosts h ON h.id = a.host_id
    ORDER BY a.id DESC
    LIMIT 5;

   - overall score saved
    SELECT audit_id, platform, overall_score, overall_level, any_high_fail, created_at
    FROM audit_scores
    WHERE audit_id = XX;

   - pass/fail control results
    SELECT control_id, status, severity, domain
    FROM control_results
    WHERE audit_id = XX
    ORDER BY
    CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
    status ASC;
    

6) Call endpoint:
   /audits/latest/evaluated?hostname=<hostname>

7) End: show overall score and top FAIL controls