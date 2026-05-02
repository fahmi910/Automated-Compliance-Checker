# Week 6 Summary: Rules Engine + Scoring + DB Storage

## Objective
Implement compliance evaluation (PASS/FAIL), scoring, and automatic storage into database after agent submission.

## What is completed
- Controls frozen using `evidence_path` format (platform-based controls: linux/windows_server/windows10)
- Rules engine evaluates controls using rule types:
  - must_equal, must_be_true, must_be_empty_list, all_objects_field_equals
- Scoring model implemented using severity weights (low=1, medium=2, high=3)
- Safety rules:
  - Any high severity FAIL downgrades risk level by 1 step
  - 2+ high severity FAIL in the same domain marks domain as Critical
- Auto-evaluate enabled on `/submit`
- Results stored into SQLite tables:
  - audits (raw_json)
  - audit_scores (overall + domain scores)
  - control_results (PASS/FAIL, evidence, recommendation)

## Evidence (files)
- Secure vs insecure outputs saved in `docs/week6/json_outputs/`
- SQLite proof screenshots saved in `docs/week6/screenshots/`

## Key demo result (secure vs insecure)
- VM1 Linux: Secure = 100% (Excellent), Insecure = 11.76% (Critical)
- VM2 Win Server: Secure = 100% (Excellent), Insecure = 45.45% (Critical)
- VM3 Win10: Secure = 100% (Excellent), Insecure = 64.29% (Critical)
Note: VM3 insecure remains Critical because a High severity control (Firewall) failed, triggering Safety Rule 1 (risk level downgrade).

## Next Week (Week 7)
Build Streamlit dashboard using:
- /hosts
- /audits/latest/evaluated?hostname=...
or directly reading audit_scores + control_results from DB.