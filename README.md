# Automated Compliance Checker (ISO27001 Annex A + PDPA 2010)

Automates security evidence collection from Linux and Windows endpoints, evaluates compliance using a control catalogue,
stores results in SQLite, and visualizes them in a Streamlit dashboard.

## 1) Project Modules
- agent/       : Runs on endpoints (VM1 Ubuntu, VM2 Windows Server, VM3 Windows 10) to collect evidence and output JSON
- server/      : Flask audit server that receives JSON and stores audit sessions
- rules/       : Control catalogue (PASS/FAIL logic, severity, recommendations)
- db/          : SQLite schema and stored audit data
- dashboard/   : Streamlit UI to show compliance results and trends
- docs/        : Architecture notes and API contract
- tests/       : Sample evidence and test cases

## 2) Intended Workflow
1. Run agent on a VM → produces evidence JSON
2. Agent sends JSON to audit server via HTTP POST
3. Server stores raw evidence + normalized results in SQLite
4. Rules engine evaluates PASS/FAIL and computes scores
5. Dashboard displays summary, details, and history

## 3) Requirements (Week 1)
- Windows PowerShell
- Python 3.10+ installed
- Git installed (already used to create commits)

## 4) Setup (Week 1 baseline)
At Week 1, only the repo structure and placeholders exist.
Later weeks will add full working code.

### Create Python virtual environment (recommended)
From the project root:
```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip

## How to run (planned, will be implemented in later weeks)
Agent:
- python .\agent\main.py

Audit Server:
- python .\server\app.py

Dashboard:
- streamlit run .\dashboard\app.py

## Week 1 Completed Outputs
- Repo structure created (agent/server/rules/db/dashboard/docs/tests)
- Placeholder files created
- Git commits created for tracking progress


