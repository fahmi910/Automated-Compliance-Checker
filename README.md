\# Automated Compliance Checker (ISO27001 Annex A + PDPA 2010)



This project automates security evidence collection from multiple OS endpoints (Linux + Windows),

evaluates compliance against defined controls, calculates scores, and displays results in a dashboard.



\## Project Structure

\- agent/       : Evidence collection agent scripts (runs on endpoints)

\- server/      : Flask audit server (receives JSON, stores results)

\- rules/       : Control catalogue + rule definitions (PASS/FAIL logic)

\- db/          : SQLite schema + stored audit data

\- dashboard/   : Streamlit dashboard UI

\- docs/        : Architecture notes + API contract

\- tests/       : Sample evidence and test cases



\## Intended Workflow

1\. Agent collects evidence and outputs JSON

2\. Agent sends JSON to audit server via POST

3\. Server stores evidence in SQLite

4\. Rules engine evaluates PASS/FAIL + scoring

5\. Dashboard shows compliance status and trends



