\# Supervisor Check-in Pack (Week 1)



\## 1) What I completed this week

\- Created project repo structure and committed it to Git (agent/server/rules/db/dashboard/docs/tests).

\- Wrote README run guide to explain system workflow and planned commands.

\- Created Control Catalogue v1 (rules/controls.json) covering Linux, Windows Server, and Windows 10 checks.

\- Created Scoring Model v1 (docs/scoring\_model\_v1.md) including critical thresholds for host and domain scores.

\- Defined Agent JSON Contract v1 and sample Linux agent output for testing.

\- Created Misconfiguration Plan v1 (docs/misconfiguration\_plan\_v1.md) to support evaluation in later weeks.



\## 2) Current outputs available in the repo

\- rules/controls.json

\- docs/scoring\_model\_v1.md

\- docs/agent\_json\_contract.md

\- tests/sample\_agent\_output\_linux.json

\- docs/misconfiguration\_plan\_v1.md



\## 3) What I plan to do next week (Week 2)

\- Implement agent skeleton for Linux and Windows:

&nbsp; - OS detection and module runner

&nbsp; - Basic evidence collection for Access Control + Logging + Asset/Config

&nbsp; - Generate JSON output following the contract

\- Implement server endpoint placeholder:

&nbsp; - /submit endpoint accepts JSON and returns success response



\## 4) Questions / feedback needed

1\) Do the current controls and severity levels look reasonable for ISO27001 Annex A and PDPA 2010 framing?

2\) Is the scoring interpretation (Critical threshold < 50%) acceptable for this project?

3\) Are there any controls you recommend adding early for stronger audit value?

4\) Do you prefer the dashboard to focus more on:

&nbsp;  - compliance score trends, or

&nbsp;  - top risks and recommended fixes?



\## 5) Evidence of progress (Git commits)

\- Repo has multiple Week 1 commits showing structured progress and documentation.



