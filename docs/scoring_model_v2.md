# Scoring Model v2 (Risk-Based + Compliance)

This scoring model produces two outputs for every endpoint:

1) **Compliance Score (%)**
- Shows how well the endpoint meets the defined controls (ISO/IEC 27001 Annex A and PDPA-aligned controls).

2) **Risk Score (0–100) + Risk Level**
- Shows how dangerous the current security posture is based on impact, likelihood, exposure, business importance, compliance importance, and how much of the risk remains after PASS/PARTIAL/FAIL/UNKNOWN results.

This approach matches real audit thinking:
- Compliance answers **“Are the controls implemented?”**
- Risk answers **“What should be fixed first because it is most dangerous?”**

---

## 1) Control Results and Status Factors

Every control produces one of these statuses:

- **PASS**: Control is met.
- **PARTIAL**: Control is partially met (reduced risk, but not fully compliant).
- **FAIL**: Control is not met.
- **UNKNOWN**: Evidence cannot be confirmed reliably (assurance gap).

Status factor is used to determine “how much risk remains”.

| Status   | Status Factor (SF) | Meaning |
|----------|---------------------|---------|
| PASS     | 0.0                 | No remaining risk from this control |
| PARTIAL  | 0.5                 | Some risk remains |
| FAIL     | 1.0                 | Full risk remains |
| UNKNOWN  | 0.7                 | Treated as risk because it cannot be proven |

Note: UNKNOWN is not counted as PASS because auditors cannot confirm the control is working.

---

## 2) Compliance Score (Percent)

Compliance score is a weighted score based on severity and PASS/FAIL outcome.

### 2.1 Severity Weights
| Severity | Weight |
|----------|--------|
| Low      | 1 |
| Medium   | 2 |
| High     | 3 |

### 2.2 Compliance Points per Control
Compliance uses a points multiplier:

| Status   | Points Multiplier (PM) |
|----------|-------------------------|
| PASS     | 1.0 |
| PARTIAL  | 0.5 |
| FAIL     | 0.0 |
| UNKNOWN  | 0.0 |

**Earned Points = Severity Weight × Points Multiplier**

### 2.3 Domain Score (%)
Domain Score (%) =
(Sum of Earned Points for controls in the domain / Sum of Max Points for controls in the domain) × 100

Domains:
- Access Control
- Logging & Monitoring
- Cryptography Configuration
- Asset & Configuration Management
- Backup & Recovery (if used)

### 2.4 Overall Compliance Score (%)
Overall Compliance Score (%) =
(Sum of Earned Points across all applicable controls / Sum of Max Points across all applicable controls) × 100

Applicable controls depend on endpoint OS:
- Linux controls apply to Linux endpoints
- Windows Server controls apply to Windows Server endpoints
- Windows 10 controls apply to Windows 10 endpoints

---

## 3) Risk Score (0–100) Using Audit-Realistic Factors

Risk score is calculated per control then aggregated.

### 3.1 Risk Factors (1–5 scale)
Each control has these factors:

1) **Business Criticality (BC)**
- How important is this control to business operations?

2) **Security Impact (SI)**
- If this control fails, how severe is the security consequence?

3) **Exposure Likelihood (EL)**
- How likely is the weakness to be exploited in the current environment?
- This should be evidence-driven where possible (service running, port open, firewall status, recent attacks in logs).

4) **Asset Coverage (ACov)**
- How many systems/users/data are affected if this fails?

5) **Compliance Importance (CI)**
- Is this control strongly tied to legal, policy, or regulatory requirements (ISO/PDPA)?

All factors use the same rating band:
- 1 = Very Low
- 2 = Low
- 3 = Medium
- 4 = High
- 5 = Very High

---

## 4) Inherent Risk Weight (IRW) Calculation

### 4.1 Impact Score (IS)
Impact Score combines multiple “impact” dimensions:

IS =
(0.35 × SI) + (0.20 × BC) + (0.20 × ACov) + (0.25 × CI)

This keeps the model realistic:
- SI drives technical consequence
- BC and ACov represent business and scale impact
- CI ensures compliance-critical controls are prioritized

IS range: 1.0 to 5.0

### 4.2 Inherent Risk Weight (IRW)
Risk is impact × likelihood:

IRW = IS × EL

IRW range: 1.0 to 25.0

---

## 5) Residual Risk per Control

### 5.1 Apply status factor
Residual Risk (before mitigation) =
IRW × SF

### 5.2 Apply mitigation credit (current security mechanisms)
Some existing protections can reduce risk, even when a control fails.
Mitigation credit is capped so it cannot hide major failures.

Mitigation% rules:
- 0% to 30% maximum
- Only applied if mitigation evidence is present and reliable

Residual Risk (final) =
(IRW × SF) × (1 − Mitigation%)

Examples of mitigation signals:
- Firewall enabled reduces exposure for network-access controls
- Logging enabled reduces detection gaps slightly
- Patch freshness reduces vulnerability exposure
- Strong authentication reduces brute-force success probability
- Endpoint protection reduces malware risk (Windows)

---

## 6) Overall Risk Score (0–100)

To normalize risk across different numbers of controls:

Max possible risk per control = IRW (when FAIL, SF=1.0, mitigation=0)

Overall Risk Score =
(Sum of Final Residual Risk across controls / Sum of IRW across controls) × 100

This guarantees:
- 0 means no remaining risk (all PASS)
- 100 means maximum remaining risk (all FAIL, no mitigation)

---

## 7) Risk Level Interpretation

| Risk Score | Level |
|-----------:|-------|
| 0–19       | Low |
| 20–39      | Moderate |
| 40–59      | High |
| 60–79      | Critical |
| 80–100     | Severe |

Note: This risk level is separate from compliance percentage.

---

## 8) Safety Rules (Audit Highlighting)

These rules ensure serious issues are not hidden by high average scores.

### Safety Rule 1: Any High severity FAIL must be highlighted
If any High severity control is FAIL, show it in “Top Risks” and label as priority fix.

### Safety Rule 2: Multiple high failures in the same domain triggers escalation
If a domain has 2 or more High severity FAIL controls, escalate that domain’s risk level by 1 step.

### Safety Rule 3: UNKNOWN is an assurance gap
If a domain contains many UNKNOWN results, show “Insufficient evidence” warning because compliance cannot be confirmed.

---

## 9) Worked Example (Exact Calculation)

Assume VM1 (Linux server) has one control:

Control: AC-LNX-01 Disable SSH root login  
Status: FAIL → SF = 1.0  
Mitigation: Logging enabled gives Mitigation% = 10% (0.10)

Risk factors:
- BC = 4
- SI = 5
- ACov = 4
- CI = 4
- EL = 4

Step 1: Impact Score (IS)
IS = (0.35×5) + (0.20×4) + (0.20×4) + (0.25×4)
IS = 1.75 + 0.80 + 0.80 + 1.00 = 4.35

Step 2: IRW
IRW = IS × EL = 4.35 × 4 = 17.40

Step 3: Residual Risk before mitigation
Residual = IRW × SF = 17.40 × 1.0 = 17.40

Step 4: Apply mitigation (10%)
Final Residual = 17.40 × (1 − 0.10) = 17.40 × 0.90 = 15.66

This control contributes 15.66 residual risk.

If multiple controls exist, total risk score is calculated using the normalization formula:
Risk Score = (Sum Residual / Sum IRW) × 100

---

## 10) Implementation Guidance (How to Carry Out This Model)

### 10.1 Add columns to the control catalogue
Add these fields per control:
- business_criticality (1–5)
- security_impact (1–5)
- asset_coverage (1–5)
- compliance_importance (1–5)
- exposure_profile (label)
- exposure_likelihood_base (1–5)
- exposure_likelihood_rules (text rules)
- mitigation_keys (list of evidence keys that reduce risk)

### 10.2 Compute Exposure Likelihood (EL) automatically using evidence
Use an exposure profile approach.

Example: exposure_profile = remote_auth
- Start EL = exposure_likelihood_base
- +1 if SSH service is active
- +1 if port is open
- +1 if firewall is disabled
- +1 if failed login attempts exist
- cap at 5

This makes risk realistic and evidence-driven.

### 10.3 Store outputs per audit session
Store these in DB for reporting and dashboard:
- compliance_score (%)
- risk_score (0–100)
- risk_level (Low/Moderate/High/Critical/Severe)
- per-domain compliance scores
- per-domain risk totals
- top risks list (sorted by residual risk per control)

---

## 11) Dashboard and Report Display (Recommended)
Show both scores:
- Compliance Score (%) for progress and trend
- Risk Score (0–100) for priority and audit realism

Always show:
- Top 5 highest residual risk controls
- Evidence snippet + recommendation for each top risk
- Any High severity FAIL highlighted as priority