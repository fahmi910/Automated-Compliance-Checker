\# Scoring Model v1 (Simple Compliance Scoring)



This scoring model turns PASS/FAIL results into a score that is easy to understand.

It also highlights serious failures so the score is not misleading.



\## 1) PASS/FAIL to Points

Each control produces one result:

\- PASS = get full points

\- FAIL = get 0 points



\## 2) Severity Weights

Some issues are more serious than others, so we use weights:



\- Low severity = 1 point

\- Medium severity = 2 points

\- High severity = 3 points



This means failing a High severity control affects the score more than failing a Low severity control.



\## 3) Domain Score (per domain)

A domain score is calculated using:



Domain Score (%) =

(sum of points earned for controls in that domain / sum of maximum points for controls in that domain) × 100



Domains used in this project:

\- Access Control

\- Logging \& Monitoring

\- Cryptography Configuration

\- Asset \& Configuration Management

\- Backup \& Recovery (simulated if used)



\## 4) Overall Score (per host / endpoint)

Overall Score (%) =

(sum of points earned across all applicable controls / sum of maximum points across all applicable controls) × 100



“Applicable controls” means:

\- Linux controls are scored for Linux endpoints

\- Windows Server controls are scored for Windows Server endpoints

\- Windows 10 controls are scored for Windows 10 endpoints



\## 5) Score Interpretation (Critical vs Not Critical)



A) Overall score per host (endpoint)

| Overall Score (%) |   Level   |                             Meaning                         |

|------------------:|-----------|-------------------------------------------------------------|

|        0–49%      | Critical  | Many important controls failed. High risk. Fix immediately. |

|       50–69%      | High Risk | Security is weak. Several gaps exist. Fix soon.             |

|       70–84%      | Moderate  | Acceptable but still has weaknesses. Improve step-by-step.  |

|       85–94%      | Good      | Mostly compliant. Minor improvements needed.                |

|       95–100%     | Excellent | Strong compliance. Maintain and monitor.                    |



Critical vs Not Critical (host):

\- Critical = below 50%

\- Not Critical = 50% and above



B) Domain score per domain

| Domain Score (%) |   Level   | Meaning                                              |

|-----------------:|-----------|------------------------------------------------------|

|      0–49%       | Critical  | Domain is badly configured. Major risk in this area. |

|      50–69%      | High Risk | Weak domain. Improve quickly.                        |

|      70–84%      | Moderate  | Some issues remain. Improve next.                    |

|      85–94%      | Good      | Mostly compliant in this domain.                     |

|      95–100%     | Excellent | Domain is strong and well configured.                |



Critical vs Not Critical (domain):

\- Critical = below 50%

\- Not Critical = 50% and above



\## 6) Safety Rules (to avoid misleading scores)



Safety rule 1: Any High severity FAIL increases risk level

If any High severity control fails, increase the risk level by 1 step.



Example:

\- Overall score is 88% (Good)

\- But a High severity control fails

\- Final risk level becomes Moderate



Safety rule 2 (optional but recommended): 2 High severity FAILs in the same domain

If a domain has 2 or more High severity FAIL controls, label that domain as Critical,

even if its score is above 50%.



This helps highlight serious weaknesses that should not be hidden by other passing controls.



\## 7) Simple Example

Assume a Linux endpoint has 4 controls, all High severity (3 points each):



1\) AC-LNX-01 PASS → earns 3/3

2\) AC-LNX-02 FAIL → earns 0/3

3\) LOG-LNX-01 PASS → earns 3/3

4\) FW-LNX-01 FAIL → earns 0/3



Total earned points = 3 + 0 + 3 + 0 = 6  

Total maximum points = 3 + 3 + 3 + 3 = 12  



Overall Score = (6 / 12) × 100 = 50% → High Risk



Also, because there are High severity FAIL controls, the system should highlight them clearly

in the dashboard and report as priority fixes.



