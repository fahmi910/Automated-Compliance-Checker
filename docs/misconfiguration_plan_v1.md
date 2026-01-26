\# Misconfiguration Plan v1 (Test Cases)



Purpose:

This plan lists the misconfigurations we intentionally apply on each VM to test whether the agent + rules engine can detect them.

Each misconfiguration should trigger a FAIL result for the expected control.



\## VM1: Ubuntu Server (Linux)



| Test ID | Misconfiguration (what we change)                      | Expected FAIL Control | Evidence Collected (what proves it) |

|---------|--------------------------------------------------------|-----------------------|---|

| LNX-01  | Enable SSH root login (PermitRootLogin yes)            | AC-LNX-01 | /etc/ssh/sshd\_config shows PermitRootLogin yes |

| LNX-02  | Enable SSH password login (PasswordAuthentication yes) | AC-LNX-02 | /etc/ssh/sshd\_config shows PasswordAuthentication yes |

| LNX-03  | Stop logging service (rsyslog stopped)                 | LOG-LNX-01 | systemctl is-active rsyslog returns inactive |

| LNX-04  | Remove or disable auth logging                         | LOG-LNX-02 | /var/log/auth.log missing or not readable |

| LNX-05  | Disable firewall (UFW inactive)                        | FW-LNX-01  | ufw status shows inactive (agent key: results.asset\_config.firewall.ufw\_enabled = false) |

| LNX-06  | Allow weak SSH ciphers (CBC/3DES)                      | CRYPTO-LNX-01 | agent reports crypto.ssh\_weak\_ciphers list is not empty |

| LNX-07  | Enable old TLS (TLS 1.0/1.1 supported)                 | CRYPTO-LNX-02 | testssl.sh JSON shows minimum\_version < 1.2 |



\## VM2: Windows Server



| Test ID | Misconfiguration (what we change) | Expected FAIL Control | Evidence Collected (what proves it) |

|---|---|---|---|

| WIN-01 | Set minimum password length below 8 | AC-WIN-01 | net accounts shows Minimum password length < 8 |

| WIN-02 | Disable password complexity | AC-WIN-02 | policy output shows complexity disabled |

| WIN-03 | Stop Windows Event Log service | LOG-WIN-01 | Get-Service EventLog shows Stopped |

| WIN-04 | Disable Windows Firewall profiles | FW-WIN-01 | Get-NetFirewallProfile shows Enabled = False |



\## VM3: Windows 10



| Test ID | Misconfiguration (what we change) | Expected FAIL Control | Evidence Collected (what proves it) |

|---|---|---|---|

| W10-01 | Disable real-time antivirus protection | EP-W10-01 | Get-MpComputerStatus shows RealTimeProtectionEnabled = False |



