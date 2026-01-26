\# VM Test Setup Checklist (Week 1)



Purpose:

This checklist ensures the lab environment is ready for repeatable testing and evaluation.

Each VM must have a secure baseline and an insecure baseline snapshot for fair comparison.



\## A) Testbed Overview

Hypervisor used: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ (VirtualBox / VMware)

Host machine: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Network type: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ (NAT / Host-only / Internal)

Audit server IP (planned): \_\_\_\_\_\_\_\_\_\_\_ (example: 192.168.56.150)



\## B) VM1: Ubuntu Server (Linux)

\- VM name: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\- IP address: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\- Login method: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ (SSH)

\- Notes: SSH service installed, UFW installed, rsyslog installed



Access check:

\- \[ ] Can ping VM from host

\- \[ ] Can SSH into VM



Snapshots:

\- \[ ] Snapshot created: secure\_baseline

\- \[ ] Snapshot created: insecure\_baseline



Secure baseline settings (target):

\- PermitRootLogin no

\- PasswordAuthentication no (SSH key login)

\- rsyslog running

\- /var/log/auth.log exists

\- UFW enabled



Insecure baseline settings (for testing):

\- PermitRootLogin yes

\- PasswordAuthentication yes

\- rsyslog stopped

\- UFW disabled



\## C) VM2: Windows Server

\- VM name: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\- IP address: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\- Login method: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ (RDP / console)

\- Notes: Event Log available, Firewall available, local policy editable



Access check:

\- \[ ] Can ping VM from host

\- \[ ] Can access VM (RDP or console)



Snapshots:

\- \[ ] Snapshot created: secure\_baseline

\- \[ ] Snapshot created: insecure\_baseline



Secure baseline settings (target):

\- Minimum password length >= 8

\- Password complexity enabled

\- Windows Event Log service running

\- Windows Firewall enabled (all profiles)



Insecure baseline settings (for testing):

\- Minimum password length < 8

\- Password complexity disabled

\- Windows Event Log service stopped

\- Windows Firewall disabled



\## D) VM3: Windows 10

\- VM name: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\- IP address: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\- Login method: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ (RDP / console)

\- Notes: Defender available, updates available, firewall available



Access check:

\- \[ ] Can ping VM from host

\- \[ ] Can access VM (console)



Snapshots:

\- \[ ] Snapshot created: secure\_baseline

\- \[ ] Snapshot created: insecure\_baseline



Secure baseline settings (target):

\- Real-time antivirus protection enabled

\- Windows Firewall enabled

\- Windows Update enabled (if you include update checks later)



Insecure baseline settings (for testing):

\- Real-time antivirus protection disabled

\- Windows Firewall disabled (optional for later tests)



\## E) Snapshot naming rule (important)

Use exactly these snapshot names for consistency:

\- secure\_baseline

\- insecure\_baseline



Reason:

It makes testing repeatable, and your evaluation section can clearly compare results.



