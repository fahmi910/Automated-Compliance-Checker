\# VM Test Setup Checklist (Week 1)



Purpose:

This checklist confirms the VirtualBox lab environment is ready for repeatable testing and evaluation.

Each VM has two snapshots:

\- secure\_baseline (secure configuration)

\- insecure\_baseline (intentional misconfiguration for testing)



\## A) Testbed Overview

Hypervisor: VirtualBox  

Host-only network: 192.168.56.0/24  

Host-only adapter IP (host PC): 192.168.56.1  

DHCP range: 192.168.56.100 – 192.168.56.200  



\## B) VM1: Ubuntu Server (Linux)

VM name: VM1-Ubuntu-Server  

Host-only IP: 192.168.56.100  

Access method: SSH  



Access check:

\- \[x] Host can ping VM1

\- \[x] Host can SSH into VM1 (tested before hardening)



Snapshots created:

\- \[x] secure\_baseline

\- \[x] insecure\_baseline



Secure baseline (target):

\- SSH root login disabled (PermitRootLogin no)

\- SSH password authentication disabled (PasswordAuthentication no)

\- rsyslog enabled and running

\- UFW enabled with SSH allowed



Insecure baseline (for testing):

\- SSH root login enabled

\- SSH password authentication enabled

\- rsyslog stopped/disabled

\- UFW disabled



\## C) VM2: Windows Server 2022 (GUI)

VM name: VM2-Windows-Server  

Host-only IP: 192.168.56.102  

Access method: Console (GUI)  

Notes: ICMP inbound rule added to allow ping



Access check:

\- \[x] Host can ping VM2



Snapshots created:

\- \[x] secure\_baseline

\- \[x] insecure\_baseline



Secure baseline (target):

\- Minimum password length >= 8

\- Password complexity enabled

\- Windows Event Log service running

\- Windows Firewall enabled (all profiles)



Insecure baseline (for testing):

\- Minimum password length lowered

\- Password complexity disabled

\- Firewall disabled

\- (Optional) audit policy weakened



\## D) VM3: Windows 10 (Client)

VM name: VM3-Windows10  

Host-only IP: 192.168.56.103  

Access method: Console (GUI)  

Notes: ICMP inbound rule added to allow ping



Access check:

\- \[x] Host can ping VM3



Snapshots created:

\- \[x] secure\_baseline

\- \[x] insecure\_baseline



Secure baseline (target):

\- Windows Defender real-time protection enabled

\- Windows Firewall enabled



Insecure baseline (for testing):

\- Windows Defender real-time protection disabled

\- (Optional) Firewall disabled



\## E) Snapshot naming rule

Snapshot names used:

\- secure\_baseline

\- insecure\_baseline



