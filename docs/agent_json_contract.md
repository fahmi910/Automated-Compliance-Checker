\# Agent JSON Contract (v1)



This document defines the standard JSON format that every endpoint agent must produce and submit to the audit server.

Using a fixed structure makes it easier to store evidence, evaluate rules, and display results.



\## 1) Required Top-Level Fields

Every agent submission must include:



\- hostname: machine name (example: vm1-ubuntu)

\- host\_id: unique ID (can be hostname or generated UUID)

\- ip\_address: endpoint IP address

\- os\_type: linux / windows\_server / windows10

\- os\_version: OS version string

\- timestamp: ISO timestamp when scan is executed

\- agent\_version: agent version number

\- results: dictionary containing evidence grouped by modules

\- errors: list of errors if a module fails (empty list if no errors)



\## 2) Results Structure (grouped by modules)

results contains module groups such as:

\- access\_control

\- logging

\- crypto

\- asset\_config

\- asset (optional, software baseline)

\- updates

\- av

\- backup (if simulated)



Example path used by rules:

\- results.access\_control.ssh.permit\_root\_login

\- results.asset\_config.firewall.ufw\_enabled

\- results.logging.rsyslog\_running



\## 3) Notes

\- If a check cannot be collected, store a null value and add a message in errors.

\- Each value should be simple (boolean, number, string, list) so rules are easy to evaluate.



