# Incident Report: Brute‑Force Credential Spray → Privilege Escalation → Lateral Admin Access

## Executive Summary
On 28 April 2025, an external host (IP 192.168.219.69) performed a rapid brute‑force attack against three application servers (appsvr01, appsvr02, appsvr03). After 263 failed attempts within ~2 seconds, the attacker successfully logged in as user **Peter** on appsvr02, granted that account a full set of high‑privilege Windows rights, and subsequently used the compromised credentials to obtain an **Administrator** session on appsvr03. The chain demonstrates credential theft, privilege escalation, and lateral movement, exposing critical systems to full control.

## Investigation
- **Detection Source**: Elastic Security (logs indexed in `logs-*`)
- **Queries Used**:
  ```kql
  # Brute‑force burst (failures)
  event.category:"authentication" and event.outcome:"failure" and source.ip:"192.168.219.69"
  # First successful login as Peter
  event.category:"authentication" and event.outcome:"success" and source.ip:"192.168.219.69" and user.name:"Peter"
  # Privilege grant to Peter
  event.category:"authorization" and source.ip:"192.168.219.69" and user.name:"Peter"
  # Lateral admin login on appsvr03
  event.category:"authentication" and event.outcome:"success" and source.ip:"192.168.219.69" and user.name:"Administrator"
  ```
- **Observed Behavior**:
  - 263 failed authentication events from the same IP within a 2‑second window targeting three hosts.
  - Immediate successful login as a low‑privilege user (Peter) on appsvr02.
  - Automatic assignment of multiple `Se*` privileges to Peter (Security, Backup, Restore, Debug, etc.).
  - Within minutes, the same IP logged in as Administrator on a different host (appsvr03).
  - Activity deviates sharply from baseline: normal login failure rate < 5 per minute, no routine privilege changes for Peter.

## Findings
- **Source IP / Host**: `192.168.219.69`
- **Target Hosts / Accounts**:
  - `appsvr02` – user **Peter**
  - `appsvr03` – user **Administrator**
- **Indicators**:
  - Massive failed login count (263) in < 2 min.
  - Successful login from the same source shortly after failures.
  - Privilege‑escalation events adding nine high‑level Windows privileges to a non‑admin account.
  - Admin login from a source previously associated with brute‑force activity.
- **Outcome**: Successful credential compromise, privilege escalation, and lateral movement to full admin control on a critical server.

## Detection Logic
An alert is triggered when **≥ 50 failed authentication events** occur from a single `source.ip` within a **1‑minute** window (`event.category:"authentication" and event.outcome:"failure"`). A secondary rule watches for **privilege‑add** actions (`event.category:"authorization"` with `event.action:"privilege_add"`) on accounts that have not previously held such rights. Correlation of the two rules within a 10‑minute window flags a potential compromise.

## Recommendations
- **Containment**
  - Block `192.168.219.69` at the perimeter firewall and on internal IDS/IPS.
  - Immediately disable the `Peter` account and force a password reset.
  - Revoke all `Se*` privileges granted to Peter; restore baseline group memberships.
  - Isolate `appsvr02` and `appsvr03` for forensic imaging.
- **Preventive Measures**
  - Enforce account lockout: 5 failed attempts → 15‑minute lockout.
  - Deploy MFA for all privileged and service accounts.
  - Apply least‑privilege principle; use Just‑In‑Time elevation (PAM) for admin tasks.
  - Harden file‑upload paths (whitelist MIME types, store outside web root, set `noexec`).
- **Monitoring Improvements**
  - Deploy the combined KQL dashboard “Brute‑Force → Privilege Escalation → Lateral Movement.”
  - Add a rule to alert on any `event.category:"authorization"` that adds `Se*` privileges to non‑admin users.
  - Enable continuous audit of admin logins from non‑admin workstations.

## MITRE ATT&CK Mapping
- **Technique**: T1110.001 – Password Spraying  
- **Technique**: T1068 – Exploitation for Privilege Escalation (privilege‑add actions)  
- **Technique**: T1078.001 – Valid Accounts: Default Accounts (use of compromised credentials)  
- **Tactic**: Credential Access → Privilege Escalation → Lateral Movement  

## Lessons Learned
The lab highlighted how a short burst of failed logins can quickly transition to a full compromise when lockout policies are absent. Correlating authentication failures with subsequent privilege‑grant events proved essential for early detection. In a production SOC, tuning the failure threshold to balance false positives while maintaining rapid response is critical. Implementing automated containment (IP blocklists, account disable) and continuous privilege‑change monitoring would reduce dwell time in real‑world incidents.