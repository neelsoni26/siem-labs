
# Incident Report: Reverse Shell, Payload Deployment, and Lateral Movement via WMI

## Setup Diagram
![Diagram.](/screenshots/LabSetup.png "Diagram")

## Executive Summary
On April 8, 2025, suspicious activity was detected across `sql01.electric.com` and `dc01.electric.com`. The attacker exploited a vulnerable PHP script to gain initial access, established a reverse shell using Netcat, downloaded and staged malicious payloads (`Sync.exe` and `apphelper.exe`) via `certutil.exe`, and attempted persistence through service hijacking. The attacker then pivoted laterally to the domain controller (`dc01`) using WMI with Administrator credentials, successfully executing `apphelper.exe`. Attempts to run the malware as a service (`lpfols`) failed, but the chain demonstrates a full intrusion lifecycle: initial access, execution, persistence, and lateral movement.

## Investigation
- **Detection Source**: Elastic Security / Sysmon dataset (`windows.sysmon_operational`)
- **Queries Used**:
  ```kql
  # Detect suspicious shell processes
  process.name: ("powershell.exe" or "cmd.exe" or "bash" or "sh" or "zsh")

  # Detect activity by wp-user on sql01
  host.name: "sql01.electric.com" and user.name: "wp-user"

  # Detect process and file creation events on sql01
  host.name: "sql01.electric.com" and event.action: ("Process Create (rule: ProcessCreate)" or "File created (rule: FileCreate)" )

  # Detect Administrator activity on dc01
  host.name: "dc01.electric.com" and user.name: "Administrator"

  # Detect process and file creation events in a specific time window
  event.action: ("Process Create (rule: ProcessCreate)" or "File created (rule: FileCreate)" )
  ```
- **Observed Behavior**:
  - Reverse shell established via `php-cgi.exe` → `cmd.exe` → `nc.exe`.
  - `certutil.exe` used to download `Sync.exe` and `apphelper.exe` from attacker IP `192.168.51.79`.
  - Service manipulation (`sc stop/start "sync breeze enterprise"`) attempted to hijack legitimate services.
  - PowerShell script dropped in Temp (`__PSScriptPolicyTest...ps1`) indicating execution policy bypass testing.
  - WMI used from `sql01` to `dc01` with Administrator credentials to execute `apphelper.exe`.
  - Named pipe (`\\.\pipe\lpfols`) created, suggesting malware IPC or C2 setup.
  - Service `lpfols` failed to connect, indicating attempted persistence.

## Findings
- **Source IP / Host**: `sql01.electric.com` (192.168.50.72)
- **Target Hosts / Accounts**: `dc01.electric.com` (Administrator account)
- **Indicators**:
  - Suspicious processes: `php-cgi.exe`, `cmd.exe`, `nc.exe`, `certutil.exe`, `sc.exe`, `rundll32.exe`, `apphelper.exe`
  - Files: `Sync.exe`, `apphelper.exe`, `__PSScriptPolicyTest...ps1`
  - IOC: Attacker IP `192.168.51.79`
- **Outcome**: Successful reverse shell and lateral movement; payload staged and executed on domain controller; persistence attempt via service creation failed.

## Detection Logic
Detection leveraged Sysmon event codes:
- **Event ID 1**: Process creation (flagged suspicious binaries and command lines).
- **Event ID 11**: File creation (flagged dropped executables and scripts).
- Queries filtered by host, user, and time range to correlate activity across `sql01` and `dc01`.

## Recommendations
- **Containment**:
  - Isolate `sql01` and `dc01` from the network.
  - Block outbound traffic to `192.168.51.79`.
  - Disable and remove the `lpfols` service and delete `Sync.exe` and `apphelper.exe`.
- **Preventive Measures**:
  - Patch vulnerable web applications to prevent PHP exploitation.
  - Enforce strong credential hygiene; avoid hardcoded passwords.
  - Restrict WMI usage to trusted administrators only.
- **Monitoring Improvements**:
  - Add detection rules for `certutil.exe` downloads and Netcat usage.
  - Monitor for suspicious service creation and named pipe usage.
  - Enhance dashboards to correlate cross-host WMI activity.

## MITRE ATT&CK Mapping
- **Technique**:
  - T1059 – Command and Scripting Interpreter (cmd.exe, PowerShell)
  - T1047 – Windows Management Instrumentation (WMI)
  - T1105 – Ingress Tool Transfer (`certutil.exe`)
  - T1543 – Create or Modify System Process (Service hijacking)
  - T1071 – Application Layer Protocol (Named pipe C2)
- **Tactic**: Execution, Persistence, Lateral Movement, Defense Evasion, Command & Control

## Lessons Learned
This lab demonstrates how attackers chain multiple techniques: exploiting web applications, abusing LOLBins (`certutil.exe`, `rundll32.exe`), leveraging WMI for lateral movement, and attempting persistence via malicious services. Key takeaways include the importance of monitoring service creation events, detecting abnormal WMI usage, and correlating activity across hosts. In a real SOC environment, detection rules should be tuned to catch these behaviors early, and credential hygiene must be enforced to prevent lateral movement with Administrator accounts.


