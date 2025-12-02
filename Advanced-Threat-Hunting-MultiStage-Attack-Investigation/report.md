# Incident Report: Complete Domain Compromise via SQL Injection & Automated Lateral Movement

## Executive Summary
A sophisticated multi-stage cyber attack compromised all critical infrastructure within 38 minutes. The attack began with SQL injection against a web application, leading to credential theft, privilege escalation to Domain Administrator, and automated lateral movement across all servers. The attacker established multiple persistence mechanisms and executed domain manipulation commands, resulting in complete domain compromise. This incident demonstrates how a single web vulnerability can lead to total infrastructure takeover.

## Investigation
- **Detection Source**: Elastic Security SIEM (Windows Security Events, Sysmon, Web Server Logs)
- **Queries Used**:
  ```kql
  # Initial SQL Injection detection in web logs
  url.original: "*' OR *" or url.original: "*UNION*SELECT*" or http.request.body: "*' OR 1=1*"
  
  # Malware download detection
  process.name: "curl.exe" and process.command_line: "*192.168.51.79/helper.exe*"
  
  # Privilege escalation detection
  user.name: "Administrator" and event.action: "logged-in" and @timestamp >= "2025-04-15T09:20:00.000"
  
  # Persistence mechanism detection
  service.name: "qLCfVtPj" or file.path: "*\\\\Tasks\\\\helper" or process.command_line: "*NetSetupSvc*"
  
  # Domain manipulation detection
  process.name: "dsregcmd.exe" and process.command_line: "*$(Arg*"
  
  # Automated attack execution
  process.name: "taskhostw.exe" and process.parent.command_line: "*svchost.exe*k netsvcs*p*s Schedule*"
  ```
- **Observed Behavior**:
  - Coordinated attack execution across multiple servers within seconds of each other
  - Use of legitimate Windows tools (curl, schtasks, dsregcmd) for malicious purposes
  - Obfuscated command execution using environment variables ($(Arg0), $(Arg1), $(Arg2))
  - Multiple redundant persistence mechanisms (Windows Service + Scheduled Tasks)
  - Systematic lateral movement pattern: dc01 → appsrv07 → sql01 → jump02

## Findings
- **Source IP / Host**: 192.168.51.79 (Attacker C2), Initial compromise via appsrv07 web application
- **Target Hosts / Accounts**: dc01 (Domain Controller), sql01 (Database), appsrv07 (Web Server), jump02 (Jump Server)
- **Indicators**:
  - Malware Hashes: helper.exe (MD5: 2419907A0BB9A14F1871F0BDA7F65578, SHA256: C53B0901C262071DA3F3FBB69C30C2C26E2AB7866C7C42183C830B9A609C7994)
  - Service Backdoor: qLCfVtPj (randomly named Windows service)
  - Scheduled Task: "helper" task running C:\Windows\Temp\helper.exe as SYSTEM
  - Network IOC: Consistent calls to 192.168.51.79 for malware downloads
  - Credential IOC: electric (IIS AppPool) and Administrator accounts compromised
- **Outcome**: Complete success for attacker - all critical systems compromised, domain integrity destroyed, data breach confirmed

## Detection Logic
Alert triggers when detecting coordinated malicious activity across multiple systems including: SQL injection patterns in web logs followed by suspicious process creation (curl downloading from external IP), privilege escalation to Domain Administrator, creation of randomly-named services, scheduled task creation for persistence, and domain manipulation commands executed across multiple servers within a short time window.

## Recommendations
- **Containment**: Immediately isolate all compromised systems (dc01, sql01, appsrv07, jump02) from network. Block all traffic to/from 192.168.51.79. Remove malicious services (qLCfVtPj) and scheduled tasks (helper).
- **Preventive Measures**: Implement WAF to block SQL injection, enforce least privilege for service accounts, implement network segmentation to restrict lateral movement, deploy application allowlisting to prevent execution of unauthorized binaries.
- **Monitoring Improvements**: Create correlation rules detecting: SQL injection followed by outbound curl/wget, service creation with random names, scheduled task creation by non-admin tools, dsregcmd.exe execution outside of domain join operations, coordinated attack patterns across multiple servers.

## MITRE ATT&CK Mapping
- **Technique**: 
  - T1190: Exploit Public-Facing Application (SQL Injection)
  - T1078: Valid Accounts (Credential reuse)
  - T1053.005: Scheduled Task (Persistence)
  - T1543.003: Windows Service (Persistence)
  - T1021: Remote Services (Lateral Movement)
  - T1484: Domain Policy Modification (Impact)
- **Tactic**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Impact

## Lessons Learned
This lab demonstrated the critical importance of defense-in-depth and rapid response. Key takeaways: 1) A single unpatched vulnerability (SQL Injection) can lead to complete domain compromise in under 40 minutes, 2) Attackers use legitimate Windows tools to evade detection, 3) Coordinated attacks across multiple systems require correlation rules rather than single-event alerts, 4) Persistence mechanisms are often redundant (service + scheduled tasks), 5) Domain controller compromise means complete business impact. In a real SOC, I would implement automated playbooks to isolate systems upon detection of certain high-severity indicators and create dashboards showing attack progression across the environment.
