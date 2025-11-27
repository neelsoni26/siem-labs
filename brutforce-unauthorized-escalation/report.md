# Incident Report: Unauthorized Access and Privilege Escalation

## Executive Summary
On April 15, 2025, a multi-phase cyber intrusion attempt was detected on the Windows Server appsrv02, involving multiple failed login attempts, unauthorized authentication, and potential privilege escalation targeting the user account Akhtar.

## Investigation
- **Detection Source**: Elastic Security / Windows Security Logs
- **Queries Used**:
  ```kql
  # Failed login attempts
  event.action : "logon-failed"

  # Successful authentication
  event.category : "authentication" and event.outcome : "success" and host.name: "appsrv02"

  # User activities
  user.name: ("Akhtar" or "akhtar" or "ANONYMOUS USER") and host.name: "appsrv02"
  ```
- **Observed Behavior**:
  - 54 consecutive failed login attempts for user Akhtar
  - Anonymous user authentication from 192.168.51.69
  - Immediate login of targeted user after anonymous access
  - Multiple reconnaissance and privilege escalation activities
  - Suspicious file and software installation attempts

## Findings
- **Source IP / Host**: 
  - 192.168.51.69 (Anonymous User)
  - Host: appsrv02 (Windows Server 2019 Standard)
- **Target Hosts / Accounts**: 
  - User: Akhtar
- **Indicators**:
  - 54 failed login attempts within 1 second
  - Anonymous user authentication
  - Creation of nighty.ps1
  - Silent MSI installation (aie.msi)
  - Extensive privilege escalation
- **Outcome**: Potential full system compromise with high-privilege access

## Detection Logic
- Alert triggers when:
  - More than 10 failed logins occur within 5 minutes
  - Anonymous user authentication is detected
  - Sudden privilege escalation with multiple high-risk permissions
  - Suspicious file creation in user documents
  - Silent software installation using msiexec

## Recommendations
- Immediate Containment:
  - Disable Akhtar user account
  - Isolate appsrv02 from network
  - Forensic image of the system
- Preventive Measures:
  - Implement multi-factor authentication
  - Enforce strict password complexity
  - Limit and monitor privileged accounts
  - Implement application whitelisting
- Monitoring Improvements:
  - Enhanced logging for privilege changes
  - Real-time alerts for suspicious file creation
  - Network traffic analysis for unauthorized access

## MITRE ATT&CK Mapping
- **Technique**: 
  - T1078 (Valid Accounts)
  - T1562 (Impair Defenses)
  - T1552 (Unsecured Credentials)
- **Tactic**: 
  - Initial Access
  - Privilege Escalation
  - Defense Evasion

## Lessons Learned
- Importance of rapid detection of multiple failed login attempts
- Need for immediate response to anonymous user authentication
- Critical to monitor and restrict privilege escalation
- Implement comprehensive logging and real-time alerting
- Conduct thorough user access review and security awareness training

