## 📌 Incident 10: RDP Brute Force Attack

---

## i) Incident Summary

- **Event ID:** 234  
- **Event Time:** March 07, 2024 – 11:44 AM  
- **Severity:** High  
- **Detection Rule:** SOC176 - RDP Brute Force Detected  
- **Incident Type:** Brute Force / Unauthorized Remote Access  
- **Verdict:** True Positive  

### Description

An alert was triggered indicating multiple failed Remote Desktop Protocol (RDP) login attempts from an external IP address.  

Investigation confirmed a successful brute-force attack, where the attacker gained unauthorized access after multiple authentication attempts. Further analysis revealed suspicious post-login activity and outbound communication suggesting possible command-and-control (C2) interaction.

Due to confirmed unauthorized access, the incident was classified as **High severity**.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Investigation (SOC176)
- Log Management & Authentication Log Review
- Traffic Analysis
- IP Reputation Check
- Endpoint Log Analysis
- Device Containment

### External Threat Intelligence Tools:
- VirusTotal (IP reputation analysis)
- ANY.RUN (if post-compromise malware behavior observed)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 234.
- Confirmed detection triggered by rule SOC176.
- Identified high number of failed RDP login attempts.

---

### 2. Log Management & Authentication Analysis

- Reviewed Windows Security Event Logs:
  - Multiple failed login attempts (Event ID 4625).
  - Followed by successful login (Event ID 4624).
- Identified source IP responsible for repeated attempts.
- Determined attack pattern consistent with brute-force activity.

---

### 3. Traffic Analysis

- Analyzed inbound network traffic.
- Confirmed traffic direction:
  - External → Internal (targeting RDP service).
- Checked for abnormal session duration and unusual login times.

---

### 4. IP Reputation & Enrichment

- Submitted suspicious source IP to VirusTotal.
  - Identified malicious reputation indicators.
- Enriched IP data with contextual threat intelligence.

---

### 5. Scope Determination

- Checked whether:
  - Other systems were targeted.
  - Lateral movement occurred.
- Reviewed additional login attempts across environment.

---

### 6. Post-Compromise Activity Analysis

- Reviewed endpoint logs for:
  - Suspicious command execution.
  - Creation of new user accounts.
  - Privilege escalation attempts.

- Analyzed browser history and network logs.
- Detected suspicious outbound traffic indicating possible C2 interaction.

---

### 7. Containment & Mitigation

- Immediately isolated the compromised system.
- Disabled compromised user account.
- Forced password reset.
- Blocked malicious source IP.
- Recommended enabling:
  - Multi-Factor Authentication (MFA)
  - Account lockout policies
  - RDP access restrictions
  - Network-level authentication (NLA)

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Suspicious external IP address
- Multiple failed RDP login attempts
- Successful login after brute-force attempts
- Suspicious outbound traffic post-login

### Evidence Collected

- Windows authentication logs (Event IDs 4624 & 4625)
- Network traffic logs
- IP reputation results
- Endpoint activity logs

---

## v) Root Cause, Impact & Resolution

### Root Cause

Weak password or lack of strong authentication controls allowed successful brute-force compromise of RDP service.

---

### Impact

- Unauthorized remote access
- Potential data access or manipulation
- Risk of lateral movement
- Suspicious outbound communication suggesting possible malware deployment

---

### Resolution Steps

1. Confirmed brute-force activity and successful login.
2. Identified malicious source IP.
3. Contained compromised system.
4. Reset affected credentials.
5. Blocked malicious IP address.
6. Implemented stronger RDP security controls.
7. Recommended enabling MFA and account lockout policies.

---

## Lessons Learned

This investigation improved my ability to:

- Analyze Windows authentication logs
- Identify brute-force attack patterns
- Correlate login events with network activity
- Detect post-compromise behavior
- Implement defensive hardening measures

---

## Final Conclusion

This alert was confirmed as a **High-Severity True Positive RDP brute-force attack**.  

The attacker successfully gained unauthorized access through repeated login attempts. Prompt detection and containment prevented further lateral movement and reduced the overall impact of the compromise.
