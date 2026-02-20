## 📌 Incident 7: Palo Alto Networks PAN-OS Command Injection Exploitation (CVE-2024-3400)

---

## i) Incident Summary

- **Event ID:** 249  
- **Event Time:** April 18, 2024 – 03:09 AM  
- **Severity:** Critical  
- **Detection Rule:** SOC274 - Palo Alto Networks PAN-OS Command Injection Vulnerability Exploitation (CVE-2024-3400)  
- **Incident Type:** Web Attack / Command Injection / Firewall Exploitation  
- **Verdict:** True Positive  

### Description

An alert was triggered indicating exploitation of **CVE-2024-3400**, a critical command injection vulnerability affecting Palo Alto Networks PAN-OS software.  

The vulnerability allows attackers to execute arbitrary commands on affected firewall devices without authentication under certain conditions.

Investigation confirmed malicious traffic targeting the firewall, with signs of successful exploitation and command-and-control (C2) communication.

Due to the security device being targeted, this incident was classified as **Critical severity**.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Investigation (SOC274)
- Firewall Log Analysis
- Network Traffic Monitoring
- Endpoint Investigation (if internal pivot suspected)
- Device Containment

### External Threat Intelligence & Research Tools:
- VirusTotal (IP/domain/hash reputation analysis)
- ANY.RUN (behavioral analysis if payload observed)
- NVD - nvd.nist.gov (CVE research and vulnerability validation)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 249.
- Confirmed detection triggered by rule SOC274.
- Identified exploitation attempt related to CVE-2024-3400.

---

### 2. Vulnerability Research

- Researched CVE-2024-3400 using NVD.
- Confirmed vulnerability allows:
  - Command injection
  - Remote code execution on firewall devices
- Determined severity as Critical due to perimeter device exposure.

---

### 3. Traffic Direction & Validation

- Analyzed firewall and network logs.
- Determined traffic direction:
  - External → Internal (targeting firewall management interface).
- Verified activity was not a planned security test.
- Confirmed malicious payload patterns in HTTP requests.

---

### 4. Determining Attack Success

- Checked logs for:
  - Abnormal command execution
  - Suspicious system-level activity
  - Unexpected outbound connections
- Identified indicators suggesting successful exploitation attempt.

---

### 5. C2 Communication Verification

- Reviewed network logs for outbound connections.
- Identified suspicious external communication.
- Confirmed successful C2 interaction through log correlation.

---

### 6. Threat Intelligence Analysis

- Checked suspicious IPs/domains using VirusTotal.
- Validated malicious reputation indicators.
- Used ANY.RUN (if payload observed) for behavior analysis.

---

### 7. Escalation & Containment

- Determined incident required immediate mitigation.
- Contained the affected system.
- Recommended:
  - Immediate patching of PAN-OS
  - Restricting management interface exposure
  - Blocking malicious IP addresses
  - Reviewing firewall configurations

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Suspicious external IP targeting firewall
- Malicious command injection patterns in HTTP requests
- Abnormal outbound communication (C2)
- Exploitation behavior consistent with CVE-2024-3400

### Evidence Collected

- Firewall traffic logs
- Web request logs
- Network outbound connection logs
- Threat intelligence lookup results
- CVE documentation (NVD reference)

---

## v) Root Cause, Impact & Resolution

### Root Cause

The firewall device was vulnerable to CVE-2024-3400, a critical command injection flaw in PAN-OS, allowing attackers to execute arbitrary commands.

---

### Impact

- Potential full firewall compromise
- Risk of lateral movement inside the network
- Possible data interception or manipulation
- Confirmed C2 communication attempt

---

### Resolution Steps

1. Confirmed malicious command injection attempt.
2. Verified exploitation indicators through log correlation.
3. Contained the affected system.
4. Blocked malicious external IP addresses.
5. Recommended urgent patching of PAN-OS.
6. Restricted public access to management interfaces.
7. Evaluated need for Tier 2 escalation.

---

## Lessons Learned

This investigation enhanced my ability to:

- Analyze firewall exploitation attempts
- Detect command injection patterns
- Validate traffic direction in perimeter attacks
- Confirm C2 activity via network log correlation
- Handle critical infrastructure-targeted incidents

---

## Final Conclusion

This alert was confirmed as a **Critical True Positive web attack** targeting a firewall device.  

The exploitation of CVE-2024-3400 posed a severe risk to the organization's perimeter security. Immediate containment and mitigation steps significantly reduced the risk of further compromise.
