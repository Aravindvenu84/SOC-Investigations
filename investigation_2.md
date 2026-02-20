## 📌 Incident 2: SharePoint ToolShell Zero-Day Exploitation (CVE-2025-53770)

---

## i) Incident Summary

- **Event ID:** 320  
- **Event Time:** July 22, 2025 – 01:07 PM  
- **Detection Rule:** SOC342 - CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE  
- **Incident Type:** Zero-Day Exploitation / Authentication Bypass / Remote Code Execution (RCE)  
- **Verdict:** True Positive  

### Description

A critical zero-day vulnerability known as **ToolShell (CVE-2025-53770)** was identified in on-premises Microsoft SharePoint Server deployments.  

The vulnerability allows authentication bypass and remote code execution (RCE), potentially enabling attackers to gain unauthorized access and execute arbitrary code on the affected system.

The investigation confirmed malicious activity associated with this vulnerability.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Investigation (SOC342)
- Endpoint Log Analysis
- Network Traffic Log Review
- Device Containment Feature

### External Threat Intelligence & Research Tools:
- VirusTotal (domain and hash reputation analysis)
- ANY.RUN (dynamic malware behavior analysis)
- NVD - nvd.nist.gov (vulnerability research and CVE analysis)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 320.
- Identified detection triggered by rule SOC342.
- Confirmed alert related to CVE-2025-53770 (ToolShell zero-day).

---

### 2. Vulnerability Research
- Researched CVE-2025-53770 using NVD (nvd.nist.gov).
- Confirmed it allows:
  - Authentication bypass
  - Remote Code Execution (RCE)
- Determined this is a high-impact critical vulnerability.

---

### 3. Log Analysis

- Checked SharePoint server logs for:
  - Suspicious authentication attempts
  - Abnormal POST requests
  - Unauthorized access patterns

- Analyzed network logs to:
  - Identify suspicious outbound communication
  - Detect possible command-and-control (C2) connections

- Identified suspicious domain:
  -mail.mailerhost.net




---

### 4. Threat Intelligence Analysis

- Checked domain reputation in VirusTotal.
  - Identified suspicious/malicious indicators.
- Used ANY.RUN (if applicable sample was available) to analyze related behavior.
  - Observed malicious communication patterns.

---

### 5. Determination of Impact

- Confirmed exploitation attempt.
- Identified signs of system compromise.
- Determined attacker leveraged authentication bypass to execute malicious activity.

---

### 6. Containment

- Isolated the compromised SharePoint server.
- Prevented further attacker interaction.
- Recommended patching and applying Microsoft security updates.
- Suggested blocking identified malicious domain indicators.

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Suspicious domain:
  - `mail.mailerhost[.]net`
- Exploitation activity related to CVE-2025-53770
- Unauthorized authentication behavior in logs
- Suspicious outbound traffic from SharePoint server

### Evidence Collected

- Authentication logs
- Web server request logs
- Network traffic logs
- Threat intelligence lookup results
- CVE documentation from NVD

---

## v) Root Cause, Impact & Resolution

### Root Cause

The SharePoint server was vulnerable to CVE-2025-53770 (ToolShell), a critical zero-day vulnerability enabling authentication bypass and remote code execution.

---

### Impact

- Unauthorized access to SharePoint server
- Potential remote code execution
- Risk of data compromise and lateral movement
- Possible persistence establishment

---

### Resolution Steps

1. Contained the compromised SharePoint system.
2. Blocked malicious domain indicators.
3. Recommended immediate patching of the vulnerability.
4. Conducted log review for additional persistence mechanisms.
5. Strengthened monitoring for authentication anomalies.

---

## Lessons Learned

This was one of the first major zero-day exploitation investigations I handled.  
Although challenging, it significantly improved my skills in:

- Log analysis
- Vulnerability research
- Threat intelligence usage
- Incident containment procedures

---

## Final Conclusion

This alert was confirmed as a **True Positive**.  
The SharePoint server was exploited through a critical zero-day vulnerability (CVE-2025-53770). Immediate containment actions helped prevent further damage and potential data compromise.
