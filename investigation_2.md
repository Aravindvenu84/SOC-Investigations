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
