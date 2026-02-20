## 📌 Incident 5: Windows OLE Zero-Click RCE Exploitation (CVE-2025-21298)

---

## i) Incident Summary

- **Event ID:** 314  
- **Event Time:** February 04, 2025 – 04:18 PM  
- **Severity:** Critical  
- **Detection Rule:** SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)  
- **Incident Type:** Malware / Remote Code Execution (RCE) / Email-Based Exploitation  
- **Verdict:** True Positive  

### Description

An alert was triggered for exploitation of **CVE-2025-21298**, a critical Windows OLE zero-click Remote Code Execution vulnerability.  

The investigation confirmed that malicious content was delivered through email. The user interacted with the malicious content, leading to successful malware execution and command-and-control (C2) communication.

This incident was classified as **Critical severity** due to successful exploitation and confirmed C2 interaction.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Investigation (SOC336)
- Endpoint Log Analysis
- Network Traffic Log Review
- Browser History Analysis
- Malware Analysis Section
- Device Containment

### External Threat Intelligence & Research Tools:
- VirusTotal (hash and domain reputation analysis)
- ANY.RUN (dynamic malware sandbox analysis)
- NVD - nvd.nist.gov (CVE research and validation)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 314.
- Confirmed detection triggered by rule SOC336.
- Identified exploitation attempt related to CVE-2025-21298.

---

### 2. Initial Log Analysis

- Checked endpoint logs for:
  - Suspicious process execution
  - OLE-related abnormal behavior
  - Newly created or modified files

- Reviewed email delivery logs to confirm malicious attachment delivery.

---

### 3. User Interaction Verification

- Confirmed the user opened/clicked the malicious file.
- Investigated browser history for suspicious redirects.
- Reviewed network logs for outbound connections.

---

### 4. Command-and-Control (C2) Verification

- Analyzed network traffic logs.
- Confirmed successful outbound communication to suspicious infrastructure.
- Verified that C2 interaction was successfully established.

---

### 5. Malware Analysis

- Extracted file hash.
- Submitted hash to VirusTotal.
  - Multiple vendors flagged it as malicious.
- Uploaded sample to ANY.RUN.
  - Observed malicious execution behavior.
  - Identified C2 communication attempts.

---

### 6. Containment & Mitigation

- Immediately isolated the compromised endpoint.
- Verified whether malware was quarantined or removed.
- Recommended patching the Windows system to address CVE-2025-21298.
- Suggested blocking malicious IPs/domains.

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Malicious email attachment exploiting CVE-2025-21298
- Suspicious outbound C2 connection
- Malicious file hash (identified via VirusTotal)
- Abnormal OLE-related process execution

### Evidence Collected

- Endpoint process execution logs
- Email delivery logs
- Browser history records
- Network traffic logs confirming C2 interaction
- Malware behavioral analysis (ANY.RUN)
- CVE documentation (NVD reference)

---

## v) Root Cause, Impact & Resolution

### Root Cause

The system was vulnerable to CVE-2025-21298 (Windows OLE Zero-Click RCE).  
Malicious content delivered via email was executed after user interaction, resulting in remote code execution and C2 communication.

---

### Impact

- Successful malware execution
- Confirmed C2 communication
- High risk of data exfiltration
- Potential lateral movement
- Full system compromise risk

---

### Resolution Steps

1. Confirmed malicious email and user interaction.
2. Identified and validated malware through threat intelligence.
3. Verified successful C2 communication.
4. Isolated the compromised endpoint.
5. Blocked malicious network indicators.
6. Recommended immediate patching of CVE-2025-21298.
7. Strengthened email security controls.

---

## Lessons Learned

This critical investigation improved my ability to:

- Handle zero-click and OLE-based RCE vulnerabilities
- Confirm C2 communication success
- Correlate browser history with network logs
- Conduct full-scope endpoint compromise analysis
- Respond quickly to high-severity malware incidents

---

## Final Conclusion

This alert was confirmed as a **Critical True Positive malware exploitation incident**.  

The attacker successfully exploited CVE-2025-21298 via email delivery, resulting in malware execution and confirmed C2 communication. Immediate containment actions reduced further risk and prevented potential lateral movement within the network.
