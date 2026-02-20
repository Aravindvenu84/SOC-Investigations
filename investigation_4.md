## 📌 Incident 4: Arbitrary File Read on Check Point Security Gateway (CVE-2024-24919)

---

## i) Incident Summary

- **Event ID:** 263  
- **Event Time:** June 06, 2024 – 03:12 PM  
- **Severity:** High  
- **Detection Rule:** SOC287 - Arbitrary File Read on Checkpoint Security Gateway [CVE-2024-24919]  
- **Incident Type:** Web Attack / Arbitrary File Read / Zero-Day Exploitation  
- **Verdict:** True Positive  

### Description

An alert was triggered indicating exploitation of **CVE-2024-24919**, a critical zero-day vulnerability affecting Check Point Security Gateways.  

The vulnerability allows unauthenticated attackers to perform arbitrary file reads, potentially exposing sensitive system files and credentials.

Investigation confirmed malicious traffic targeting the security gateway.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Investigation (SOC287)
- Network Traffic Log Analysis
- Web Gateway Logs Review
- Endpoint Investigation
- Device Containment

### External Threat Intelligence & Research Tools:
- VirusTotal (IP/domain/hash reputation analysis)
- ANY.RUN (Behavioral analysis if applicable payload observed)
- NVD - nvd.nist.gov (CVE research and vulnerability validation)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 263.
- Confirmed detection triggered by rule SOC287.
- Identified activity linked to CVE-2024-24919 exploitation attempt.

---

### 2. Vulnerability Research
- Researched CVE-2024-24919 via NVD.
- Confirmed vulnerability allows:
  - Arbitrary file read
  - Potential exposure of sensitive files
- Determined severity as High due to data exposure risk.

---

### 3. Traffic Analysis

- Reviewed firewall and gateway logs.
- Determined:
  - Direction of traffic (external to internal).
  - Malicious HTTP requests targeting specific file paths.
- Confirmed traffic was not a planned security test.

---

### 4. Determining Attack Success

- Analyzed logs to identify:
  - Whether sensitive files were accessed.
  - If abnormal data transfer occurred.
- Concluded exploitation attempt occurred and required mitigation.

---

### 5. Threat Intelligence Analysis

- Checked suspicious IPs/domains in VirusTotal.
- Validated malicious indicators.
- Used ANY.RUN (if applicable artifacts observed) for behavioral insight.

---

### 6. Escalation & Containment

- Determined incident severity required mitigation.
- Contained the affected system.
- Recommended patching and updating Check Point Security Gateway.
- Suggested blocking identified malicious IP addresses.

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Suspicious external IP targeting gateway
- Malicious HTTP requests attempting file access
- Exploitation pattern consistent with CVE-2024-24919

### Evidence Collected

- Gateway traffic logs
- Web request logs
- Threat intelligence lookup results
- CVE documentation (NVD reference)

---

## v) Root Cause, Impact & Resolution

### Root Cause

The Check Point Security Gateway was vulnerable to CVE-2024-24919, allowing attackers to attempt arbitrary file read exploitation.

---

### Impact

- Potential exposure of sensitive system files
- Risk of credential leakage
- Increased risk of follow-up attacks

---

### Resolution Steps

1. Confirmed malicious traffic targeting the gateway.
2. Contained the affected system.
3. Blocked malicious IP addresses.
4. Recommended immediate patching of CVE-2024-24919.
5. Strengthened monitoring for similar web exploitation attempts.
6. Evaluated need for Tier 2 escalation.

---

## Lessons Learned

This investigation enhanced my understanding of:

- Web-based exploitation techniques
- Arbitrary file read vulnerabilities
- Gateway log analysis
- Traffic direction analysis
- Incident mitigation procedures

---

## Final Conclusion

This alert was confirmed as a **True Positive High-Severity Web Attack**.  

Exploitation attempts targeting CVE-2024-24919 were detected and mitigated. Immediate containment and remediation actions reduced the risk of sensitive data exposure.
