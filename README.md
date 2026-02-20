# 🔐(1) LetsDefend SOC Investigation Report 

## 📌 Incident 1: CVE-2024-49138 Exploitation Detected

---

## i) Incident Summary

- **Event ID:** 313  
- **Event Time:** January 22, 2025 – 02:37 AM  
- **Detection Rule:** SOC335 - CVE-2024-49138 Exploitation Detected  
- **Incident Type:** Exploitation / Malware Delivery  
- **Verdict:** True Positive  

### Description

An alert was triggered for a potential exploitation attempt related to CVE-2024-49138.  
Investigation confirmed that the attacker attempted to gain access and successfully downloaded a malicious file. Further analysis revealed suspicious network activity indicating possible Command-and-Control (C2) communication.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Rule Investigation (SOC335)
- Endpoint Log Analysis
- Network Traffic Analysis
- Malware Analysis Section
- Playbook Execution
- Endpoint Containment

### External Threat Intelligence Tools:
- VirusTotal (Hash & reputation analysis)
- ANY.RUN (Dynamic malware sandbox analysis)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 313.
- Confirmed detection triggered by rule SOC335.
- Identified activity related to CVE-2024-49138 exploitation attempt.

### 2. Log Analysis
- Checked endpoint logs for:
  - Suspicious process execution
  - Unauthorized file download
  - Potential persistence behavior

- Reviewed network logs to:
  - Identify suspicious outbound connections
  - Detect potential C2 communication

### 3. Malware Analysis
- Extracted suspicious file hash.
- Submitted hash to VirusTotal.
  - Multiple security vendors flagged the file as malicious.
- Uploaded sample to ANY.RUN.
  - Observed malicious behavior.
  - Detected outbound communication to suspicious infrastructure.

### 4. Playbook Execution
- Checked if someone requested the C2.
- Analyzed malware behavior.
- Verified whether the malware was quarantined or cleaned.

### 5. Containment
- Identified affected endpoint device.
- Isolated the device from the network.
- Prevented further lateral movement and potential data exfiltration.

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)
- Malicious file hash (identified via VirusTotal)
- Suspicious outbound IP connection (possible C2 server)
- Exploitation activity linked to CVE-2024-49138
- Malicious file download event in endpoint logs

### Evidence Collected
- Endpoint process execution logs
- Network traffic logs
- VirusTotal detection results
- ANY.RUN behavioral analysis report

---

## v) Root Cause, Impact & Resolution

### Root Cause
The target system was vulnerable to CVE-2024-49138, which allowed the attacker to exploit the system and deliver malware.

### Impact
- Successful malicious file download
- Attempted C2 communication
- Risk of further compromise if not contained

### Resolution Steps
1. Isolated the infected endpoint.
2. Verified malware detection and classification.
3. Blocked identified malicious IP/domain indicators.
4. Recommended patching the vulnerability (CVE-2024-49138).
5. Strengthened monitoring rules for similar exploit attempts.

---

## Final Conclusion

This incident was confirmed as a **True Positive**.  
The exploitation attempt successfully delivered malware; however, timely detection, thorough investigation, and endpoint containment prevented further damage.
