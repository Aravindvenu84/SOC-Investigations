## 📌 Incident 9: Phishing Alert – Deceptive Mail Detected

---

## i) Incident Summary

- **Event ID:** 257  
- **Event Time:** May 13, 2024 – 09:22 AM  
- **Severity:** Medium  
- **Detection Rule:** SOC282 - Phishing Alert - Deceptive Mail Detected  
- **Incident Type:** Phishing / Email-Based Malware Delivery  
- **Verdict:** True Positive  

### Description

An alert was triggered indicating a deceptive phishing email targeting users within the organization.  

Investigation confirmed that the phishing attempt was successful, as the user interacted with the malicious content. Further analysis revealed malware execution and confirmed command-and-control (C2) communication.

Although categorized as Medium severity in detection, the confirmed compromise increased the risk level due to successful user interaction.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Investigation (SOC282)
- Email Log Analysis (Exchange)
- Mail Delivery Tracking
- Endpoint Log Review
- Network Traffic Analysis
- Browser History Investigation
- Device Containment

### External Threat Intelligence Tools:
- VirusTotal (URL, IP, and file hash analysis)
- ANY.RUN (dynamic malware behavior analysis)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 257.
- Confirmed detection triggered by rule SOC282.
- Identified suspicious phishing email indicators.

---

### 2. Email Delivery & Header Analysis

- Verified whether the malicious email was delivered.
- Checked:
  - Sender details
  - Email headers
  - Embedded URLs
  - Attachments
- Confirmed presence of malicious URL/attachment.

---

### 3. User Interaction Verification

- Confirmed that the user opened the email.
- Verified that the malicious link/file was clicked.
- Correlated timestamps with endpoint activity logs.

---

### 4. Endpoint & Execution Analysis

- Reviewed endpoint logs for:
  - Suspicious process execution
  - New file creation
  - Abnormal system behavior

- Investigated browser history for:
  - Redirects to suspicious domains
  - Download activity

---

### 5. Command-and-Control (C2) Confirmation

- Analyzed outbound network traffic logs.
- Identified suspicious external connections.
- Confirmed successful C2 communication.

---

### 6. Threat Intelligence & Malware Analysis

- Submitted suspicious URL and/or file hash to VirusTotal.
  - Multiple vendors flagged malicious indicators.
- Uploaded sample (if available) to ANY.RUN.
  - Observed malicious behavior and external communication attempts.

---

### 7. Containment & Mitigation

- Isolated the compromised system.
- Blocked malicious domains and IP addresses.
- Deleted phishing email from mailboxes.
- Recommended credential reset for affected user.
- Suggested strengthening email filtering rules.

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Malicious phishing email
- Suspicious URL/attachment
- Malicious file hash (identified via VirusTotal)
- Confirmed outbound C2 communication
- Abnormal endpoint process activity

### Evidence Collected

- Email header and delivery logs
- Endpoint process execution logs
- Browser history records
- Network traffic logs confirming C2 interaction
- Malware behavioral report (ANY.RUN)

---

## v) Root Cause, Impact & Resolution

### Root Cause

A deceptive phishing email bypassed email filtering controls and was delivered to the user. The user interacted with malicious content, leading to malware execution and C2 communication.

---

### Impact

- Successful phishing compromise
- Malware execution on endpoint
- Confirmed C2 interaction
- Risk of credential theft and data exfiltration

---

### Resolution Steps

1. Confirmed phishing delivery and user interaction.
2. Validated malicious indicators using threat intelligence tools.
3. Confirmed C2 communication.
4. Isolated the compromised endpoint.
5. Blocked malicious network indicators.
6. Reset user credentials.
7. Strengthened phishing detection mechanisms.

---

## Lessons Learned

This investigation improved my ability to:

- Perform full phishing-to-compromise analysis
- Correlate email, endpoint, and network logs
- Confirm C2 communication
- Respond effectively to user-driven compromises
- Strengthen defensive email monitoring

---

## Final Conclusion

This alert was confirmed as a **True Positive phishing incident**.  

The phishing email successfully compromised the endpoint, resulting in malware execution and confirmed C2 communication. Immediate containment and remediation actions minimized further damage and reduced organizational risk.
