## 📌 Incident 3: Impersonating Domain MX Record Change (Phishing Attack)

---

## i) Incident Summary

- **Event ID:** 304  
- **Event Time:** September 17, 2024 – 12:05 PM  
- **Detection Rule:** SOC326 - Impersonating Domain MX Record Change Detected  
- **Incident Type:** Phishing / Email Spoofing / Domain Impersonation  
- **Verdict:** True Positive  

### Description

An alert was triggered indicating a suspicious MX record change attempt involving domain impersonation.  

Investigation confirmed this was a phishing attack designed to impersonate a legitimate domain and trick users into interacting with malicious links or attachments.

This incident required detailed email security analysis and threat intelligence validation.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Email Security Log Analysis
- Alert Investigation (SOC326)
- Mail Delivery Tracking
- URL & Attachment Analysis Section
- Endpoint Investigation
- Device Containment

### External Threat Intelligence Tools:
- VirusTotal (URL and file reputation analysis)
- ANY.RUN (Dynamic analysis of suspicious attachments/URLs)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 304.
- Confirmed detection triggered by rule SOC326.
- Identified potential domain impersonation and phishing activity.

---

### 2. Email Security Analysis

- Checked whether the malicious email was delivered to users.
- Verified:
  - Sender domain
  - MX record anomalies
  - Email headers
  - SPF/DKIM/DMARC alignment (if applicable)

- Analyzed:
  - Embedded URLs
  - Attachments
  - Timestamps
  - User interaction logs

---

### 3. User Activity Investigation

- Checked if any user:
  - Opened the malicious email
  - Clicked the URL
  - Downloaded or executed attachments

- Reviewed endpoint logs for suspicious behavior following email interaction.

---

### 4. Threat Intelligence & Malware Analysis

- Submitted suspicious URLs and/or file hashes to VirusTotal.
  - Confirmed malicious reputation indicators.

- Used ANY.RUN to analyze:
  - Attachment behavior (if present)
  - URL redirection behavior
  - Potential credential harvesting activity

---

### 5. Containment & Remediation

- Contained the affected system (if user interaction occurred).
- Deleted the phishing email from mailboxes.
- Blocked malicious URLs/domains.
- Recommended user awareness reinforcement.

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Malicious phishing email
- Suspicious impersonated domain
- Malicious URL embedded in email
- Potential malicious attachment (if present)

### Evidence Collected

- Email header analysis
- Mail server delivery logs
- URL reputation results (VirusTotal)
- Behavioral analysis report (ANY.RUN)
- Endpoint activity logs

---

## v) Root Cause, Impact & Resolution

### Root Cause

An attacker attempted domain impersonation by manipulating or spoofing MX-related configurations to conduct a phishing campaign targeting internal users.

---

### Impact

- Risk of credential harvesting
- Potential malware infection
- Possible business email compromise (BEC)
- Organizational email trust abuse

---

### Resolution Steps

1. Identified and confirmed phishing activity.
2. Deleted malicious emails from affected inboxes.
3. Contained any impacted endpoints.
4. Blocked malicious URLs and domains.
5. Recommended strengthening email security policies.
6. Suggested enhanced phishing awareness training.

---

## Lessons Learned

This investigation significantly improved my skills in:

- Email header analysis
- Phishing detection techniques
- Domain impersonation identification
- Threat intelligence validation
- Incident containment procedures

---

## Final Conclusion

This alert was confirmed as a **True Positive phishing attack** involving domain impersonation.  

Timely investigation, email deletion, and endpoint containment prevented further compromise and reduced the risk of credential theft or malware infection.
