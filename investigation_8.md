## 📌 Incident 8: SQL Injection Web Attack

---

## i) Incident Summary

- **Event ID:** 235  
- **Event Time:** March 07, 2024 – 12:51 PM  
- **Severity:** High  
- **Detection Rule:** SOC127 - SQL Injection Detected  
- **Incident Type:** Web Attack / SQL Injection  
- **Verdict:** True Positive  

### Description

An alert was triggered indicating a SQL Injection attack targeting a web application.  

Investigation confirmed malicious SQL payloads were sent from an external source attempting to manipulate backend database queries. The attack posed a high risk of unauthorized data access and database compromise.

This incident was classified as **High severity** due to potential data exposure and application compromise risk.

---

## ii) Tools & Features Used in LetsDefend.io

### LetsDefend Platform Tools:
- Alert Investigation (SOC127)
- Web Server Log Analysis
- Network Traffic Monitoring
- Endpoint Investigation (if compromise suspected)
- Device Containment

### External Threat Intelligence Tools:
- VirusTotal (IP/domain reputation analysis)
- ANY.RUN (if payload or follow-up malware activity observed)

---

## iii) Step-by-Step Investigation Process

### 1. Alert Review
- Reviewed Event ID 235.
- Confirmed detection triggered by rule SOC127.
- Identified SQL injection patterns in web requests.

---

### 2. Traffic Direction & Validation

- Analyzed web server logs.
- Determined traffic direction:
  - External → Internal (targeting web application).
- Verified that activity was not part of a planned security test.
- Identified malicious SQL payload patterns such as:
  - `' OR 1=1 --`
  - UNION-based query attempts
  - Suspicious parameter manipulation

---

### 3. Determining Attack Success

- Checked application and database logs for:
  - Unauthorized query execution
  - Data retrieval anomalies
  - Unexpected database errors
- Investigated whether data extraction occurred.

---

### 4. Post-Exploitation & C2 Verification (If Applicable)

- Reviewed network logs for abnormal outbound connections.
- Checked endpoint logs for signs of follow-up malware.
- Investigated browser history and system logs if user interaction was involved.
- Confirmed whether any command-and-control (C2) communication occurred.

---

### 5. Threat Intelligence Analysis

- Checked suspicious source IP addresses using VirusTotal.
- Verified malicious reputation indicators.
- Used ANY.RUN if artifacts suggested follow-up payload execution.

---

### 6. Escalation & Containment

- Determined whether Tier 2 escalation was required.
- Contained affected systems if compromise indicators were detected.
- Recommended:
  - Web application patching
  - Input validation improvements
  - Implementation of prepared statements
  - Web Application Firewall (WAF) rule enhancement

---

## iv) Key Findings & IOCs

### Indicators of Compromise (IOCs)

- Suspicious external IP address
- Malicious SQL payload patterns in HTTP requests
- Abnormal database query attempts
- Potential unauthorized data access attempts

### Evidence Collected

- Web server access logs
- Application error logs
- Database query logs
- Network traffic logs
- Threat intelligence lookup results

---

## v) Root Cause, Impact & Resolution

### Root Cause

The web application was vulnerable to SQL Injection due to insufficient input validation and improper query handling.

---

### Impact

- Potential unauthorized database access
- Risk of sensitive data exposure
- Possible data manipulation or deletion
- Elevated risk of further exploitation

---

### Resolution Steps

1. Confirmed malicious SQL injection attempt.
2. Verified traffic originated externally.
3. Checked whether attack was successful.
4. Contained affected systems (if necessary).
5. Blocked malicious IP addresses.
6. Recommended secure coding practices (prepared statements, input validation).
7. Suggested Web Application Firewall tuning.

---

## Lessons Learned

This investigation strengthened my understanding of:

- SQL injection attack patterns
- Web application log analysis
- Traffic direction validation
- Post-exploitation detection
- Mitigation strategies for web-based attacks

---

## Final Conclusion

This alert was confirmed as a **High-Severity True Positive SQL Injection attack**.  

Timely detection and investigation reduced the risk of database compromise and helped improve defensive controls against future web application attacks.
