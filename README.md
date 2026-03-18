# Access Log Threat Hunt

A Node.js-based log analysis tool that detects suspicious activity in web server access logs, simulating real Tier 1 SOC analyst workflows.

---

## 🔍 Overview

This project analyzes HTTP access logs and identifies potential security threats such as:

- SQL Injection attempts
- Cross-Site Scripting (XSS)
- Directory traversal attacks
- Access to sensitive files
- Known scanning tools (e.g., sqlmap, nmap)
- High-volume IP activity (possible brute force or scanning)

---

## 🚨 Detection Capabilities

| Threat Type           | Description |
|----------------------|------------|
| SQL Injection        | Detects common injection patterns (`UNION SELECT`, `OR 1=1`) |
| XSS                  | Flags script injection attempts (`<script>`, `javascript:`) |
| Directory Traversal  | Detects `../` path manipulation |
| Sensitive Files      | Access attempts to `.env`, `.git`, config files |
| Scanner Detection    | Identifies known tools via User-Agent |
| High Volume IPs      | Flags IPs with excessive requests |

---

## ⚙️ How It Works

1. Parses each log line into structured data
2. Applies regex-based threat detection rules
3. Tracks IP request frequency
4. Outputs detected threats and suspicious activity

---

## 📂 Output

The script generates:

- `alerts.json` → Detected threats
- `ip_summary.json` → Request counts per IP

---

## 🧠 SOC Relevance

This project demonstrates:

- Log parsing and normalization
- Threat detection using pattern matching
- Basic behavioral analysis (IP activity tracking)
- Security-focused scripting in Node.js

---

## 🚀 Future Improvements

- Add geolocation lookup for IPs
- Integrate with SIEM tools (Splunk/Wazuh)
- Real-time log monitoring
- Alert severity scoring system

---

## 📌 Tech Stack

- Node.js
- Regex-based detection
- File system processing

---

## 📎 Note

This project is part of my cybersecurity portfolio as I prepare for a Tier 1 SOC Analyst role.
