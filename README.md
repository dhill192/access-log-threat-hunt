# Access Log Threat Hunt

A Node.js log analysis tool that parses web server access logs and flags suspicious activity commonly reviewed in a Tier 1 SOC workflow.

## Overview

This project reads HTTP access logs, extracts useful request data, and applies simple detection logic to identify potentially malicious behavior.

The current version looks for:

- SQL injection patterns
- Cross-site scripting (XSS) attempts
- Directory traversal activity
- Requests for sensitive files
- Known scanner or automation user agents
- High-volume IP activity that may suggest scanning or brute-force behavior

## What It Does

The script:

- Parses each access log line into structured fields
- Applies regex-based detection rules to request paths and user agents
- Tracks request volume by source IP
- Writes findings to output files for review

## Detection Coverage

| Threat Type | What It Looks For |
|---|---|
| SQL Injection | Patterns such as `UNION SELECT`, `' OR 1=1`, and similar query manipulation |
| XSS | Script-related payloads such as `<script>` or `javascript:` |
| Directory Traversal | Requests containing `../` or similar traversal patterns |
| Sensitive File Access | Attempts to reach files like `.env`, `.git`, or config-related paths |
| Scanner Detection | User agents associated with tools such as `sqlmap` or `nmap` |
| High-Volume IPs | Unusually high request counts from a single IP |

## Tech Stack

- Node.js
- JavaScript
- Regular expressions
- File system processing

## How to Run It

1. Clone the repository
2. Make sure Node.js is installed
3. Place or confirm the sample log file in the expected location
4. Run the script:

```bash
node analyzer.js --in sample_logs/access.log
