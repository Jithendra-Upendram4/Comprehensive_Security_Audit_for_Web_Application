# Cybersecurity Automation Toolkit

## Overview
This project is a comprehensive **Cybersecurity Automation Toolkit** designed to streamline security assessments by automating vulnerability scanning, penetration testing, and forensic analysis. It integrates powerful tools like **OWASP ZAP**, **SQLMap**, **Burp Suite**, **Metasploit**, and **Wireshark (Tshark)** for complete end-to-end security evaluations.

## Features
- ✅ Automated Vulnerability Scanning using OWASP ZAP and Burp Suite.
- ✅ SQL Injection Detection with SQLMap.
- ✅ Exploit Vulnerabilities using Metasploit.
- ✅ Network Traffic Capture and Analysis using Tshark.
- ✅ Forensic Log Analysis for Threat Detection.
- ✅ Latest Vulnerability Updates from NVD API.
- ✅ Comprehensive Security Report Generation.

## Prerequisites
Ensure the following tools are installed:
- Python 3.8+
- OWASP ZAP (localhost:8081)
- SQLMap
- Burp Suite (localhost:8082)
- Metasploit Framework
- Wireshark (Tshark)

Install necessary Python packages using:
```bash
pip install aiohttp aiofiles python-owasp-zap-v2
```

## Configuration
Edit the configuration variables in the script:
```python
TARGET_URL = "http://localhost:80"
ZAP_API_KEY = "your_zap_api_key"
ZAP_URL = "http://localhost:8081"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "your_nvd_api_key"
BURP_API_URL = "http://localhost:8082/v0.1"
BURP_API_KEY = "your_burp_api_key"
```

## Usage
Run the script with:
```bash
python main.py
```
The script will perform the following:
1. Fetch latest vulnerabilities from NVD API.
2. Perform OWASP ZAP spider and active scans.
3. Execute a Burp Suite active scan.
4. Test for SQL injection using SQLMap.
5. Perform exploitation with Metasploit.
6. Analyze MySQL and system logs for suspicious activities.
7. Capture network traffic using Tshark.
8. Generate a detailed security report.

## Example Report Output
```
==== Security Assessment Report ====
Date: 2025-03-29 14:30:45

== Detected Vulnerabilities ==
- Alert: SQL Injection
  Risk: High
  URL: http://localhost:80/login

== Forensics Analysis ==
Suspicious log entries detected:
[ALERT] Unauthorized access attempt detected in /var/log/auth.log
```

## Troubleshooting
- Ensure that OWASP ZAP, Burp Suite, and Metasploit services are running.
- Verify the API keys and URLs in the configuration.
- Check network access and firewall settings.

## Contribution
Contributions are welcome! Feel free to submit pull requests or report issues.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

