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

## How It Works
### Step 1: Set Up Localhost with XAMPP
1. Download and install **XAMPP** from [Apache Friends](https://www.apachefriends.org/index.html).
2. Start **Apache** and **MySQL** from the XAMPP Control Panel.
3. Place your test web application in the `htdocs` folder (e.g., `C:\xampp\htdocs\myapp`).
4. Access the application using `http://localhost/myapp`.

### Step 2: Install Required Tools
Ensure the following tools are installed and running:
- **OWASP ZAP** on `localhost:8081`
- **Burp Suite** on `localhost:8082`
- **Metasploit**
- **Wireshark (Tshark)**
- **SQLMap**

### Step 3: Configure the Project
Edit the configuration variables in the script as per your setup:
```python
TARGET_URL = "http://localhost:80"
ZAP_API_KEY = "your_zap_api_key"
ZAP_URL = "http://localhost:8081"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "your_nvd_api_key"
BURP_API_URL = "http://localhost:8082/v0.1"
BURP_API_KEY = "your_burp_api_key"
```

### Step 4: Run the Security Assessment
Run the script using the following command:
```bash
python main.py
```
The following steps will be performed automatically:

1. **Fetch Latest Vulnerabilities**: The script uses the **NVD API** to get the latest known vulnerabilities.
2. **OWASP ZAP Spider and Active Scan**: Scans the application to find vulnerabilities.
3. **SQLMap Testing**: SQL injection testing is performed using **SQLMap**.
4. **Burp Suite Scan**: A Burp Suite active scan is initiated.
5. **Metasploit Exploitation**: Attempts to exploit vulnerabilities using **Metasploit**.
6. **Log Analysis**: The script scans MySQL logs and system logs to identify anomalies.
7. **Network Capture**: **Tshark** captures up to 1000 packets for analysis.
8. **Generate Report**: A detailed security report is generated.

### Step 5: Review the Report
The final report will be saved in the project directory as `security_report_<timestamp>.txt`. Example output:
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

