import os
import asyncio
import aiohttp
import re
import aiofiles
from zapv2 import ZAPv2
from datetime import datetime

# Configuration
TARGET_URL = "http://localhost:80"
ZAP_API_KEY = "aej247vl3rle1dqlk9f2jspl42"
ZAP_URL = "http://localhost:8081"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "87d9ff29-2dca-4105-a1ae-22ef1cc8290b"
BURP_API_URL = "http://localhost:8082/v0.1"
BURP_API_KEY = "zOHcvTjJUJIz2kYLflv2fzyNQMICyeKn"
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})

# --------------------------------------
# Fetch Latest Vulnerabilities from NVD
# --------------------------------------
async def fetch_latest_vulnerabilities():
    print("[*] Fetching latest vulnerabilities from NVD API...")
    params = {"resultsPerPage": 4, "apiKey": API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(NVD_API_URL, params=params) as response:
            if response.status == 200:
                data = await response.json()
                cve_list = []
                for item in data.get("vulnerabilities", []):
                    cve_id = item["cve"]["id"]
                    description = item["cve"]["descriptions"][0]["value"]
                    cve_list.append({"id": cve_id, "description": description})
                print("[+] Successfully fetched latest vulnerabilities.")
                return cve_list
            else:
                print(f"[-] Failed to fetch data from NVD API. Status Code: {response.status}")
                return []

# ------------------------ 
# SQLMap for SQL Injection
# ------------------------ 
def run_sqlmap(target_url):
    print("[*] Running SQLMap for SQL Injection Testing...")
    os.system(f"sqlmap -u {target_url} --batch --dbs")

# --------------------------
# OWASP ZAP Active Scan
# --------------------------
async def zap_active_scan(target_url):
    print("[*] Starting OWASP ZAP Active Scan...")

    try:
        # Ensure target URL is in context
        zap.core.access_url(target_url)
        zap.context.include_in_context("Default Context", target_url + ".*")

        # Start Active Scan
        scan_id = zap.ascan.scan(target_url)
        
        if not scan_id or scan_id == "0":
            print("[-] Failed to initiate Active Scan. Ensure ZAP is running and the API is accessible.")
            return
        
        print(f"[*] Active Scan initiated with Scan ID: {scan_id}")

        # Monitor Scan Progress
        while True:
            await asyncio.sleep(5)
            status = zap.ascan.status(scan_id)
            print(f"[*] Active Scan Status: {status}%")
            if status == "100":
                break
        
        print("[+] Active Scan Completed.")
    except Exception as e:
        print(f"[-] Error during OWASP ZAP Active Scan: {e}")



# ----------------------
# OWASP ZAP Spider Scan
# ----------------------
async def zap_spider(target_url):
    print("[*] Starting OWASP ZAP Spider Scan...")
    try:
        scan_id = zap.spider.scan(target_url)
        print(f"[*] Spider Scan initiated with Scan ID: {scan_id}")
        
        while True:
            await asyncio.sleep(5)
            status = zap.spider.status(scan_id)
            print(f"[*] Spider Scan Status: {status}%")
            if status == "100":
                break
        
        print("[+] Spider Scan Completed.")
    except Exception as e:
        print(f"[-] Error during OWASP ZAP Spider Scan: {e}")



# ------------------------------
# Fetch Results from OWASP ZAP
# ------------------------------
async def zap_get_results(latest_vulnerabilities):
    print("[*] Fetching Vulnerability Report from OWASP ZAP...")
    alerts = zap.core.alerts()
    vulnerability_list = []

    if alerts:
        print("[+] Found vulnerabilities:")
        for alert in alerts:
            print(f"[-] {alert['alert']} - {alert['risk']} Risk")
            print(f"    URL: {alert['url']}")
            print(f"    Description: {alert['description']}")
            vulnerability_list.append(alert)
    else:
        print("[+] No vulnerabilities found.")

    return vulnerability_list

# ---------------------------
# Run Metasploit Exploits
# ---------------------------
def run_metasploit(vuln):
    print("[*] Running Metasploit Exploits...")
    if "SQL Injection" in vuln['alert']:
        os.system("msfconsole -x 'use exploit/unix/webapp/php_sql_injection; set RHOST {} ; run'".format(vuln['url']))
    elif "Remote Code Execution" in vuln['alert']:
        os.system("msfconsole -x 'use exploit/unix/webapp/php_rce; set RHOST {} ; run'".format(vuln['url']))
    else:
        print(f"[-] No Metasploit exploit available for {vuln['alert']}")

# ---------------------------- 
# Run Burp Suite Active Scan 
# ---------------------------- 
async def run_burp_scan(): 
    print("[*] Starting Burp Suite Active Scan...") 
    headers = {"Authorization": f"Bearer {BURP_API_KEY}"} 
    
    async with aiohttp.ClientSession() as session: 
        async with session.post(f"{BURP_API_URL}/scan", json={"url": TARGET_URL}, headers=headers) as response: 
            if response.status == 200: 
                data = await response.json() 
                scan_id = data.get("scan_id") 
                print(f"[+] Burp Suite Scan Started. Scan ID: {scan_id}") 
                return scan_id 
            else: 
                print(f"[-] Failed to start Burp Suite scan. Status Code: {response.status}") 
                return None


async def analyze_mysql_logs():
    print("[*] Analyzing XAMPP MySQL Logs with Enhanced Efficiency...")
    mysql_error_log_path = r"C:\xampp\mysql\data\mysql_error.log"
    
    if not os.path.exists(mysql_error_log_path):
        print("[-] MySQL error log not found or logging not enabled.")
        return []

    # Define regex pattern for error detection
    error_patterns = [
        re.compile(r"error", re.IGNORECASE),
        re.compile(r"failed", re.IGNORECASE),
        re.compile(r"unauthorized", re.IGNORECASE),
        re.compile(r"access denied", re.IGNORECASE),
        re.compile(r"can't start server", re.IGNORECASE),
    ]

    logs_found = []

    try:
        async with aiofiles.open(mysql_error_log_path, mode="r") as file:
            async for line in file:
                if any(pattern.search(line) for pattern in error_patterns):
                    print(f"[ALERT] Suspicious MySQL Log Entry: {line.strip()}")
                    logs_found.append(line.strip())
    except Exception as e:
        print(f"[-] Error reading MySQL logs: {e}")

    return logs_found

# ------------------------ 
# Exploitation Phase 
# ------------------------ 
def run_pentesting_modules(vulnerability_list): 
    print("[*] Starting Pentesting Modules...") 
    for vuln in vulnerability_list: 
        if "SQL Injection" in vuln['alert']: 
            print("[*] Exploiting SQL Injection...") 
            run_sqlmap(vuln['url']) 
        run_metasploit(vuln) 
    print("[+] Pentesting Modules Completed.")

# --------------------------------------
# Forensics Functions (Using Tshark)
# --------------------------------------
# --------------------------------------
# Forensics Functions (Using Tshark)
# --------------------------------------
def capture_network_traffic():
    print("[*] Capturing Network Traffic using Wireshark (Tshark)...")
    tshark_path = r"C:\Users\jithe\Wireshark\tshark.exe"
    
    if not os.path.isfile(tshark_path):
        print("[-] Tshark executable not found at the specified path.")
        return
    
    # Get the list of interfaces to identify Wi-Fi
    print("[*] Fetching Network Interfaces using Tshark...")
    interfaces_command = f'"{tshark_path}" -D'
    interfaces = os.popen(interfaces_command).read()
    print(interfaces)

    # Identify the correct interface for Wi-Fi
    wifi_interface = None
    for line in interfaces.splitlines():
        if "Wi-Fi" in line or "Wireless" in line:
            wifi_interface = line.split('.')[0].strip()
            break

    if not wifi_interface:
        print("[-] Wi-Fi interface not found. Please check your network connections.")
        return
    
    print(f"[+] Wi-Fi interface found: {wifi_interface}. Starting capture (limited to 1000 packets)...")

    # Capture Network Traffic (Limit to 1000 packets)
    capture_command = f'"{tshark_path}" -i {wifi_interface} -c 1000 -w traffic_capture.pcap'
    print(f"[+] Running: {capture_command}")
    os.system(capture_command)
    print("[+] Network Traffic Capture Completed. File saved as 'traffic_capture.pcap'.")


def analyze_logs():
    print("[*] Analyzing System Logs...")
    log_files = ["/var/log/auth.log", "/var/log/syslog"]
    logs_found = []
    for log_file in log_files:
        if os.path.exists(log_file):
            with open(log_file, "r") as file:
                for line in file:
                    if "failed password" in line.lower() or "unauthorized access" in line.lower():
                        print(f"[ALERT] Suspicious Log Entry: {line.strip()}")
                        logs_found.append(line.strip())
    return logs_found

async def perform_forensics():
    print("[*] Performing Forensics Investigation...")
    capture_network_traffic()
    logs_found = analyze_logs()
    print("[+] Forensics Investigation Completed.")
    return logs_found

# --------------------------------------
# Generate Report
# --------------------------------------
def generate_report(vulnerabilities, logs_found):
    print("[*] Generating Security Assessment Report...")
    report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_filename, "w") as report_file:
        report_file.write("==== Security Assessment Report ====\n")
        report_file.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        report_file.write("== Detected Vulnerabilities ==\n")
        if vulnerabilities:
            for vuln in vulnerabilities:
                report_file.write(f"- Alert: {vuln['alert']}\n  Risk: {vuln['risk']}\n  URL: {vuln['url']}\n\n")
        else:
            report_file.write("No vulnerabilities detected.\n\n")
        
        report_file.write("== Forensics Analysis ==\n")
        if logs_found:
            report_file.write("Suspicious log entries detected:\n")
            for log in logs_found:
                report_file.write(f"{log}\n")
        else:
            report_file.write("No suspicious log entries found.\n")
    print(f"[+] Report saved as {report_filename}")

# --------------------------------------
# Main Function
# --------------------------------------
async def main():
    print("[*] Starting Security Assessment...")
    latest_vulnerabilities = await fetch_latest_vulnerabilities()
    await zap_spider(TARGET_URL)
    await zap_active_scan(TARGET_URL)
    await run_burp_scan()
    vulnerability_list = await zap_get_results(latest_vulnerabilities)
    if vulnerability_list:
        run_pentesting_modules(vulnerability_list)
    logs_found = await perform_forensics()
    generate_report(vulnerability_list, logs_found)
    print("[+] Security Assessment, Forensics, and Report Generation Completed.")

if __name__ == "__main__":
    asyncio.run(main())