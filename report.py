import asyncio
import webbrowser
import os
import subprocess
from zapv2 import ZAPv2
from datetime import datetime

# Configuration
ZAP_API_KEY = "aej247vl3rle1dqlk9f2jspl42"
ZAP_URL = "http://localhost:8081"
REPORT_FILE = "security_assessment_report.html"
TSHARK_PATH = r"C:\Users\jithe\Wireshark\tshark.exe"

# Initialize ZAP API
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})

# ------------------------------
# Analyze Captured Network Traffic
# ------------------------------
def get_network_summary():
    if not os.path.exists("traffic_capture.pcap"):
        return "No network capture available."

    try:
        summary_command = f'"{TSHARK_PATH}" -r traffic_capture.pcap -c 10 -T fields -e frame.time -e ip.src -e ip.dst -e frame.len'
        process = subprocess.Popen(summary_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()

        if output:
            summary_data = output.decode('utf-8').strip().split('\n')
            return summary_data
        else:
            return f"Error during summary generation: {error.decode('utf-8')}"
    except Exception as e:
        return str(e)

# ------------------------------
# Analyze Logs for Forensics
# ------------------------------
def analyze_logs():
    print("[*] Analyzing System Logs...")
    log_files = ["/var/log/auth.log", "/var/log/syslog"]
    suspicious_logs = []

    for log_file in log_files:
        if os.path.exists(log_file):
            with open(log_file, "r") as file:
                for line in file:
                    if "failed password" in line.lower() or "unauthorized access" in line.lower():
                        suspicious_logs.append(line.strip())
    return suspicious_logs

# ------------------------------
# Generate HTML Report
# ------------------------------
async def generate_report():
    print("[*] Generating Security Assessment Report...")

    # Fetch alerts from ZAP
    alerts = zap.core.alerts()
    network_summary = get_network_summary()
    logs_found = analyze_logs()

    # Start building the report
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Security Assessment Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f9f9f9;
            }}
            .container {{
                max-width: 900px;
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.05);
            }}
            h1, h2, h3 {{
                color: #333;
            }}
            .alert {{
                border-left: 5px solid #d9534f;
                background: #f2dede;
                padding: 15px;
                margin-bottom: 10px;
            }}
            .medium {{
                border-left: 5px solid #f0ad4e;
                background: #fcf8e3;
            }}
            .low {{
                border-left: 5px solid #5bc0de;
                background: #d9edf7;
            }}
            pre {{
                background-color: #f0f0f0;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
            }}
            a {{
                color: #007bff;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Security Assessment Report</h1>
            <p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Tool Version:</strong> OWASP ZAP {zap.core.version}</p>
            <p><strong>Total Issues Found:</strong> {len(alerts)}</p>
    """

    # Download link for pcap
    if os.path.exists("traffic_capture.pcap"):
        html_content += """
        <p><a href="traffic_capture.pcap" download>Download Network Capture (traffic_capture.pcap)</a></p>
        """

    # Vulnerabilities Section
    html_content += "<h2>Vulnerabilities Detected</h2>"
    if alerts:
        for alert in alerts:
            risk = alert.get("risk", "Informational")
            risk_class = "alert"
            if risk == "Medium":
                risk_class = "alert medium"
            elif risk == "Low":
                risk_class = "alert low"

            html_content += f"""
            <div class="{risk_class}">
                <h3>{alert['alert']} - {alert['risk']} Risk</h3>
                <p><strong>URL:</strong> {alert['url']}</p>
                <p><strong>Description:</strong> {alert['description']}</p>
            </div>
            """
    else:
        html_content += "<p>No vulnerabilities found.</p>"

    # Forensics Analysis
    html_content += "<h2>Forensics Analysis</h2>"
    if logs_found:
        html_content += "<p>Suspicious log entries detected:</p><pre>"
        html_content += "\n".join(logs_found)
        html_content += "</pre>"
    else:
        html_content += "<p>No suspicious log entries found.</p>"

    # Network Traffic Summary
    html_content += "<h2>Network Traffic Summary</h2>"
    if isinstance(network_summary, list):
        html_content += "<p>Sample Packets (Limited to 10 for Preview):</p><pre>"
        html_content += "\n".join(network_summary)
        html_content += "</pre>"
    else:
        html_content += f"<p>{network_summary}</p>"

    # Closing HTML
    html_content += """
        </div>
    </body>
    </html>
    """

    # Write to file
    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"[+] Report saved as {REPORT_FILE}")

# ------------------------------
# Open Report in Browser
# ------------------------------
async def open_report():
    report_path = os.path.abspath(REPORT_FILE)
    webbrowser.open(report_path)

# ------------------------------
# Main Function
# ------------------------------
async def main():
    await generate_report()
    await open_report()

if __name__ == "__main__":
    asyncio.run(main())
