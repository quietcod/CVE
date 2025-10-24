import requests
import smtplib
from email.mime.text import MIMEText
import os
import json

# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&pubStartDate=2023-01-01T00:00:00:000%20UTC-00:00"
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
RECIPIENTS = ["quietcod@protonmail.com", "raghu@thesunrisecomputers.com"]

# File to store seen entries for deduplication
SEEN_FILE = "seen_cves.json"

def load_seen():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            try:
                return set(json.load(f))
            except json.JSONDecodeError:
                print("Warning: seen_cves.json is corrupted, starting fresh.")
                return set()
    else:
        print("No seen_cves.json found, creating new one...")
        return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)

def send_email(subject, body, recipients):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = ", ".join(recipients)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, recipients, msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")

def main():
    print("Fetching latest CVE data from NVD API...")
    response = requests.get(NVD_API_URL)
    if response.status_code != 200:
        print("Error: Failed to fetch CVE data. Check network or NVD API service.")
        return

    data = response.json()
    cve_items = data.get("vulnerabilities", [])
    seen = load_seen()
    new_entries = []

    for item in cve_items:
        cve_id = item["cve"]["id"].strip()
        if cve_id not in seen:
            new_entries.append(item)
            seen.add(cve_id)

    if new_entries:
        print(f"Found {len(new_entries)} new CVE(s). Sending alerts...")
        for item in new_entries:
            cve = item["cve"]
            cve_id = cve["id"]
            description = cve.get("descriptions", [{}])[0].get("value", "No summary provided.")
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            subject = f"New CVE Published: {cve_id}"
            body = f"{cve_id}\n\n{description}\n\nLink: {url}"
            send_email(subject, body, RECIPIENTS)
            print(f"Sent alert for {cve_id}")
        save_seen(seen)
        print("Updated seen_cves.json file.")
    else:
        print("No new CVEs found. Nothing to update.")

if __name__ == "__main__":
    main()
