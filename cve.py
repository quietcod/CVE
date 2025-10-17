import feedparser
import smtplib
from email.mime.text import MIMEText
import os
import json

# Configuration
NVD_RSS_URL = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
EMAIL_USER = os.getenv("EMAIL_USER")  # Sender email from GitHub Secrets
EMAIL_PASS = os.getenv("EMAIL_PASS")  # App password from GitHub Secrets
RECIPIENTS = ["quietcod@protonmail.com", "raghu@thesunrisecomputers.com"]

# File to store seen CVEs for deduplication
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
    print("Fetching latest CVE feed...")
    feed = feedparser.parse(NVD_RSS_URL)

    if not feed.entries:
        print("Error: Failed to fetch CVE data. Check network or NVD feed URL.")
        return

    seen = load_seen()
    new_entries = []

    for entry in feed.entries:
        cve_id = entry.title.strip()
        if cve_id not in seen:
            new_entries.append(entry)
            seen.add(cve_id)

    if new_entries:
        print(f"Found {len(new_entries)} new CVE(s). Sending alerts...")
        for entry in new_entries:
            subject = f"New CVE Published: {entry.title}"
            body = f"{entry.title}\n\n{entry.summary}\n\nLink: {entry.link}"
            send_email(subject, body, RECIPIENTS)
            print(f"Sent alert for {entry.title}")
        save_seen(seen)
        print("Updated seen_cves.json file.")
    else:
        print("No new CVEs found. Nothing to update.")

if __name__ == "__main__":
    main()
