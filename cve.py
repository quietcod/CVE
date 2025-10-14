import feedparser
import smtplib
from email.mime.text import MIMEText
import os
import json

# Configuration
NVD_RSS_URL = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
EMAIL_USER = os.getenv("EMAIL_USER")  # Your email address (from GitHub Secrets)
EMAIL_PASS = os.getenv("EMAIL_PASS")  # Your email app password (from GitHub Secrets)
RECIPIENTS = ["gshubh270@gmail.com"]  # Add emails here

# File to store seen entries for deduplication
SEEN_FILE = "seen_cves.json"

def load_seen():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)

def send_email(subject, body, recipients):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_USER
    msg['To'] = ", ".join(recipients)
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, recipients, msg.as_string())

def main():
    feed = feedparser.parse(NVD_RSS_URL)
    seen = load_seen()
    new_entries = []

    for entry in feed.entries:
        cve_id = entry.title  # CVE-xxxx-xxxx
        if cve_id not in seen:
            new_entries.append(entry)
            seen.add(cve_id)

    if new_entries:
        for entry in new_entries:
            subject = f"New CVE Published: {entry.title}"
            body = f"{entry.title}\n\n{entry.summary}\n\nLink: {entry.link}"
            send_email(subject, body, RECIPIENTS)
            print(f"Sent alert for {entry.title}")
        save_seen(seen)
    else:
        print("No new CVEs found.")

if __name__ == "__main__":
    main()

