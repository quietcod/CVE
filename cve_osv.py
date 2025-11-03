import requests
import smtplib
import json
import os
import logging
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
CIRCL_API_URL = "https://cve.circl.lu/api/last"

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
RECIPIENTS = ["quietcod@protonmail.com"]
SEEN_FILE = "seen_cves.json"

def load_seen():
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return set(data)
                elif isinstance(data, dict) and "cves" in data:
                    return set(data["cves"].keys())
                return set(data)
        except Exception as e:
            logger.warning(f"Error loading seen CVEs: {e}")
    return set()

def save_seen(cve_set):
    try:
        with open(SEEN_FILE, "w") as f:
            json.dump(sorted(list(cve_set)), f, indent=2)
        logger.info(f"Saved {len(cve_set)} CVEs to seen_cves.json")
    except Exception as e:
        logger.error(f"Error saving seen CVEs: {e}")

def fetch_osv_cves():
    logger.info("Fetching CVEs from OSV.dev API...")
    cves = {}
    try:
        payload = {
            "page_token": None,
            "page_size": 100
        }
        response = requests.post(OSV_API_URL, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulns", [])
        logger.info(f"Retrieved {len(vulns)} vulnerabilities from OSV.dev")
        for vuln in vulns:
            cve_id = vuln.get("id", "").strip()
            if not cve_id.startswith("CVE-"):
                continue
            published_date = vuln.get("published", "")
            modified_date = vuln.get("modified", "")
            summary = vuln.get("summary", "No description available")
            details = vuln.get("details", "")
            cvss_score = "N/A"
            if "severity" in vuln:
                for severity in vuln.get("severity", []):
                    if severity.get("type") == "CVSS_V3":
                        cvss_score = severity.get("score", "N/A")
                        break
            affected_packages = []
            for pkg in vuln.get("affected", []):
                pkg_name = pkg.get("package", {}).get("name", "Unknown")
                ecosystem = pkg.get("package", {}).get("ecosystem", "Unknown")
                affected_packages.append(f"{pkg_name} ({ecosystem})")
            cves[cve_id] = {
                "published": published_date,
                "modified": modified_date,
                "summary": summary,
                "details": details,
                "cvss_score": cvss_score,
                "affected_packages": affected_packages[:5],
                "source": "OSV.dev",
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            }
        logger.info(f"Successfully fetched {len(cves)} CVEs from OSV.dev")
        return cves
    except Exception as e:
        logger.error(f"Error fetching from OSV.dev: {e}")
        return {}

def fetch_circl_cves():
    logger.info("Fetching CVEs from CIRCL API...")
    cves = {}
    try:
        response = requests.get(CIRCL_API_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        logger.info(f"Retrieved {len(data)} CVEs from CIRCL")
        for idx, item in enumerate(data[:50]):
            if isinstance(item, dict):
                cve_id = item.get("id") or item.get("cveMetadata", {}).get("cveId")
            else:
                cve_id = item
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            if cve_id in cves:
                continue
            published = item.get("cveMetadata", {}).get("datePublished", "") if isinstance(item, dict) else ""
            cves[cve_id] = {
                "published": published,
                "modified": "",
                "summary": "Check CIRCL database for details",
                "details": "",
                "cvss_score": "N/A",
                "affected_packages": [],
                "source": "CIRCL",
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            }
        logger.info(f"Successfully fetched {len(cves)} CVEs from CIRCL")
        return cves
    except Exception as e:
        logger.error(f"Error fetching from CIRCL: {e}")
        return {}

def merge_cves(osv_cves, circl_cves):
    all_cves = {}
    all_cves.update(circl_cves)
    all_cves.update(osv_cves)
    logger.info(f"Merged CVEs: {len(all_cves)} unique vulnerabilities")
    return all_cves

def scrape_cve_details(cve_id):
    logger.info(f"Scraping CVE details for {cve_id}")
    url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        desc_tag = soup.find("td", {"data-testid": "vuln-description"})
        if not desc_tag:
            # Try alternate element/class common on MITRE page
            desc_tag = soup.find("td", {"valign": "top"})
        description = desc_tag.text.strip() if desc_tag else "Description not found."
        # MITRE CVE pages don't have CVSS scores so keep as 'N/A'
        return description, "N/A"
    except Exception as e:
        logger.error(f"Failed to scrape {cve_id}: {str(e)}")
        return None, None

def patch_missing_cve_details(cves):
    time.sleep(30)  # Initial delay
    patched_count = 0
    for cveid, cvedata in cves.items():
        if patched_count >= 5:
            break
        if cvedata.get("summary", "") in ("", "Check CIRCL database for details") or cvedata.get("cvss_score", "N/A") == "N/A":
            desc, cvss = scrape_cve_details(cveid)
            if desc:
                if cvedata.get("summary", "") in ("", "Check CIRCL database for details"):
                    cvedata["summary"] = desc
                if cvedata.get("cvss_score", "N/A") == "N/A":
                    cvedata["cvss_score"] = cvss
                patched_count += 1
                time.sleep(10)  # Delay between requests
    return cves

def send_summary_email(new_cves, recipients):
    subject = f"New CVE Alerts - {len(new_cves)} vulnerabilities found"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = ", ".join(recipients)
    html = "<html><body><h2>New CVE Vulnerabilities Found:</h2>"
    for cveid, cvedata in new_cves.items():
        html += f"""
        <hr>
        <h3>{cveid}</h3>
        <b>CVSS Score:</b> {cvedata.get("cvss_score", "N/A")}<br>
        <b>Description:</b> {cvedata.get("summary", "No description available")}<br>
        <b>Link:</b> <a href="{cvedata.get("url", "")}">{cvedata.get("url", "")}</a><br>
        """
    html += "</body></html>"
    part = MIMEText(html, "html")
    msg.attach(part)
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, recipients, msg.as_string())
        logger.info(f"Summary email sent for {len(new_cves)} CVEs")
        return True
    except Exception as e:
        logger.error(f"Error sending summary email: {e}")
        return False

def main():
    logger.info("CVE Alert System Started (OSV.dev Enhanced)")
    try:
        if not EMAIL_USER or not EMAIL_PASS:
            logger.error("EMAIL_USER or EMAIL_PASS not set in environment variables")
            return
        seen_cves = load_seen()
        logger.info(f"Loaded {len(seen_cves)} previously seen CVEs")
        osv_cves = fetch_osv_cves()
        circl_cves = fetch_circl_cves()
        all_cves = merge_cves(osv_cves, circl_cves)
        if not all_cves:
            logger.warning("No CVEs fetched from any source")
            return
        new_cve_ids = set(all_cves.keys()) - seen_cves
        if new_cve_ids:
            logger.info(f"Found {len(new_cve_ids)} new CVEs")
            new_cves_data = {cveid: all_cves[cveid] for cveid in sorted(new_cve_ids)}
            # Patch missing details with scraping
            patched_cves = patch_missing_cve_details(new_cves_data)
            send_summary_email(patched_cves, RECIPIENTS)
            seen_cves.update(new_cve_ids)
            save_seen(seen_cves)
        else:
            logger.info("No new CVEs found")
        logger.info("CVE Alert System Completed Successfully")
    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)

if __name__ == "__main__":
    main()
