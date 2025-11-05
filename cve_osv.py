import requests
import smtplib
import json
import os
import logging
import time
import gzip
import io
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Selenium imports for dynamic scraping
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Timeout and delay configurations
DEFAULT_TIMEOUT = 30    # seconds, for general requests
API_TIMEOUT = 15        # seconds, for API calls
SCRAPE_TIMEOUT = 20     # seconds, for web scraping page loads
NVD_TIMEOUT = 60        # seconds, for large NVD downloads
SCRAPE_POLITE_DELAY = 10  # seconds, between Selenium scrapes of CVE.org (politeness)

# Constants
OSV_API_URL = "https://api.osv.dev/v1/query"
CIRCL_API_URL = "https://cve.circl.lu/api/last"
NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"

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
        response = requests.post(OSV_API_URL, json=payload, timeout=API_TIMEOUT)
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
        return cves
    except Exception as e:
        logger.error(f"Error fetching from OSV.dev: {e}")
        return {}

def fetch_circl_cves():
    logger.info("Fetching CVEs from CIRCL API...")
    cves = {}
    try:
        response = requests.get(CIRCL_API_URL, timeout=API_TIMEOUT)
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
        return cves
    except Exception as e:
        logger.error(f"Error fetching from CIRCL: {e}")
        return {}

def fetch_nvd_cves():
    logger.info("Downloading latest NVD modified feed...")
    feed_url = NVD_BASE_URL + "nvdcve-1.1-modified.json.gz"
    try:
        resp = requests.get(feed_url, timeout=NVD_TIMEOUT)
        resp.raise_for_status()
        gz = gzip.GzipFile(fileobj=io.BytesIO(resp.content))
        data = json.load(gz)
        cves = {}
        for item in data.get("CVE_Items", []):
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
            if not cve_id.startswith("CVE-"):
                continue
            description_data = item.get("cve", {}).get("description", {}).get("description_data", [])
            description = description_data[0]["value"] if description_data else "No description available"
            impact = item.get("impact", {})
            cvss_score = "N/A"
            if "baseMetricV3" in impact:
                cvss_score = str(impact["baseMetricV3"].get("cvssV3", {}).get("baseScore", "N/A"))
            cves[cve_id] = {
                "summary": description,
                "cvss_score": cvss_score,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source": "NVD"
            }
        logger.info(f"Extracted {len(cves)} CVEs from NVD feed")
        return cves
    except Exception as e:
        logger.error(f"Error downloading/parsing NVD feed: {e}")
        return {}

def merge_cves(osv_cves, circl_cves, nvd_cves):
    all_cves = {}
    all_cves.update(circl_cves)
    all_cves.update(nvd_cves)
    all_cves.update(osv_cves)
    logger.info(f"Merged CVEs: {len(all_cves)} unique vulnerabilities")
    return all_cves

def scrape_cve_org_details_and_cvss_selenium(cve_id):
    logger.info(f"Scraping CVE.org for details and CVSS of {cve_id} using Selenium")
    url = f"https://www.cve.org/CVERecord?id={cve_id}"
    options = Options()
    options.headless = True
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(SCRAPE_TIMEOUT)
    driver.get(url)
    try:
        time.sleep(5)  # Wait for JS content to load
        desc_div = driver.find_element(By.ID, "cve-description")
        children = desc_div.find_elements(By.XPATH, "./*")
        desc_lines = []
        for el in children:
            if el.tag_name.lower() == 'h4':
                continue
            desc_lines.append(el.text.strip())
        description = "\n".join(desc_lines).strip()
        try:
            score_td = driver.find_element(By.XPATH, '//td[@data-label="Score"]')
            cvss_score = score_td.text.strip()
        except NoSuchElementException:
            cvss_score = "N/A"
        return description if description else "Description not found.", cvss_score
    except Exception as e:
        logger.error(f"Error scraping {cve_id} with Selenium: {e}")
        return "Scraping error.", "N/A"
    finally:
        driver.quit()

def patch_missing_with_scrape(cves):
    for cveid, cvedata in cves.items():
        needs_summary = cvedata.get("summary", "").startswith("Check CIRCL database") or not cvedata.get("summary")
        needs_cvss = cvedata.get("cvss_score", "N/A") == "N/A"
        if needs_summary or needs_cvss:
            description, cvss = scrape_cve_org_details_and_cvss_selenium(cveid)
            if needs_summary and description:
                cvedata["summary"] = description
            if needs_cvss and cvss:
                cvedata["cvss_score"] = cvss
            time.sleep(SCRAPE_POLITE_DELAY)  # Polite delay between Selenium scrapes
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
    logger.info("CVE Alert System Started")
    try:
        if not EMAIL_USER or not EMAIL_PASS:
            logger.error("EMAIL_USER or EMAIL_PASS not set in environment variables")
            return
        seen_cves = load_seen()
        logger.info(f"Loaded {len(seen_cves)} previously seen CVEs")
        osv_cves = fetch_osv_cves()
        circl_cves = fetch_circl_cves()
        nvd_cves = fetch_nvd_cves()
        all_cves = merge_cves(osv_cves, circl_cves, nvd_cves)
        if not all_cves:
            logger.warning("No CVEs fetched from any source")
            return
        new_cve_ids = set(all_cves.keys()) - seen_cves
        if new_cve_ids:
            logger.info(f"Found {len(new_cve_ids)} new CVEs")
            new_cves_data = {cveid: all_cves[cveid] for cveid in sorted(new_cve_ids)}
            patched_cves = patch_missing_with_scrape(new_cves_data)
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
