import requests
import smtplib
import json
import os
import logging
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Selenium imports for dynamic scraping
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

API_TIMEOUT = 15
SCRAPE_TIMEOUT = 20
SCRAPE_POLITE_DELAY = 10
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
                "summary": "",
                "cvss_score": "N/A",
                "source": "CIRCL",
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            }
        return cves
    except Exception as e:
        logger.error(f"Error fetching from CIRCL: {e}")
        return {}

def scrape_cve_details_selenium(cve_id):
    logger.info(f"Scraping CVE.org and Mitre for {cve_id} using Selenium")
    
    # Try CVE.org first
    url_org = f"https://www.cve.org/CVERecord?id={cve_id}"
    options = Options()
    options.headless = True
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.set_page_load_timeout(SCRAPE_TIMEOUT)
    description, cvss_score = "", "N/A"

    try:
        driver.get(url_org)
        time.sleep(5)
        try:
            desc_div = driver.find_element(By.ID, "cve-description")
            children = desc_div.find_elements(By.XPATH, "./*")
            desc_lines = [el.text.strip() for el in children if el.tag_name.lower() != 'h4']
            description = "\n".join(desc_lines).strip()
        except NoSuchElementException:
            description = ""
        try:
            score_td = driver.find_element(By.XPATH, '//td[@data-label="Score"]')
            cvss_score = score_td.text.strip()
        except NoSuchElementException:
            cvss_score = "N/A"
    except Exception as e:
        logger.warning(f"CVE.org scrape failed for {cve_id}: {e}")
    finally:
        driver.quit()
    
    # If still missing a summary, try MITRE
    if not description:
        url_mitre = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        options = Options()
        options.headless = True
        driver_mitre = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver_mitre.set_page_load_timeout(SCRAPE_TIMEOUT)
        try:
            driver_mitre.get(url_mitre)
            time.sleep(5)
            try:
                desc_td = driver_mitre.find_element(By.XPATH, '//table[@id="TableWithBorder"]/tbody/tr[2]/td[2]')
                description = desc_td.text.strip()
            except NoSuchElementException:
                description = "Description not found."
        except Exception as e:
            logger.warning(f"Mitre scrape failed for {cve_id}: {e}")
        finally:
            driver_mitre.quit()
    return description, cvss_score

def patch_with_scrape(cves):
    for cveid, cvedata in cves.items():
        if not cvedata.get("summary"):
            description, cvss = scrape_cve_details_selenium(cveid)
            if description:
                cvedata["summary"] = description
            if cvss:
                cvedata["cvss_score"] = cvss
            time.sleep(SCRAPE_POLITE_DELAY)
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
        circl_cves = fetch_circl_cves()
        if not circl_cves:
            logger.warning("No CVEs fetched from CIRCL")
            return
        new_cve_ids = set(circl_cves.keys()) - seen_cves
        if new_cve_ids:
            logger.info(f"Found {len(new_cve_ids)} new CVEs")
            new_cves_data = {cveid: circl_cves[cveid] for cveid in sorted(new_cve_ids)}
            patched_cves = patch_with_scrape(new_cves_data)
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
