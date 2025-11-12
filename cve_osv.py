import requests
import smtplib
import json
import os
import logging
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException, WebDriverException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
API_TIMEOUT = 30
SCRAPE_TIMEOUT = 25
SCRAPE_POLITE_DELAY = 2
CIRCL_API_URL = "https://cve.circl.lu/api/last"

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

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
    try:
        headers = {'User-Agent': 'CVE-Monitor/1.0 (+https://github.com/quietcod/CVE)'}
        response = requests.get(CIRCL_API_URL, timeout=API_TIMEOUT, headers=headers)
        response.raise_for_status()
        data = response.json()
        logger.info(f"Retrieved {len(data)} CVEs from CIRCL")
        
        cves = {}
        limit = int(os.getenv("CVE_LIMIT", "10"))
        
        for item in data[:limit]:
            if isinstance(item, dict):
                cve_id = item.get("id") or item.get("cveMetadata", {}).get("cveId")
            else:
                cve_id = item
                
            if not cve_id or not cve_id.startswith("CVE-") or cve_id in cves:
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

def get_chrome_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-software-rasterizer")
    options.add_argument("--disable-background-timer-throttling")
    options.add_argument("--disable-backgrounding-occluded-windows")
    options.add_argument("--disable-renderer-backgrounding")
    options.add_argument("--disable-features=TranslateUI,VizDisplayCompositor")
    options.add_argument("--window-size=1280,720")
    options.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-plugins")
    options.add_argument("--disable-images")
    options.add_argument("--disable-javascript")
    options.add_argument("--no-first-run")
    options.add_argument("--disable-default-apps")
    
    try:
        service = Service()
        driver = webdriver.Chrome(service=service, options=options)
        logger.info("Using system ChromeDriver")
    except Exception as e:
        logger.info(f"System ChromeDriver failed: {e}, trying webdriver-manager")
        from webdriver_manager.chrome import ChromeDriverManager
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        logger.info("Using webdriver-manager ChromeDriver")
    
    driver.set_page_load_timeout(SCRAPE_TIMEOUT)
    driver.implicitly_wait(3)
    return driver

def scrape_cve_details_selenium(cve_id):
    logger.info(f"Scraping {cve_id} using Selenium")
    
    driver = None
    description = ""
    cvss_score = "N/A"
    
    for attempt in range(2):
        try:
            driver = get_chrome_driver()
            
            # Try MITRE first
            mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            logger.info(f"Loading MITRE page: {mitre_url} (attempt {attempt + 1})")
            
            driver.get(mitre_url)
            time.sleep(2)
            
            description_selectors = [
                '//table[@id="TableWithBorder"]//td[contains(text(),"Description")]/following-sibling::td',
                '//table//tr[td[contains(text(),"Description")]]/td[2]'
            ]
            
            for selector in description_selectors:
                try:
                    desc_elem = driver.find_element(By.XPATH, selector)
                    if desc_elem and desc_elem.text.strip():
                        description = desc_elem.text.strip()
                        logger.info(f"Found description using selector: {selector}")
                        break
                except NoSuchElementException:
                    continue
            
            if description:
                break
                
            # Try NVD if MITRE failed and it's the last attempt
            if attempt == 1:
                logger.info(f"Trying NVD for {cve_id}")
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                
                try:
                    driver.get(nvd_url)
                    time.sleep(3)
                    
                    nvd_selectors = [
                        '//p[@data-testid="vuln-description"]',
                        '//div[contains(@class,"vuln-description")]//p'
                    ]
                    
                    for selector in nvd_selectors:
                        try:
                            desc_elem = driver.find_element(By.XPATH, selector)
                            if desc_elem and desc_elem.text.strip():
                                description = desc_elem.text.strip()
                                logger.info(f"Found description on NVD using: {selector}")
                                break
                        except NoSuchElementException:
                            continue
                    
                    # Try CVSS score
                    try:
                        cvss_elem = driver.find_element(By.XPATH, '//span[@data-testid="vuln-cvss3-base-score"]')
                        if cvss_elem and cvss_elem.text.strip():
                            cvss_score = cvss_elem.text.strip()
                    except NoSuchElementException:
                        pass
                        
                except Exception as e:
                    logger.warning(f"NVD scraping failed for {cve_id}: {e}")
            break
            
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} failed for {cve_id}: {e}")
            if attempt == 1:
                logger.error(f"All attempts failed for {cve_id}")
        finally:
            if driver:
                try:
                    driver.quit()
                    driver = None
                except Exception as e:
                    logger.warning(f"Error closing driver: {e}")
    
    final_description = description if description else "Description not available"
    logger.info(f"Scraping result for {cve_id}: description_length={len(final_description)}, cvss={cvss_score}")
    
    return final_description, cvss_score

def patch_with_scrape(cves):
    total_cves = len(cves)
    for idx, (cveid, cvedata) in enumerate(cves.items(), 1):
        if not cvedata.get("summary"):
            logger.info(f"Patching {cveid} ({idx}/{total_cves})...")
            description, cvss = scrape_cve_details_selenium(cveid)
            
            if description and description != "Description not available":
                cvedata["summary"] = description
            if cvss and cvss != "N/A":
                cvedata["cvss_score"] = cvss
            
            if idx < total_cves:
                time.sleep(SCRAPE_POLITE_DELAY)
    return cves

def send_summary_email(new_cves, recipients):
    if not EMAIL_USER or not EMAIL_PASS:
        logger.error("Email credentials not configured")
        return False
    
    subject = f"🚨 New CVE Alerts - {len(new_cves)} vulnerabilities found"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = ", ".join(recipients)
    
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
            .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .cve-item {{ border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; background-color: #fff; }}
            .cve-title {{ color: #d73027; margin-top: 0; margin-bottom: 10px; }}
            .description-box {{ background-color: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; margin: 10px 0; }}
            .metadata {{ color: #666; font-size: 14px; }}
            .cvss-high {{ color: #d73027; font-weight: bold; }}
            .cvss-medium {{ color: #fd7e14; font-weight: bold; }}
            .cvss-low {{ color: #28a745; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2 style="margin: 0; color: #d73027;">🚨 New CVE Vulnerabilities Found: {len(new_cves)}</h2>
            <p style="margin: 10px 0 0 0; color: #666;">Detected on {time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    """
    
    for cveid, cvedata in new_cves.items():
        cvss = cvedata.get("cvss_score", "N/A")
        if cvss != "N/A":
            try:
                cvss_num = float(cvss)
                severity_class = "cvss-high" if cvss_num >= 7.0 else "cvss-medium" if cvss_num >= 4.0 else "cvss-low"
            except:
                severity_class = "metadata"
        else:
            severity_class = "metadata"
        
        html += f"""
        <div class="cve-item">
            <h3 class="cve-title">{cveid}</h3>
            <p class="metadata">
                <strong>CVSS Score:</strong> <span class="{severity_class}">{cvss}</span> | 
                <strong>Source:</strong> {cvedata.get("source", "Unknown")} | 
                <strong>Published:</strong> {cvedata.get("published", "Unknown")}
            </p>
            <div class="description-box">
                <strong>Description:</strong><br>
                {cvedata.get("summary", "No description available")}
            </div>
            <p><strong>🔗 Reference:</strong> <a href="{cvedata.get("url", "")}" style="color: #007bff;">{cvedata.get("url", "")}</a></p>
        </div>
        """
    
    html += """
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <div style="text-align: center; color: #666; font-size: 12px;">
            <p>This alert was generated by CVE Monitor System</p>
            <p>Report issues: <a href="mailto:quietcod@protonmail.com" style="color: #007bff;">quietcod@protonmail.com</a></p>
        </div>
    </body>
    </html>
    """
    
    part = MIMEText(html, "html")
    msg.attach(part)
    
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, recipients, msg.as_string())
        server.quit()
        
        logger.info(f"✅ Summary email sent for {len(new_cves)} CVEs to {len(recipients)} recipients")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error sending summary email: {e}")
        return False

def main():
    logger.info("🚀 CVE Alert System Started")
    try:
        if not EMAIL_USER or not EMAIL_PASS:
            logger.error("❌ EMAIL_USER or EMAIL_PASS not set in environment variables")
            return
            
        seen_cves = load_seen()
        logger.info(f"📝 Loaded {len(seen_cves)} previously seen CVEs")
        
        circl_cves = fetch_circl_cves()
        if not circl_cves:
            logger.warning("⚠️  No CVEs fetched from CIRCL")
            return
            
        new_cve_ids = set(circl_cves.keys()) - seen_cves
        
        if new_cve_ids:
            logger.info(f"🔍 Found {len(new_cve_ids)} new CVEs: {sorted(new_cve_ids)}")
            new_cves_data = {cveid: circl_cves[cveid] for cveid in sorted(new_cve_ids)}
            
            logger.info("📡 Fetching detailed information with Selenium...")
            patched_cves = patch_with_scrape(new_cves_data)
            
            if send_summary_email(patched_cves, RECIPIENTS):
                logger.info("✅ Email sent successfully")
            else:
                logger.error("❌ Failed to send email")
            
            seen_cves.update(new_cve_ids)
            save_seen(seen_cves)
            logger.info(f"💾 Updated seen CVEs, total: {len(seen_cves)}")
            
        else:
            logger.info("✅ No new CVEs found")
            
        logger.info("🎯 CVE Alert System Completed Successfully")
        
    except Exception as e:
        logger.error(f"💥 Fatal error in main: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
