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

# Perplexity AI config
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY")
AI_ENABLED = os.getenv("AI_ENABLED", "false").lower() == "true"
# You can change model via env: PERPLEXITY_MODEL=sonar-pro, sonar-small-chat, sonar-medium-online, etc.
PERPLEXITY_MODEL = os.getenv("PERPLEXITY_MODEL", "sonar-small-chat")
PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"


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

        # DEBUG: Print the actual structure
        logger.info("=== DEBUG: CIRCL API Response Structure ===")
        logger.info(f"Response type: {type(data)}")
        logger.info(f"Response length: {len(data)}")

        if len(data) > 0:
            logger.info("First 3 items:")
            for i, item in enumerate(data[:3]):
                logger.info(f"Item {i+1}: {item}")
                logger.info(f"Item {i+1} type: {type(item)}")

        logger.info("=== END DEBUG ===")

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

        logger.info(f"Final processed CVEs: {list(cves.keys())}")
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
    options.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-plugins")
    options.add_argument("--no-first-run")
    options.add_argument("--disable-default-apps")

    # Better modern website compatibility
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)

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
    driver.implicitly_wait(5)
    return driver


def scrape_cve_details_selenium(cve_id):
    logger.info(f"Scraping {cve_id} using Selenium")

    driver = None
    description = ""
    cvss_score = "N/A"

    for attempt in range(2):
        try:
            driver = get_chrome_driver()

            # Try CVE.org first (modern structure)
            cve_org_url = f"https://www.cve.org/CVERecord?id={cve_id}"
            logger.info(f"Loading CVE.org page: {cve_org_url} (attempt {attempt + 1})")

            driver.get(cve_org_url)
            time.sleep(5)  # Wait for JavaScript to load

            # CVE.org description selectors
            cve_org_selectors = [
                '//p[@class="content cve-x-scroll"]',
                '//div[@id="cve-description"]//p[@class="content cve-x-scroll"]',
                '//div[@id="cve-description"]//p',
                '//div[contains(@class,"cve-description")]//p',
                '//p[contains(@class,"content")]',
                '//div[@id="cve-cna-container-start"]//p[@class="content cve-x-scroll"]',
                '//div[@class="content"]//p[@class="content cve-x-scroll"]'
            ]

            for i, selector in enumerate(cve_org_selectors):
                try:
                    logger.info(f"Trying CVE.org description selector {i+1}: {selector}")
                    desc_elem = driver.find_element(By.XPATH, selector)
                    if desc_elem and desc_elem.text.strip():
                        description = desc_elem.text.strip()
                        logger.info(f"✅ Found description using CVE.org selector {i+1}")
                        break
                except NoSuchElementException:
                    logger.info(f"❌ CVE.org description selector {i+1} failed")
                    continue

            # CVE.org CVSS selectors
            cvss_selectors_cve_org = [
                '//td[@data-label="Score"]',
                '//td[contains(@data-label,"Score")]',
                '//table[contains(@class,"table-container")]//td[@data-label="Score"]',
                '//div[@id="cvss-table"]//td[@data-label="Score"]',
                '//td[@data-label="Severity"]',
                '//td[contains(@data-label,"CVSS")]',
                '//div[contains(@class,"cvss")]//span',
                '//div[@id="cve-cna-container-start"]//div[contains(@class,"score")]',
                '//*[contains(text(),"CVSS")]/following-sibling::*',
                '//span[contains(@class,"score")]'
            ]

            for i, selector in enumerate(cvss_selectors_cve_org):
                try:
                    logger.info(f"Trying CVE.org CVSS selector {i+1}: {selector}")
                    cvss_elem = driver.find_element(By.XPATH, selector)
                    if cvss_elem and cvss_elem.text.strip():
                        cvss_text = cvss_elem.text.strip()
                        import re
                        score_match = re.search(r'(\d+\.?\d*)', cvss_text)
                        if score_match:
                            cvss_score = score_match.group(1)
                        else:
                            cvss_score = cvss_text
                        logger.info(f"✅ Found CVSS on CVE.org using selector {i+1}: {cvss_score}")
                        break
                except NoSuchElementException:
                    logger.info(f"❌ CVE.org CVSS selector {i+1} failed")
                    continue

            # If found description on CVE.org, break attempt loop
            if description:
                break

            # If no description from CVE.org, try MITRE (fallback)
            if not description:
                logger.info(f"No description on CVE.org, trying MITRE for {cve_id}")
                mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"

                try:
                    driver.get(mitre_url)
                    time.sleep(3)

                    mitre_selectors = [
                        '//table[@id="TableWithBorder"]//td[contains(text(),"Description")]/following-sibling::td',
                        '//table[@id="TableWithBorder"]//tr[td[contains(text(),"Description")]]/td[2]',
                        '//table//td[contains(text(),"Description")]/../td[2]',
                        '//table//tr[contains(.,"Description")]/td[2]',
                        '//td[contains(text(),"Description")]/following-sibling::td[1]',
                        '//table//td[normalize-space(text())="Description"]/following-sibling::td'
                    ]

                    for i, selector in enumerate(mitre_selectors):
                        try:
                            logger.info(f"Trying MITRE selector {i+1}: {selector}")
                            desc_elem = driver.find_element(By.XPATH, selector)
                            if desc_elem and desc_elem.text.strip():
                                description = desc_elem.text.strip()
                                logger.info(f"✅ Found description using MITRE selector {i+1}")
                                break
                        except NoSuchElementException:
                            logger.info(f"❌ MITRE selector {i+1} failed")
                            continue

                except Exception as e:
                    logger.warning(f"MITRE scraping failed for {cve_id}: {e}")

            break  # Exit attempt loop

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
    logger.info(f"Final result for {cve_id}: description_length={len(final_description)}, cvss={cvss_score}")

    return final_description, cvss_score


def simplify_description(description: str, cve_id: str) -> str:
    """
    Use Perplexity API to turn a technical CVE description into
    a plain-language explanation. On any failure, returns the original.
    """
    if not AI_ENABLED:
        logger.info("AI simplification disabled (AI_ENABLED is false)")
        return description

    if not PERPLEXITY_API_KEY:
        logger.error("PERPLEXITY_API_KEY not set, skipping AI simplification")
        return description

    if not description or description == "Description not available":
        return description

    logger.info(f"Calling Perplexity API to simplify description for {cve_id}")

    system_prompt = (
        "You are a cybersecurity risk translator. Your job is to rewrite technical "
        "vulnerability descriptions into simple terms for non-technical people such as CEOs, "
        "managers, or small business owners.\n\n"
        "RULES:\n"
        "Do NOT copy the original sentence structure.\n"
        "Avoid technical terms such as RCE, SQL injection, buffer overflow, etc. "
        "If a term MUST be mentioned, briefly define it.\n"
        "Focus on the real-world impact (example: 'attackers could steal customer data', "
        "'attackers could take control of the system', etc.).\n"
        "Give a risk tone: Low / Medium / High / Critical (based on the CVSS score).\n"
        "Maximum 5 sentences.\n"
        "Do NOT invent details that are not present.\n"
        "Write in clear business language.\n\n"
        "FORMAT:\n"
        "Short Summary: <1-sentence human-friendly explanation>\n"
        "Impact: <what could realistically happen>\n"
        "Risk Level: <Low/Medium/High/Critical based on score>\n"
        "Action: <recommended response, keep general, no configs>\n\n"
        "EXAMPLE:\n"
        "Original: 'Improper input validation in Apache module enables crafted request to execute arbitrary code remotely.'\n"
        "Rewritten:\n"
        "Short Summary: An attacker could send a malicious request and take over the server.\n"
        "Impact: If exploited, the attacker could run programs, change files, or steal information.\n"
        "Risk Level: Critical.\n"
        "Action: Update the software as soon as possible."
    )
    
    user_prompt = (
        f"Rewrite the following vulnerability for a non-technical audience:\n\n"
        f"CVE ID: {cve_id}\n"
        f"Technical description:\n{description}\n"
    )


    headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": PERPLEXITY_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 220,
        "temperature": 0.2,
    }

    try:
        resp = requests.post(
            PERPLEXITY_API_URL,
            headers=headers,
            json=payload,
            timeout=25,
        )
        resp.raise_for_status()
        data = resp.json()

        simplified = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )

        if not simplified:
            logger.warning(f"Perplexity returned empty content for {cve_id}")
            return description

        logger.info(f"Got simplified description for {cve_id} from Perplexity")
        return simplified

    except Exception as e:
        logger.error(f"Error calling Perplexity API for {cve_id}: {e}")
        return description


def patch_with_scrape(cves):
    total_cves = len(cves)
    for idx, (cveid, cvedata) in enumerate(cves.items(), 1):
        if not cvedata.get("summary"):
            logger.info(f"Patching {cveid} ({idx}/{total_cves})...")
            description, cvss = scrape_cve_details_selenium(cveid)

            if description and description != "Description not available":
                cvedata["summary"] = description

                # New: AI-based plain-language summary
                simplified = simplify_description(description, cveid)
                if simplified and simplified != description:
                    cvedata["summary_plain"] = simplified

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
            .plain-box {{ background-color: #f1f3f5; padding: 15px; border-left: 4px solid #28a745; margin: 10px 0; }}
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
            except Exception:
                severity_class = "metadata"
        else:
            severity_class = "metadata"

        plain_summary = cvedata.get("summary_plain")

        item_html = f"""
        <div class="cve-item">
            <h3 class="cve-title">{cveid}</h3>
            <p class="metadata">
                <strong>CVSS Score:</strong> <span class="{severity_class}">{cvss}</span> | 
                <strong>Source:</strong> {cvedata.get("source", "Unknown")} | 
                <strong>Published:</strong> {cvedata.get("published", "Unknown")}
            </p>
            <div class="description-box">
                <strong>Description (technical):</strong><br>
                {cvedata.get("summary", "No description available")}
            </div>
        """

        if plain_summary:
            item_html += f"""
            <div class="plain-box">
                <strong>Plain-language summary (AI-generated):</strong><br>
                {plain_summary}
            </div>
            """

        item_html += f"""
            <p><strong>🔗 Reference:</strong> <a href="{cvedata.get("url", "")}" style="color: #007bff;">{cvedata.get("url", "")}</a></p>
        </div>
        """

        html += item_html

    html += """
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <div style="text-align: center; color: #666; font-size: 12px;">
            <p>This alert was generated by CVE Monitor System.</p>
            <p>Plain-language summaries are generated by an AI assistant. Always verify details with the official CVE reference.</p>
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

