import logging
import time
from typing import Dict

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException

from .ai_simplifer import simplify_description
from .config import SCRAPE_POLITE_DELAY, SCRAPE_TIMEOUT

logger = logging.getLogger(__name__)


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
    options.add_argument(
        "--user-agent=Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-plugins")
    options.add_argument("--no-first-run")
    options.add_argument("--disable-default-apps")

    # Better modern website compatibility
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

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


def scrape_cve_details_selenium(cve_id: str):
    logger.info(f"Scraping {cve_id} using Selenium")

    driver = None
    description = ""
    cvss_score = "N/A"

    for attempt in range(2):
        try:
            driver = get_chrome_driver()

            # Try CVE.org first
            cve_org_url = f"https://www.cve.org/CVERecord?id={cve_id}"
            logger.info(
                f"Loading CVE.org page: {cve_org_url} (attempt {attempt + 1})"
            )

            driver.get(cve_org_url)
            time.sleep(5)  # wait for JS

            cve_org_selectors = [
                '//p[@class="content cve-x-scroll"]',
                '//div[@id="cve-description"]//p[@class="content cve-x-scroll"]',
                '//div[@id="cve-description"]//p',
                '//div[contains(@class,"cve-description")]//p',
                '//p[contains(@class,"content")]',
                '//div[@id="cve-cna-container-start"]//p[@class="content cve-x-scroll"]',
                '//div[@class="content"]//p[@class="content cve-x-scroll"]',
            ]

            for i, selector in enumerate(cve_org_selectors):
                try:
                    logger.info(f"Trying CVE.org description selector {i+1}: {selector}")
                    desc_elem = driver.find_element(By.XPATH, selector)
                    if desc_elem and desc_elem.text.strip():
                        description = desc_elem.text.strip()
                        logger.info(
                            f"Found description using CVE.org selector {i+1}"
                        )
                        break
                except NoSuchElementException:
                    logger.info(
                        f"CVE.org description selector {i+1} failed"
                    )
                    continue

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
                '//span[contains(@class,"score")]',
            ]

            for i, selector in enumerate(cvss_selectors_cve_org):
                try:
                    logger.info(f"Trying CVE.org CVSS selector {i+1}: {selector}")
                    cvss_elem = driver.find_element(By.XPATH, selector)
                    if cvss_elem and cvss_elem.text.strip():
                        cvss_text = cvss_elem.text.strip()
                        import re

                        score_match = re.search(r"(\d+\.?\d*)", cvss_text)
                        if score_match:
                            cvss_score = score_match.group(1)
                        else:
                            cvss_score = cvss_text
                        logger.info(
                            f"Found CVSS on CVE.org using selector {i+1}: {cvss_score}"
                        )
                        break
                except NoSuchElementException:
                    logger.info(
                        f"CVE.org CVSS selector {i+1} failed"
                    )
                    continue

            if description:
                break

            # MITRE fallback
            if not description:
                logger.info(f"No description on CVE.org, trying MITRE for {cve_id}")
                mitre_url = (
                    f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                )
                try:
                    driver.get(mitre_url)
                    time.sleep(3)

                    mitre_selectors = [
                        '//table[@id="TableWithBorder"]//td[contains(text(),"Description")]/following-sibling::td',
                        '//table[@id="TableWithBorder"]//tr[td[contains(text(),"Description")]]/td[2]',
                        '//table//td[contains(text(),"Description")]/../td[2]',
                        '//table//tr[contains(.,"Description")]/td[2]',
                        '//td[contains(text(),"Description")]/following-sibling::td[1]',
                        '//table//td[normalize-space(text())="Description"]/following-sibling::td',
                    ]

                    for i, selector in enumerate(mitre_selectors):
                        try:
                            logger.info(f"Trying MITRE selector {i+1}: {selector}")
                            desc_elem = driver.find_element(By.XPATH, selector)
                            if desc_elem and desc_elem.text.strip():
                                description = desc_elem.text.strip()
                                logger.info(
                                    f"Found description using MITRE selector {i+1}"
                                )
                                break
                        except NoSuchElementException:
                            logger.info(f"MITRE selector {i+1} failed")
                            continue
                except Exception as e:
                    logger.warning(f"MITRE scraping failed for {cve_id}: {e}")

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

    final_description = (
        description if description else "Description not available"
    )
    logger.info(
        f"Final result for {cve_id}: description_length={len(final_description)}, "
        f"cvss={cvss_score}"
    )

    return final_description, cvss_score


def patch_with_scrape(cves: Dict[str, dict]) -> Dict[str, dict]:
    """Fill in missing summaries and CVSS scores (plus AI plain-language summaries)."""
    total_cves = len(cves)
    for idx, (cveid, cvedata) in enumerate(cves.items(), 1):
        if not cvedata.get("summary"):
            logger.info(f"Patching {cveid} ({idx}/{total_cves})...")
            description, cvss = scrape_cve_details_selenium(cveid)

            if description and description != "Description not available":
                cvedata["summary"] = description

                simplified = simplify_description(description, cveid, cvss)
                if simplified and simplified != description:
                    cvedata["summary_plain"] = simplified

            if cvss and cvss != "N/A":
                cvedata["cvss_score"] = cvss

            if idx < total_cves:
                time.sleep(SCRAPE_POLITE_DELAY)

    return cves
