import logging

from .circl_client import fetch_circl_cves
from .config import EMAIL_PASS, EMAIL_USER
from .emailer import send_summary_email
from .scrapper import patch_with_scrape
from .storage import load_seen, save_seen

logger = logging.getLogger(__name__)


def main() -> None:
    logger.info("CVE Alert System Started")
    try:
        if not EMAIL_USER or not EMAIL_PASS:
            logger.error(
                "EMAIL_USER or EMAIL_PASS not set in environment variables"
            )
            return

        seen_cves = load_seen()
        logger.info(f"Loaded {len(seen_cves)} previously seen CVEs")

        circl_cves = fetch_circl_cves()
        if not circl_cves:
            logger.warning("No CVEs fetched from CIRCL")
            return

        new_cve_ids = set(circl_cves.keys()) - seen_cves

        if new_cve_ids:
            logger.info(
                f"Found {len(new_cve_ids)} new CVEs: {sorted(new_cve_ids)}"
            )
            new_cves_data = {
                cveid: circl_cves[cveid] for cveid in sorted(new_cve_ids)
            }

            logger.info("Fetching detailed information with Selenium...")
            patched_cves = patch_with_scrape(new_cves_data)

            if send_summary_email(patched_cves):
                logger.info("Email sent successfully")
            else:
                logger.error("Failed to send email")

            seen_cves.update(new_cve_ids)
            save_seen(seen_cves)
            logger.info(f"Updated seen CVEs, total: {len(seen_cves)}")

        else:
            logger.info("No new CVEs found")

        logger.info("CVE Alert System Completed Successfully")

    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        raise
