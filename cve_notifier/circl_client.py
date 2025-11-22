import logging
import os
from typing import Dict

import requests

from .config import API_TIMEOUT, CIRCL_API_URL

logger = logging.getLogger(__name__)


def fetch_circl_cves() -> Dict[str, dict]:
    """Fetch the latest CVEs from CIRCL and normalize them into a dict."""
    logger.info("Fetching CVEs from CIRCL API...")
    try:
        headers = {
            "User-Agent": "CVE-Monitor/1.0 (+https://github.com/quietcod/CVE)"
        }
        response = requests.get(
            CIRCL_API_URL,
            timeout=API_TIMEOUT,
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
        logger.info(f"Retrieved {len(data)} CVEs from CIRCL")

        # DEBUG structure
        logger.info("=== DEBUG: CIRCL API Response Structure ===")
        logger.info(f"Response type: {type(data)}")
        logger.info(f"Response length: {len(data)}")

        if len(data) > 0:
            logger.info("First 3 items:")
            for i, item in enumerate(data[:3]):
                logger.info(f"Item {i+1}: {item}")
                logger.info(f"Item {i+1} type: {type(item)}")

        logger.info("=== END DEBUG ===")

        cves: Dict[str, dict] = {}
        limit = int(os.getenv("CVE_LIMIT", "10"))

        for item in data[:limit]:
            if isinstance(item, dict):
                cve_id = item.get("id") or item.get("cveMetadata", {}).get("cveId")
            else:
                cve_id = item

            if not cve_id or not cve_id.startswith("CVE-") or cve_id in cves:
                continue

            published = (
                item.get("cveMetadata", {}).get("datePublished", "")
                if isinstance(item, dict)
                else ""
            )
            cves[cve_id] = {
                "published": published,
                "summary": "",
                "cvss_score": "N/A",
                "source": "CIRCL",
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            }

        logger.info(f"Final processed CVEs: {list(cves.keys())}")
        return cves

    except Exception as e:
        logger.error(f"Error fetching from CIRCL: {e}")
        return {}
