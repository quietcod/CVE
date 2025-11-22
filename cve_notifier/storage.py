import json
import logging
import os
from typing import Set

from .config import SEEN_FILE

logger = logging.getLogger(__name__)


def load_seen() -> Set[str]:
    """Load previously seen CVE IDs from disk."""
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return set(data)
                if isinstance(data, dict) and "cves" in data:
                    return set(data["cves"].keys())
                return set(data)
        except Exception as e:
            logger.warning(f"Error loading seen CVEs: {e}")
    return set()


def save_seen(cve_set: Set[str]) -> None:
    """Persist the set of seen CVE IDs to disk."""
    try:
        with open(SEEN_FILE, "w") as f:
            json.dump(sorted(list(cve_set)), f, indent=2)
        logger.info(f"Saved {len(cve_set)} CVEs to {SEEN_FILE}")
    except Exception as e:
        logger.error(f"Error saving seen CVEs: {e}")
