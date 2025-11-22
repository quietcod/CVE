import logging
from typing import Optional

import requests

from .config import (
    AI_ENABLED,
    PERPLEXITY_API_KEY,
    PERPLEXITY_API_URL,
    PERPLEXITY_MODEL,
)

logger = logging.getLogger(__name__)


def simplify_description(
    description: str, cve_id: str, cvss_score: Optional[str] = None
) -> str:
    """
    Use Perplexity to turn a technical CVE description into
    a plain-language explanation for non-technical readers.
    On any failure, returns the original description.
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

    score_text = cvss_score or "N/A"

    system_prompt = (
        "You are a cybersecurity risk translator. Your job is to rewrite technical "
        "vulnerability descriptions into simple terms for non-technical people such as CEOs, "
        "managers, or small business owners.\n\n"
        "RULES:\n"
        "Do NOT copy the original sentence structure.\n"
        "Avoid technical terms such as RCE, SQL injection, buffer overflow, etc. "
        "If a term MUST be mentioned, briefly define it.\n"
        "Focus on the real-world impact (example: 'attackers could steal customer data', "
        "'attackers could take control of the system').\n"
        "Give a risk tone: Low / Medium / High / Critical (based on the CVSS score if given).\n"
        "Maximum 5 sentences.\n"
        "Do NOT invent extra details that are not present in the original description.\n"
        "Write in clear business language.\n\n"
        "FORMAT:\n"
        "Short Summary: <1-sentence human-friendly explanation>\n"
        "Impact: <what could realistically happen>\n"
        "Risk Level: <Low/Medium/High/Critical>\n"
        "Action: <high-level recommended response>\n\n"
        "EXAMPLE:\n"
        "Original: 'Improper input validation in Apache module enables crafted request to execute arbitrary code remotely.'\n"
        "Rewritten:\n"
        "Short Summary: An attacker could send a malicious request and take over the server.\n"
        "Impact: If exploited, the attacker could run programs, change files, or steal information.\n"
        "Risk Level: Critical.\n"
        "Action: Update the software as soon as possible.\n"
    )

    user_prompt = (
        f"Rewrite the following vulnerability for a non-technical audience.\n\n"
        f"CVE ID: {cve_id}\n"
        f"CVSS Score (if known): {score_text}\n\n"
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
