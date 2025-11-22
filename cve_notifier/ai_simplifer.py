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

    # Build a single user message, like your working project
    user_prompt = (
        "Rewrite the following vulnerability description for a non-technical audience.\n\n"
        "Rules:\n"
        "- Do not use security jargon like IDOR, SQL injection, XSS, etc.\n"
        "- Focus on what could actually happen in the real world (data leak, account takeover, etc.).\n"
        "- Use simple business language a manager can understand.\n"
        "- Keep it under 5 sentences.\n"
        "- Do not invent details that are not mentioned.\n\n"
        "Output format:\n"
        "Short Summary: <1 sentence>\n"
        "Impact: <what an attacker could do>\n"
        "Risk Level: <Low/Medium/High/Critical>\n"
        "Action: <high-level recommendation>\n\n"
        f"CVE ID: {cve_id}\n"
        f"CVSS Score (if known): {score_text}\n\n"
        f"Technical description:\n{description}"
    )

    headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json",
    }

    # ⚠ Minimal payload – same style as your working snippet
    payload = {
        "model": PERPLEXITY_MODEL,  # e.g., "sonar-pro"
        "messages": [
            {"role": "user", "content": user_prompt}
        ],
    }

    try:
        resp = requests.post(
            PERPLEXITY_API_URL,
            headers=headers,
            json=payload,
            timeout=25,
        )
        if not resp.ok:
            logger.error(
                "Perplexity API error for %s: status=%s body=%s",
                cve_id,
                resp.status_code,
                resp.text[:500],
            )
            return description

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
