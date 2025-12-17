import json
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
        "Analyze the following vulnerability description and extract/infer the following details:\n"
        "- Affected Versions\n"
        "- Impact (what an attacker could do)\n"
        "- Mitigation (suggested action)\n\n"
        "Rules:\n"
        "- Do not use security jargon like IDOR, SQL injection, XSS, etc. in the Impact/Mitigation unless necessary.\n"
        "- Focus on real-world consequences.\n"
        "- Be concise.\n"
        "- Do not invent details.\n\n"
        "Output format:\n"
        "Return ONLY a valid JSON object with the following keys:\n"
        "{\n"
        '  "affected_versions": "...",\n'
        '  "impact": "...",\n'
        '  "mitigation": "..."\n'
        "}\n"
        "Do not include markdown formatting (like ```json).\n\n"
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
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )

        # Clean up markdown code blocks if present
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        if not content:
            logger.warning(f"Perplexity returned empty content for {cve_id}")
            return description

        # Validate JSON
        try:
            json.loads(content)
            logger.info(f"Got simplified description for {cve_id} from Perplexity")
            return content
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON from Perplexity for {cve_id}: {content}")
            return description

    except Exception as e:
        logger.error(f"Error calling Perplexity API: {e}")
        return description

    except Exception as e:
        logger.error(f"Error calling Perplexity API for {cve_id}: {e}")
        return description
