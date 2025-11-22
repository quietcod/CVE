# Required environment variables:
# EMAIL_USER          → Email sender login
# EMAIL_PASS          → App password
# PERPLEXITY_API_KEY  → (optional) enables AI summaries when AI_ENABLED=true
# AI_ENABLED          → "true" or "false"

import os

# API + scraping config
API_TIMEOUT = 30
SCRAPE_TIMEOUT = 25
SCRAPE_POLITE_DELAY = 2
CIRCL_API_URL = "https://cve.circl.lu/api/last"

# Email config
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

# Recipients + state file
RECIPIENTS = ["quietcod@protonmail.com"]
SEEN_FILE = "seen_cves.json"

# Perplexity AI config
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY")
AI_ENABLED = os.getenv("AI_ENABLED", "false").lower() == "true"
PERPLEXITY_MODEL = os.getenv("PERPLEXITY_MODEL", "sonar-small-chat")
PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
