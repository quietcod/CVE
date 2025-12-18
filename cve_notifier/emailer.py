import logging
import smtplib
import time
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Iterable
from datetime import datetime

from .config import EMAIL_PASS, EMAIL_USER, SMTP_HOST, SMTP_PORT, RECIPIENTS

logger = logging.getLogger(__name__)


def format_date(date_str: str) -> str:
    """Convert raw CVE timestamp into: DD-MM-YYYY at HH:MM:SS UTC"""
    if not date_str or date_str.lower() == "unknown":
        return "Unknown"

    patterns = [
        "%Y-%m-%dT%H:%M:%S.%fZ",  # example: 2025-01-14T21:32:00.000Z
        "%Y-%m-%dT%H:%M:%SZ",     # example: 2025-01-14T21:32:00Z
        "%Y-%m-%d",               # fallback format: 2025-01-14
    ]

    for pattern in patterns:
        try:
            dt = datetime.strptime(date_str, pattern)
            return dt.strftime("%d-%m-%Y at %H:%M:%S UTC")
        except ValueError:
            continue

    # If no pattern matches, return raw string as fallback
    return date_str


def send_summary_email(
    new_cves: Dict[str, dict],
) -> bool:
    """Send the HTML summary email for the new CVEs."""
    if not EMAIL_USER or not EMAIL_PASS:
        logger.error("Email credentials not configured")
        return False

    recipients: list[str] = list(RECIPIENTS)
    if not recipients:
        logger.error("No recipients configured (RECIPIENTS is empty)")
        return False

    subject = f"{len(new_cves)} Vulnerabilities Found"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"CVE Alert <{EMAIL_USER}>"
    # msg["To"] will be set individually for each recipient

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
            <h2 style="margin: 0; color: #d73027;">{len(new_cves)} Vulnerabilities Found</h2>
            <p style="margin: 10px 0 0 0; color: #666;">Detected on {time.strftime('%d-%m-%Y at %H:%M:%S UTC')}</p>
        </div>
    """

    for cveid, cvedata in new_cves.items():
        cvss = cvedata.get("cvss_score", "N/A")
        severity_label = "Unknown"
        severity_class = "metadata"

        if cvss != "N/A":
            try:
                cvss_num = float(cvss)
                if cvss_num >= 9.0:
                    severity_label = "Critical"
                    severity_class = "cvss-high"
                elif cvss_num >= 7.0:
                    severity_label = "High"
                    severity_class = "cvss-high"
                elif cvss_num >= 4.0:
                    severity_label = "Medium"
                    severity_class = "cvss-medium"
                else:
                    severity_label = "Low"
                    severity_class = "cvss-low"
            except Exception:
                pass

        plain_summary = cvedata.get("summary_plain")
        ai_data = {}
        if plain_summary:
            try:
                ai_data = json.loads(plain_summary)
            except json.JSONDecodeError:
                # Fallback if it's just text (e.g. API failed and returned description)
                pass

        publish_date = format_date(cvedata.get("published", "Unknown"))

        item_html = f"""
        <div class="cve-item">
            <ul style="list-style-type: disc; padding-left: 20px; margin: 0;">
                <li style="margin-bottom: 5px;"><strong>CVE ID:</strong> {cveid}</li>
                <li style="margin-bottom: 5px;"><strong>Published:</strong> {publish_date}</li>
                <li style="margin-bottom: 5px;"><strong>CVSS Score:</strong> <span class="{severity_class}">{cvss} ({severity_label})</span></li>
                <li style="margin-bottom: 5px;"><strong>Full Description:</strong> "{cvedata.get("summary", "No description available")}"</li>
        """

        if ai_data.get("affected_versions"):
            item_html += f'<li style="margin-bottom: 5px;"><strong>Affected Versions:</strong> {ai_data["affected_versions"]}</li>'
        
        if ai_data.get("impact"):
            item_html += f'<li style="margin-bottom: 5px;"><strong>Impact:</strong> {ai_data["impact"]}</li>'
            
        if ai_data.get("mitigation"):
            item_html += f'<li style="margin-bottom: 5px;"><strong>Mitigation:</strong> {ai_data["mitigation"]}</li>'

        item_html += f"""
            </ul>
            <p style="margin-top: 15px;"><strong>🔗 Reference:</strong> <a href="{cvedata.get("url", "")}" style="color: #007bff;">{cvedata.get("url", "")}</a></p>
        </div>
        """

        html += item_html

    html += """
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <div style="text-align: center; color: Red; font-size: 12px;">
            <p>Plain-language summaries are generated by an AI assistant.</p>
            <p>Always verify details with the official CVE reference.</p>
        </div>
    </body>
    </html>
    """

    msg.attach(MIMEText(html, "html"))

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)

        # Send individual emails to each recipient
        for recipient in recipients:
            # Create a copy of the message object or just update the 'To' header
            # Updating the header on the same object is risky if we were doing this async,
            # but in a simple loop it's fine as long as we reset it or use a fresh object.
            # However, 'msg' is already fully constructed.
            # The safest way is to update the 'To' header before sending each time.
            
            del msg["To"]
            msg["To"] = recipient
            
            server.sendmail(EMAIL_USER, [recipient], msg.as_string())
        
        server.quit()

        logger.info(
            f"✅ Summary email sent for {len(new_cves)} CVEs to {len(recipients)} recipients"
        )
        return True

    except Exception as e:
        logger.error(f"❌ Error sending summary email: {e}")
        return False

