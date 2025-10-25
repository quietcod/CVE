"""
Enhanced CVE Alert System using OSV.dev API
Fetches latest vulnerabilities from multiple sources and sends email alerts
"""

import requests
import smtplib
import json
import os
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
OSV_API_URL = "https://api.osv.dev/v1/query"
CIRCL_API_URL = "https://cve.circl.lu/api/last"

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

RECIPIENTS = ["quietcod@protonmail.com"]
SEEN_FILE = "seen_cves.json"

# Store CVE details for email formatting
CVE_DETAILS = {}


def load_seen():
    """Load previously seen CVE IDs to avoid duplicates"""
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, "r") as f:
                data = json.load(f)
                # Handle both list and dict formats
                if isinstance(data, list):
                    return set(data)
                elif isinstance(data, dict) and "cves" in data:
                    return set(data["cves"].keys())
                return set(data)
        except Exception as e:
            logger.warning(f"Error loading seen CVEs: {e}")
    return set()


def save_seen(cve_dict):
    """Save seen CVE IDs and their details"""
    try:
        with open(SEEN_FILE, "w") as f:
            json.dump(cve_dict, f, indent=2)
        logger.info(f"Saved {len(cve_dict)} CVEs to seen_cves.json")
    except Exception as e:
        logger.error(f"Error saving seen CVEs: {e}")


def fetch_osv_cves():
    """
    Fetch latest CVEs from OSV.dev API
    OSV provides real-time vulnerability data across multiple ecosystems
    """
    logger.info("Fetching CVEs from OSV.dev API...")
    cves = {}
    
    try:
        # Query for recently published vulnerabilities
        payload = {
            "page_token": None,
            "page_size": 100  # Fetch up to 100 latest
        }
        
        response = requests.post(OSV_API_URL, json=payload, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        vulns = data.get("vulns", [])
        
        logger.info(f"Retrieved {len(vulns)} vulnerabilities from OSV.dev")
        
        for vuln in vulns:
            cve_id = vuln.get("id", "").strip()
            
            # Filter for CVEs (not other vulnerability formats)
            if not cve_id.startswith("CVE-"):
                continue
            
            # Extract metadata
            published_date = vuln.get("published", "")
            modified_date = vuln.get("modified", "")
            summary = vuln.get("summary", "No description available")
            details = vuln.get("details", "")
            
            # Get CVSS score if available
            cvss_score = "N/A"
            if "severity" in vuln:
                for severity in vuln.get("severity", []):
                    if severity.get("type") == "CVSS_V3":
                        cvss_score = severity.get("score", "N/A")
                        break
            
            # Get affected packages
            affected_packages = []
            for pkg in vuln.get("affected", []):
                pkg_name = pkg.get("package", {}).get("name", "Unknown")
                ecosystem = pkg.get("package", {}).get("ecosystem", "Unknown")
                affected_packages.append(f"{pkg_name} ({ecosystem})")
            
            cves[cve_id] = {
                "published": published_date,
                "modified": modified_date,
                "summary": summary,
                "details": details,
                "cvss_score": cvss_score,
                "affected_packages": affected_packages[:5],  # Limit to 5
                "source": "OSV.dev",
                "url": f"https://osv.dev/vulnerability/{cve_id}"
            }
        
        logger.info(f"Successfully fetched {len(cves)} CVEs from OSV.dev")
        return cves
        
    except Exception as e:
        logger.error(f"Error fetching from OSV.dev: {e}")
        return {}


def fetch_circl_cves():
    """
    Fetch latest CVEs from CIRCL API
    Provides real-time CVE information with publication timestamps
    """
    logger.info("Fetching CVEs from CIRCL API...")
    cves = {}
    
    try:
        response = requests.get(CIRCL_API_URL, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        logger.info(f"Retrieved {len(data)} CVEs from CIRCL")
        
        for idx, item in enumerate(data[:50]):  # Fetch latest 50
            if isinstance(item, dict):
                cve_id = item.get("id") or item.get("cveMetadata", {}).get("cveId")
            else:
                cve_id = item
            
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            
            if cve_id in cves:
                continue  # Skip if already fetched
            
            published = item.get("cveMetadata", {}).get("datePublished", "") if isinstance(item, dict) else ""
            
            cves[cve_id] = {
                "published": published,
                "modified": "",
                "summary": "Check CIRCL database for details",
                "details": "",
                "cvss_score": "N/A",
                "affected_packages": [],
                "source": "CIRCL",
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            }
        
        logger.info(f"Successfully fetched {len(cves)} CVEs from CIRCL")
        return cves
        
    except Exception as e:
        logger.error(f"Error fetching from CIRCL: {e}")
        return {}



def merge_cves(osv_cves, circl_cves):
    """
    Merge CVEs from multiple sources
    Prioritize OSV.dev data as it's most up-to-date
    """
    all_cves = {}
    
    # Priority order: OSV > CIRCL
    all_cves.update(circl_cves)   # Add CIRCL first (lower priority)
    all_cves.update(osv_cves)     # Overwrite with OSV (highest priority)
    
    logger.info(f"Merged CVEs: {len(all_cves)} unique vulnerabilities")
    return all_cves


def send_html_email(subject, cve_id, cve_data, recipients):
    """Send formatted HTML email with CVE details"""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = ", ".join(recipients)
        
        # Create HTML content
        html = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background-color: #d32f2f; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
                    .content {{ border: 1px solid #ddd; padding: 20px; }}
                    .footer {{ background-color: #f5f5f5; padding: 15px; border-radius: 0 0 5px 5px; font-size: 12px; }}
                    .detail-row {{ margin: 10px 0; }}
                    .label {{ font-weight: bold; color: #555; }}
                    .cvss {{ display: inline-block; padding: 5px 10px; background-color: #ff9800; color: white; border-radius: 3px; }}
                    .source {{ display: inline-block; padding: 3px 8px; background-color: #2196F3; color: white; border-radius: 3px; font-size: 12px; }}
                    a {{ color: #1976D2; text-decoration: none; }}
                    a:hover {{ text-decoration: underline; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>⚠️ New CVE Alert</h1>
                    </div>
                    <div class="content">
                        <div class="detail-row">
                            <span class="label">CVE ID:</span> {cve_id}
                            <span class="source">{cve_data.get('source', 'Unknown')}</span>
                        </div>
                        
                        <div class="detail-row">
                            <span class="label">Description:</span><br/>
                            {cve_data.get('summary', 'No description available')}
                        </div>
                        
                        <div class="detail-row">
                            <span class="label">CVSS Score:</span> 
                            <span class="cvss">{cve_data.get('cvss_score', 'N/A')}</span>
                        </div>
                        
                        <div class="detail-row">
                            <span class="label">Published:</span> {cve_data.get('published', 'N/A')}
                        </div>
                        
                        <div class="detail-row">
                            <span class="label">Last Modified:</span> {cve_data.get('modified', 'N/A')}
                        </div>
                        
                        {f'<div class="detail-row"><span class="label">Affected Packages:</span><br/>{", ".join(cve_data.get("affected_packages", []))}</div>' if cve_data.get('affected_packages') else ''}
                        
                        <div class="detail-row" style="margin-top: 20px;">
                            <a href="{cve_data.get('url', '#')}" style="background-color: #1976D2; color: white; padding: 10px 20px; border-radius: 3px; display: inline-block;">
                                View Full Details
                            </a>
                        </div>
                    </div>
                    <div class="footer">
                        <p>This is an automated alert from your CVE monitoring system.</p>
                        <p>Latest update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    </div>
                </div>
            </body>
        </html>
        """
        
        part = MIMEText(html, "html")
        msg.attach(part)
        
        # Send email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, recipients, msg.as_string())
        
        logger.info(f"Email sent for {cve_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending email for {cve_id}: {e}")
        return False


def main():
    """Main function to orchestrate CVE fetching and alerting"""
    logger.info("=" * 80)
    logger.info("CVE Alert System Started (OSV.dev Enhanced)")
    logger.info("=" * 80)
    
    try:
        # Validate email credentials
        if not EMAIL_USER or not EMAIL_PASS:
            logger.error("EMAIL_USER or EMAIL_PASS not set in environment variables")
            return
        
        # Load previously seen CVEs
        seen_cves = load_seen()
        logger.info(f"Loaded {len(seen_cves)} previously seen CVEs")
        
        # Fetch from multiple sources
        osv_cves = fetch_osv_cves()
        circl_cves = fetch_circl_cves()
        
        # Merge all CVEs
        all_cves = merge_cves(osv_cves, circl_cves)
        
        if not all_cves:
            logger.warning("No CVEs fetched from any source")
            return
        
        # Find new CVEs
        new_cve_ids = set(all_cves.keys()) - seen_cves
        
        if new_cve_ids:
            logger.info(f"Found {len(new_cve_ids)} new CVEs")
            
            # Send alerts for new CVEs
            sent_count = 0
            for cve_id in sorted(new_cve_ids):
                cve_data = all_cves[cve_id]
                subject = f"🚨 New CVE Alert: {cve_id} (CVSS: {cve_data.get('cvss_score', 'N/A')})"
                
                if send_html_email(subject, cve_id, cve_data, RECIPIENTS):
                    sent_count += 1
                    seen_cves.add(cve_id)
            
            logger.info(f"Successfully sent {sent_count}/{len(new_cve_ids)} alerts")
            
            # Save updated seen CVEs
            save_seen(seen_cves)
        else:
            logger.info("No new CVEs found")
        
        logger.info("=" * 80)
        logger.info("CVE Alert System Completed Successfully")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        
        # Send error notification
        try:
            error_subject = f"⛔ CVE Alert System Error - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            error_body = f"""
Error in CVE Alert System:

{str(e)}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

Please check the logs for more details.
"""
            send_html_email(error_subject, "ERROR", {"summary": error_body, "source": "System", "cvss_score": "N/A", "published": "", "modified": "", "affected_packages": [], "url": ""}, RECIPIENTS)
        except:
            logger.error("Could not send error notification email")


if __name__ == "__main__":
    main()
