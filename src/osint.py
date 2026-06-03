import logging
import re
import socket
from datetime import datetime

import requests

from src.env import ENV

logger = logging.getLogger(__name__)

VT_API_KEY = ENV.VIRUSTOTAL_API_KEY


# ── Extraction helpers ─────────────────────────────────────────────────────────

def extract_domains(text: str) -> list:
    """Extract all unique domains from text."""
    url_pattern = r'https?://([^\s/]+)'
    email_pattern = r'[\w\.-]+@([\w\.-]+)'

    domains = []
    domains += re.findall(url_pattern, text, re.IGNORECASE)
    domains += re.findall(email_pattern, text, re.IGNORECASE)

    # Clean and deduplicate
    cleaned = []
    for d in domains:
        d = d.strip().lower().rstrip('/')
        if d and '.' in d and d not in cleaned:
            cleaned.append(d)

    return cleaned[:10]  # Max 10 domains


def extract_ips(text: str) -> list:
    """Extract IP addresses from text."""
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    # Filter out common false positives
    return list(set([
        ip for ip in ips
        if not ip.startswith('192.168') and
           not ip.startswith('10.') and
           not ip.startswith('127.')
    ]))[:5]


def extract_sender_email(text: str) -> str:
    """Extract the primary sender email."""
    from_match = re.search(r'from:\s*.*?([\w\.-]+@[\w\.-]+)', text, re.IGNORECASE)
    if from_match:
        return from_match.group(1)
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    return email_match.group() if email_match else ""


# ── Domain investigation ───────────────────────────────────────────────────────

def investigate_domain(domain: str) -> dict:
    """Full domain investigation using free APIs."""
    result = {
        "domain": domain,
        "ip": None,
        "country": None,
        "org": None,
        "domain_age_days": None,
        "creation_date": None,
        "is_new_domain": False,
        "blacklisted": False,
        "blacklist_count": 0,
        "mx_records": [],
        "risk_indicators": [],
        "risk_score": 0,
    }

    # ── 1. Resolve domain to IP ────────────────────────────────────────────────
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
    except Exception as e:
        logger.warning("osint: Failed to resolve domain %s: %s", domain, e)
        result["risk_indicators"].append("Domain does not resolve — possibly fake")
        result["risk_score"] += 30
        return result

    # ── 2. IP Geolocation (free API) ──────────────────────────────────────────
    try:
        geo = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,org,isp,hosting",
            timeout=8
        ).json()

        result["country"] = geo.get("country", "Unknown")
        result["org"]     = geo.get("org", geo.get("isp", "Unknown"))

        # Hosting providers are suspicious for phishing
        if geo.get("hosting"):
            result["risk_indicators"].append(
                "Hosted on a data center/VPS — common for phishing sites"
            )
            result["risk_score"] += 10

    except Exception as e:
        logger.warning("osint: IP geolocation failed for %s: %s", ip, e)

    # ── 3. WHOIS domain age check (free API) ──────────────────────────────────
    try:
        whois_data = requests.get(
            f"https://api.whoisfreaks.com/v1.0/whois?apiKey=free&whois=live&domainName={domain}",
            timeout=10
        ).json()

        created = whois_data.get("create_date", "")
        if created:
            try:
                created_dt = datetime.strptime(created[:10], "%Y-%m-%d")
                age_days = (datetime.now() - created_dt).days
                result["domain_age_days"] = age_days
                result["creation_date"]   = created[:10]

                if age_days < 30:
                    result["is_new_domain"] = True
                    result["risk_indicators"].append(
                        f"Domain created {age_days} days ago — very new, high phishing risk"
                    )
                    result["risk_score"] += 35
                elif age_days < 90:
                    result["risk_indicators"].append(
                        f"Domain created {age_days} days ago — relatively new"
                    )
                    result["risk_score"] += 15
            except Exception as e:
                logger.warning("osint: Failed to parse WHOIS date for %s: %s", domain, e)
    except Exception as e:
        logger.warning("osint: WHOIS lookup failed for %s: %s", domain, e)

    # ── 4. VirusTotal domain check ─────────────────────────────────────────────
    if VT_API_KEY:
        try:
            headers = {"x-apikey": VT_API_KEY}
            vt_resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
                timeout=10
            )

            if vt_resp.status_code == 200:
                vt_data  = vt_resp.json()
                attrs    = vt_data.get("data", {}).get("attributes", {})
                stats    = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                result["blacklist_count"] = malicious

                if malicious >= 3:
                    result["blacklisted"] = True
                    result["risk_indicators"].append(
                        f"Domain flagged by {malicious} security vendors on VirusTotal"
                    )
                    result["risk_score"] += 40
                elif malicious >= 1 or suspicious >= 2:
                    result["risk_indicators"].append(
                        f"Domain flagged by {malicious} vendors as malicious, {suspicious} as suspicious"
                    )
                    result["risk_score"] += 20

        except Exception as e:
            logger.warning("osint: VirusTotal lookup failed for %s: %s", domain, e)

    # ── 5. Suspicious domain pattern checks ───────────────────────────────────
    suspicious_patterns = [
        (r'paypal|amazon|microsoft|apple|google|netflix|bank|irs',
         "Brand name in domain — possible impersonation"),
        (r'secure|login|verify|update|confirm|account|banking',
         "Deceptive keyword in domain name"),
        (r'\d{4,}',
         "Excessive numbers in domain — common in auto-generated phishing domains"),
        (r'[a-z]{15,}\.',
         "Very long domain name — common phishing pattern"),
        (r'\.xyz$|\.tk$|\.ml$|\.ga$|\.cf$',
         "High-risk TLD commonly used for phishing"),
        (r'\.ru$|\.cn$|\.pw$',
         "Geographic TLD associated with high phishing activity"),
    ]

    for pattern, message in suspicious_patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            result["risk_indicators"].append(message)
            result["risk_score"] += 10

    result["risk_score"] = min(result["risk_score"], 100)
    return result


# ── IP investigation ───────────────────────────────────────────────────────────

def investigate_ip(ip: str) -> dict:
    """Investigate a raw IP address."""
    result = {
        "ip": ip,
        "country": None,
        "org": None,
        "is_hosting": False,
        "risk_indicators": [],
        "risk_score": 0,
    }

    try:
        geo = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,org,isp,hosting,proxy,tor",
            timeout=8
        ).json()

        result["country"]    = geo.get("country", "Unknown")
        result["org"]        = geo.get("org", "Unknown")
        result["is_hosting"] = geo.get("hosting", False)

        if geo.get("tor"):
            result["risk_indicators"].append("IP is a TOR exit node — anonymization tool")
            result["risk_score"] += 40

        if geo.get("proxy"):
            result["risk_indicators"].append("IP is a known proxy/VPN — identity concealment")
            result["risk_score"] += 25

        if geo.get("hosting"):
            result["risk_indicators"].append("IP belongs to a hosting provider — VPS/cloud server")
            result["risk_score"] += 15

    except Exception as e:
        logger.warning("osint: IP investigation failed for %s: %s", ip, e)
        result["risk_indicators"].append("Could not investigate IP")

    return result


# ── Full OSINT analysis ────────────────────────────────────────────────────────

def run_osint(email_text: str) -> dict:
    """Run full OSINT investigation on email content."""

    sender      = extract_sender_email(email_text)
    domains     = extract_domains(email_text)
    ips         = extract_ips(email_text)

    domain_results = []
    ip_results     = []

    # Investigate domains
    for domain in domains[:5]:  # Max 5 domains
        result = investigate_domain(domain)
        domain_results.append(result)

    # Investigate IPs
    for ip in ips[:3]:  # Max 3 IPs
        result = investigate_ip(ip)
        ip_results.append(result)

    # Calculate overall OSINT risk
    total_risk = 0
    if domain_results:
        total_risk = max(r["risk_score"] for r in domain_results)

    high_risk_domains  = [r for r in domain_results if r["risk_score"] >= 50]
    new_domains        = [r for r in domain_results if r["is_new_domain"]]
    blacklisted        = [r for r in domain_results if r["blacklisted"]]

    return {
        "sender":            sender,
        "domains_found":     domains,
        "domain_results":    domain_results,
        "ip_results":        ip_results,
        "high_risk_domains": high_risk_domains,
        "new_domains":       new_domains,
        "blacklisted":       blacklisted,
        "osint_risk_score":  total_risk,
        "total_indicators":  sum(len(r["risk_indicators"]) for r in domain_results),
    }
