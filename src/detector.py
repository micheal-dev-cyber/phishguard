import json
import re
from pathlib import Path

# Load keywords from JSON
KEYWORDS_PATH = Path(__file__).parent.parent / "data" / "phishing_keywords.json"
with open(KEYWORDS_PATH, "r") as f:
    PHISHING_KEYWORDS = json.load(f)

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r'http://(?!https)',                    # HTTP not HTTPS
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', # IP address URLs
    r'bit\.ly|tinyurl|t\.co|ow\.ly',       # URL shorteners
    r'[a-z0-9]{20,}\.',                    # Very long random subdomains
    r'paypal\.(?!com)',                     # Fake PayPal domains
    r'amazon\.(?!com|co\.|ca|de|fr)',      # Fake Amazon domains
    r'secure-.*\.com',                     # "secure-" prefix scam
    r'login-.*\.com',                      # "login-" prefix scam
    r'verify-.*\.com',                     # "verify-" prefix scam
]


def extract_urls(text: str) -> list:
    """Extract all URLs from email text."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def check_urls(urls: list) -> dict:
    """Analyze URLs for suspicious patterns."""
    suspicious = []
    for url in urls:
        flags = []
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                flags.append(pattern)
        if flags:
            suspicious.append({"url": url, "flags": flags})
    return suspicious


def scan_keywords(text: str) -> dict:
    """Scan text for phishing keyword categories."""
    text_lower = text.lower()
    results = {}
    total_hits = 0

    for category, keywords in PHISHING_KEYWORDS.items():
        hits = [kw for kw in keywords if kw in text_lower]
        if hits:
            results[category] = hits
            total_hits += len(hits)

    return results, total_hits


def calculate_risk_score(keyword_hits: int, url_count: int,
                          suspicious_urls: int, has_attachments: bool) -> dict:
    """Calculate a 0-100 risk score."""
    score = 0

    # Keyword scoring
    score += min(keyword_hits * 8, 40)  # max 40 points from keywords

    # URL scoring
    score += min(suspicious_urls * 15, 30)  # max 30 points from bad URLs
    score += min(url_count * 2, 10)          # max 10 points from URL count

    # Attachment flag
    if has_attachments:
        score += 15

    # Cap at 100
    score = min(score, 100)

    # Severity label
    if score >= 75:
        severity = "CRITICAL"
        color = "#FF0000"
    elif score >= 50:
        severity = "HIGH"
        color = "#FF6600"
    elif score >= 25:
        severity = "MEDIUM"
        color = "#FFAA00"
    else:
        severity = "LOW"
        color = "#00AA00"

    return {
        "score": score,
        "severity": severity,
        "color": color
    }


def detect_attachments(text: str) -> bool:
    """Detect if email mentions attachments."""
    attachment_keywords = [
        "attachment", "attached", "see the file", "open the document",
        "download", ".zip", ".exe", ".pdf", ".doc", "invoice attached"
    ]
    return any(kw in text.lower() for kw in attachment_keywords)


def analyze_email(email_text: str) -> dict:
    """Main function — full phishing analysis."""
    
    urls = extract_urls(email_text)
    suspicious_urls = check_urls(urls)
    keyword_matches, total_hits = scan_keywords(email_text)
    has_attachments = detect_attachments(email_text)
    risk = calculate_risk_score(
        total_hits, len(urls), len(suspicious_urls), has_attachments
    )

    return {
        "risk_score": risk["score"],
        "severity": risk["severity"],
        "severity_color": risk["color"],
        "keyword_matches": keyword_matches,
        "total_keyword_hits": total_hits,
        "urls_found": urls,
        "suspicious_urls": suspicious_urls,
        "has_attachments": has_attachments,
        "url_count": len(urls),
        "suspicious_url_count": len(suspicious_urls),
    }