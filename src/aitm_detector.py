import re
from typing import Optional

AITM_URL_PATTERNS = [
    (r"(?:verify|2fa|mfa|otp|auth|authenticator|challenge|totp)",
     "MFA/OTP keyword in URL"),
    (r"(?:login|signin|sign.?in|logon)",
     "Authentication page in URL"),
    (r"(?:token|secret|password|credential|passwd)",
     "Credential harvesting keyword in URL"),
    (r"(?:secure|confirm|update|verification)",
     "Deceptive security keyword in URL"),
    (r"(?:recovery|reset|unlock)",
     "Account recovery page in URL"),
    (r"(?:unusual|suspicious|unauthorized)",
     "Social engineering keyword in URL"),
    (r"(?:code|pin|otp)", "OTP/code keyword in URL"),
]

AITM_BODY_PATTERNS = [
    (r"(?:enter|provide|submit|send|confirm).{,30}(?:verification\s*code|code|OTP|one.?time.?pass)",
     "Requests verification code or OTP"),
    (r"(?:MFA|2FA|multi.?factor|two.?factor).{,40}(?:expire|disabled?|enable|required?|fail)",
     "MFA-related urgency language"),
    (r"(?:authenticator|authy|google\s*authenticator|microsoft\s*authenticator)",
     "References authenticator app"),
    (r"(?:your.{,15}(?:account|session).{,10}(?:expire|lock|suspend|compromised|blocked))",
     "Account compromise urgency"),
    (r"(?:verify|confirm).{,25}(?:identity|account|login|sign.?in|activity)",
     "Identity verification request"),
    (r"(?:unauthorized|unusual|suspicious).{,30}(?:login|access|attempt|activity|sign.?in)",
     "Suspicious activity alert"),
    (r"(?:click.{,15}(?:here|link).{,30}(?:verify|secure|login|confirm))",
     "Link-based verification redirect"),
    (r"(?:fail|unsuccessful|attempt|blocked).{,20}(?:login|sign.?in|access|attempt)",
     "Failed login notification"),
    (r"(?:recent.{,10}(?:login|access|activity|attempt).{,15}(?:unusual|unknown|new|different|suspicious))",
     "Recent login from unknown location"),
]

HIGH_RISK_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".pw", ".ru", ".cn", ".top", ".club", ".work", ".bid", ".date", ".loan"}

BRAND_KEYWORDS = ["paypal", "amazon", "microsoft", "apple", "google", "netflix",
                  "bank", "chase", "wells fargo", "boa", "american express",
                  "visa", "mastercard", "dhl", "fedex", "usps", "irs", "adp",
                  "office365", "outlook", "sharepoint", "dropbox", "facebook",
                  "instagram", "linkedin", "twitter", "whatsapp"]


def detect_aitm_harvester(
    email_text: str = "",
    urls: Optional[list] = None,
    osint_data: Optional[dict] = None,
) -> dict:
    if urls is None:
        urls = []
    indicators = []
    score = 0

    url_score = _analyze_urls(urls, indicators)
    body_score = _analyze_body(email_text, indicators)
    domain_score = _analyze_domains(urls, osint_data, indicators)

    score = url_score + body_score + domain_score
    score = min(score, 100)

    detected = score >= 35

    if score >= 70:
        severity = "CRITICAL"
        label = "AitM Credential Harvesting Attempt"
    elif score >= 50:
        severity = "HIGH"
        label = "Suspicious OTP/MFA Harvesting Patterns"
    elif score >= 35:
        severity = "MEDIUM"
        label = "Possible Credential Harvesting Indicators"
    else:
        severity = "LOW"
        label = "No significant AitM/OTP harvesting indicators"

    return {
        "detected": detected,
        "confidence": score,
        "severity": severity,
        "label": label,
        "indicators": indicators,
        "url_score": url_score,
        "body_score": body_score,
        "domain_score": domain_score,
    }


def _analyze_urls(urls: list, indicators: list) -> int:
    score = 0
    for url in urls:
        if not isinstance(url, str):
            if isinstance(url, dict):
                url = url.get("url", "")
            else:
                url = str(url)
        if not url:
            continue
        url_lower = url.lower()
        for pattern, desc in AITM_URL_PATTERNS:
            if re.search(pattern, url_lower):
                indicators.append(f"URL pattern: {desc} — {url[:80]}")
                score += 15
        brand_match = _check_brand_in_url(url_lower)
        if brand_match:
            indicators.append(f"Brand impersonation in URL: {brand_match} — {url[:80]}")
            score += 20
    return min(score, 50)


def _analyze_body(email_text: str, indicators: list) -> int:
    score = 0
    body_lower = email_text.lower()
    for pattern, desc in AITM_BODY_PATTERNS:
        if re.search(pattern, body_lower):
            indicators.append(f"Email body: {desc}")
            score += 12
    brand_mentions = [b for b in BRAND_KEYWORDS if b in body_lower]
    if len(brand_mentions) >= 2:
        indicators.append(f"Multiple brand names in body: {', '.join(brand_mentions[:4])}")
        score += 10
    link_count = len(re.findall(r'https?://[^\s]+', email_text))
    if link_count >= 3:
        indicators.append(f"Multiple links ({link_count}) — common in credential harvesting")
        score += 8
    return min(score, 40)


def _analyze_domains(urls: list, osint_data: Optional[dict], indicators: list) -> int:
    score = 0
    domains = set()
    for url in urls:
        if not isinstance(url, str):
            if isinstance(url, dict):
                url = url.get("url", "")
            else:
                url = str(url)
        if not url:
            continue
        m = re.search(r'https?://([^/\s]+)', url.lower())
        if m:
            domains.add(m.group(1))

    for domain in domains:
        for tld in HIGH_RISK_TLDS:
            if domain.endswith(tld):
                indicators.append(f"High-risk TLD in domain: {domain}")
                score += 15
                break
        brand_match = _check_brand_in_domain(domain)
        if brand_match:
            indicators.append(f"Domain impersonates brand: '{brand_match}' in {domain}")
            score += 25

    if osint_data:
        domain_results = osint_data.get("domain_results", [])
        for dr in domain_results:
            if dr.get("risk_score", 0) >= 50 and dr.get("domain", "") in domains:
                indicators.append(f"Low reputation domain (OSINT risk {dr['risk_score']}/100): {dr['domain']}")
                score += 15
                break

    return min(score, 40)


def _check_brand_in_url(url_lower: str) -> Optional[str]:
    for brand in BRAND_KEYWORDS:
        safe = re.escape(brand)
        if re.search(rf"(?:^|[^a-z]){safe}(?:[^a-z]|$)", url_lower):
            return brand
    return None


def _check_brand_in_domain(domain: str) -> Optional[str]:
    domain_no_tld = domain.rsplit(".", 1)[0] if "." in domain else domain
    for brand in BRAND_KEYWORDS:
        safe = re.escape(brand)
        if re.search(rf"(?:^|\W){safe}(?:\W|$)", domain_no_tld):
            return brand
    return None
