import json
import re
from pathlib import Path

from src.fingerprinting import fingerprint_email

# Load keywords
KEYWORDS_PATH = Path(__file__).parent.parent / "data" / "phishing_keywords.json"
with open(KEYWORDS_PATH, "r", encoding="utf-8") as f:
    PHISHING_KEYWORDS = json.load(f)

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r'http://(?!https)',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl|short\.io',
    r'[a-z0-9]{20,}\.',
    r'paypal\.(?!com)',
    r'amazon\.(?!com|co\.|ca|de|fr)',
    r'secure-.*\.com',
    r'login-.*\.com',
    r'verify-.*\.com',
    r'update-.*\.com',
    r'account-.*\.com',
    r'banking-.*\.com',
]

# Malicious attachment extensions
MALICIOUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.scr', '.pif', '.com',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.ps1', '.psm1', '.psd1', '.msi', '.dll', '.reg',
    '.hta', '.cpl', '.inf', '.lnk',
]

MACRO_EXTENSIONS = [
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
    '.xlam', '.ppam', '.potm', '.ppsm',
]

DOUBLE_EXTENSION_PATTERN = r'\.[a-zA-Z]{2,4}\.(exe|bat|cmd|scr|pif|vbs|js|ps1)$'

# Fake sender patterns
FAKE_SENDER_PATTERNS = [
    r'@.*paypal.*\.(?!com)',
    r'@.*amazon.*\.(?!com)',
    r'@.*microsoft.*\.(?!com)',
    r'@.*apple.*\.(?!com)',
    r'@.*google.*\.(?!com)',
    r'@.*netflix.*\.(?!com)',
    r'@.*irs.*\.(?!gov)',
    r'@.*fedex.*\.(?!com)',
    r'noreply.*@(?!.*\.(com|org|gov|edu)$)',
    r'support.*@(?!.*\.(com|org|gov|edu)$)',
    r'security.*@(?!.*\.(com|org|gov|edu)$)',
]

# ── Multilingual Phishing Keywords ───────────────────────────────────────────

ARABIC_KEYWORDS = {
    "urgency": ["تحقق", "عاجل", "فوري", "انتهت", "محدود", "الآن", "خطر"],
    "credentials": ["كلمة المرور", "تسجيل الدخول", "حسابك", "بياناتك"],
    "financial": ["تحويل", "مبلغ", "دفع", "بنك", "بطاقة", "رصيد"],
    "suspension": ["تم تعليق", "محظور", "مغلق", "انتهت صلاحية"],
}

FRENCH_KEYWORDS = {
    "urgency": ["urgent", "immediatement", "expire", "limite", "maintenant", "danger"],
    "credentials": ["mot de passe", "connexion", "votre compte", "identifiant"],
    "financial": ["virement", "paiement", "banque", "carte", "solde", "fraude"],
    "suspension": ["suspendu", "bloque", "ferme", "expire", "desactive"],
}


def detect_languages(text: str) -> dict:
    """Detect which languages are present in the email text."""
    text_lower = text.lower()
    detected = {"ar": False, "fr": False, "en": True}
    ar_count = 0
    fr_count = 0

    for kw_list in ARABIC_KEYWORDS.values():
        for kw in kw_list:
            if kw in text:
                ar_count += 1

    for kw_list in FRENCH_KEYWORDS.values():
        for kw in kw_list:
            if kw in text_lower:
                fr_count += 1

    if ar_count >= 2:
        detected["ar"] = True
    if fr_count >= 2:
        detected["fr"] = True

    return detected


def scan_multilingual_keywords(text: str) -> dict:
    """Scan for Arabic and French phishing keywords."""
    results = {}
    text_lower = text.lower()

    for lang, lang_keywords in [("ar", ARABIC_KEYWORDS), ("fr", FRENCH_KEYWORDS)]:
        for category, keywords in lang_keywords.items():
            key = f"{lang}_{category}"
            if lang == "ar":
                hits = [kw for kw in keywords if kw in text]
            else:
                hits = [kw for kw in keywords if kw in text_lower]
            if hits:
                results[key] = hits

    return results


# Language manipulation patterns
URGENCY_PATTERNS = [
    r'\b(immediately|urgent|asap|right now|right away)\b',
    r'\b(\d+\s*hours?|\d+\s*minutes?|\d+\s*days?)\b',
    r'\b(expire[sd]?|expiring|deadline|due today)\b',
    r'\b(last chance|final notice|final warning|last warning)\b',
    r'\b(act now|respond now|reply now|click now)\b',
]

FEAR_PATTERNS = [
    r'\b(suspended|terminated|closed|blocked|locked|disabled)\b',
    r'\b(unauthorized|illegal|fraudulent|suspicious activity)\b',
    r'\b(legal action|law enforcement|police|lawsuit|court)\b',
    r'\b(compromised|hacked|breached|violated|stolen)\b',
    r'\b(penalty|fine|charge|fee|debt)\b',
]

GRAMMAR_PATTERNS = [
    r'\b(kindly|do the needful|revert back|prepone)\b',
    r'\b(dear (sir|madam|customer|user|friend|valued))\b',
    r'\b(we are (writing|contacting|reaching) to (inform|notify|alert))\b',
    r'\b(your (account|profile|access) (have|has been|will be))\b',
]


# ── Extraction functions ───────────────────────────────────────────────────────

def extract_urls(text: str) -> list:
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def extract_emails(text: str) -> list:
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    return re.findall(email_pattern, text, re.IGNORECASE)


def extract_attachments(text: str) -> list:
    attachment_pattern = r'\b[\w\-]+(\.[a-zA-Z]{2,5}){1,3}\b'
    candidates = re.findall(r'\b[\w\-]+(\.[\w]{2,5})+\b', text)
    return candidates


# ── Detection functions ────────────────────────────────────────────────────────

def check_urls(urls: list) -> list:
    suspicious = []
    for url in urls:
        flags = []
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                flags.append(pattern)
        if flags:
            suspicious.append({"url": url, "flags": flags})
    return suspicious


def scan_keywords(text: str) -> tuple:
    text_lower = text.lower()
    results = {}
    total_hits = 0

    for category, keywords in PHISHING_KEYWORDS.items():
        hits = [kw for kw in keywords if kw in text_lower]
        if hits:
            results[category] = hits
            total_hits += len(hits)

    ml_results = scan_multilingual_keywords(text)
    for key, hits in ml_results.items():
        results[key] = hits
        total_hits += len(hits)

    return results, total_hits


def analyze_headers(text: str) -> dict:
    """Detect fake senders, domain spoofing, reply-to mismatches."""
    findings = []
    risk_score = 0

    emails_found = extract_emails(text)

    # Check for fake sender domains
    for email in emails_found:
        for pattern in FAKE_SENDER_PATTERNS:
            if re.search(pattern, email, re.IGNORECASE):
                findings.append(f"Suspicious sender domain: {email}")
                risk_score += 10

    # Check reply-to mismatch
    from_match = re.search(r'from:\s*([\w\.-]+@[\w\.-]+)', text, re.IGNORECASE)
    reply_match = re.search(r'reply-to:\s*([\w\.-]+@[\w\.-]+)', text, re.IGNORECASE)

    if from_match and reply_match:
        from_domain = from_match.group(1).split('@')[1]
        reply_domain = reply_match.group(1).split('@')[1]
        if from_domain != reply_domain:
            findings.append(
                f"Reply-To mismatch: From={from_domain} vs Reply-To={reply_domain}"
            )
            risk_score += 20

    # Check for display name spoofing
    display_spoof = re.search(
        r'(paypal|amazon|microsoft|apple|google|netflix|irs|fedex)\s*<[^>]+@(?!paypal|amazon|microsoft|apple|google|netflix|irs|fedex)',
        text, re.IGNORECASE
    )
    if display_spoof:
        findings.append(f"Display name spoofing detected: {display_spoof.group()[:60]}")
        risk_score += 25

    # Free email provider sending as corporate
    free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    for email in emails_found:
        domain = email.split('@')[-1].lower()
        if domain in free_providers:
            if any(brand in text.lower() for brand in
                   ['paypal', 'amazon', 'microsoft', 'apple', 'bank', 'irs']):
                findings.append(
                    f"Free email provider ({domain}) impersonating a brand"
                )
                risk_score += 15

    return {
        "findings": findings,
        "risk_score": min(risk_score, 40),
        "emails_found": emails_found,
    }


def analyze_attachments(text: str) -> dict:
    """Detect malicious attachment types and patterns."""
    findings = []
    risk_score = 0
    detected = []

    text_lower = text.lower()

    # Check malicious extensions
    for ext in MALICIOUS_EXTENSIONS:
        if ext in text_lower:
            findings.append(f"Dangerous file type detected: {ext}")
            detected.append(ext)
            risk_score += 20

    # Check macro-enabled documents
    for ext in MACRO_EXTENSIONS:
        if ext in text_lower:
            findings.append(f"Macro-enabled document detected: {ext}")
            detected.append(ext)
            risk_score += 15

    # Check double extensions
    if re.search(DOUBLE_EXTENSION_PATTERN, text, re.IGNORECASE):
        findings.append("Double extension detected (e.g. invoice.pdf.exe)")
        risk_score += 25

    # Check for attachment language
    attachment_words = [
        'attachment', 'attached', 'see attached', 'open the file',
        'download the file', 'enclosed', 'find attached',
        'open document', 'view attachment', 'invoice attached',
        'document attached', 'file attached'
    ]
    attachment_language = [w for w in attachment_words if w in text_lower]
    if attachment_language:
        findings.append(f"Attachment language detected: {', '.join(attachment_language[:3])}")
        risk_score += 8

    return {
        "findings": findings,
        "risk_score": min(risk_score, 40),
        "detected_extensions": detected,
        "has_attachment_language": len(attachment_language) > 0,
    }


def analyze_language(text: str) -> dict:
    """Detect manipulation language, urgency, fear, grammar issues."""
    findings = []
    risk_score = 0
    text_lower = text.lower()

    # Urgency patterns
    urgency_hits = []
    for pattern in URGENCY_PATTERNS:
        matches = re.findall(pattern, text_lower)
        if matches:
            urgency_hits.extend(matches if isinstance(matches[0], str) else
                                [m[0] for m in matches])

    if urgency_hits:
        findings.append(f"Urgency manipulation: {', '.join(set(str(h) for h in urgency_hits[:4]))}")
        risk_score += min(len(urgency_hits) * 5, 20)

    # Fear patterns
    fear_hits = []
    for pattern in FEAR_PATTERNS:
        matches = re.findall(pattern, text_lower)
        if matches:
            fear_hits.extend(matches if isinstance(matches[0], str) else
                             [m[0] for m in matches])

    if fear_hits:
        findings.append(f"Fear tactics: {', '.join(set(str(h) for h in fear_hits[:4]))}")
        risk_score += min(len(fear_hits) * 5, 20)

    # Grammar patterns (common in translated phishing)
    grammar_hits = []
    for pattern in GRAMMAR_PATTERNS:
        if re.search(pattern, text_lower):
            grammar_hits.append(pattern)

    if grammar_hits:
        findings.append(f"Suspicious grammar patterns detected ({len(grammar_hits)} matches)")
        risk_score += min(len(grammar_hits) * 5, 15)

    # Excessive capitalization
    words = text.split()
    if len(words) > 10:
        caps_ratio = sum(1 for w in words if w.isupper() and len(w) > 2) / len(words)
        if caps_ratio > 0.15:
            findings.append(f"Excessive capitalization ({int(caps_ratio*100)}% of words)")
            risk_score += 10

    # Excessive punctuation
    exclamation_count = text.count('!')
    if exclamation_count > 3:
        findings.append(f"Excessive exclamation marks ({exclamation_count} found)")
        risk_score += 8

    # Too many numbers (fake order IDs, case numbers)
    number_pattern = re.findall(r'\b\d{6,}\b', text)
    if len(number_pattern) > 3:
        findings.append(f"Multiple fake reference numbers detected ({len(number_pattern)} found)")
        risk_score += 8

    return {
        "findings": findings,
        "risk_score": min(risk_score, 40),
        "urgency_count": len(urgency_hits),
        "fear_count": len(fear_hits),
        "grammar_issues": len(grammar_hits),
    }


def detect_attachments(text: str) -> bool:
    attachment_keywords = [
        "attachment", "attached", "see the file", "open the document",
        "download", ".zip", ".exe", ".pdf", ".doc", "invoice attached"
    ]
    return any(kw in text.lower() for kw in attachment_keywords)


def calculate_risk_score(keyword_hits: int, url_count: int,
                          suspicious_urls: int, has_attachments: bool,
                          header_score: int, attachment_score: int,
                          language_score: int,
                          kit_score: float = 0.0) -> dict:

    score = 0
    score += min(keyword_hits * 6, 30)
    score += min(suspicious_urls * 12, 25)
    score += min(url_count * 2, 8)
    score += 10 if has_attachments else 0
    score += min(header_score, 20)
    score += min(attachment_score, 15)
    score += min(language_score, 15)
    score += int(kit_score * 20)
    score = min(score, 100)

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

    return {"score": score, "severity": severity, "color": color}


def analyze_email(email_text: str) -> dict:
    """Main analysis function — runs all detection engines."""

    urls = extract_urls(email_text)
    suspicious_urls = check_urls(urls)
    keyword_matches, total_hits = scan_keywords(email_text)
    has_attachments = detect_attachments(email_text)

    # New engines
    header_analysis    = analyze_headers(email_text)
    attachment_analysis = analyze_attachments(email_text)
    language_analysis  = analyze_language(email_text)

    kit_fingerprint    = fingerprint_email(email_text)

    risk = calculate_risk_score(
        total_hits,
        len(urls),
        len(suspicious_urls),
        has_attachments,
        header_analysis["risk_score"],
        attachment_analysis["risk_score"],
        language_analysis["risk_score"],
        kit_fingerprint["highest_confidence"] / 100,
    )

    languages_detected = detect_languages(email_text)
    lang_codes = []
    if languages_detected.get("ar"):
        lang_codes.append("AR")
    if languages_detected.get("fr"):
        lang_codes.append("FR")
    lang_codes.append("EN")

    return {
        "risk_score":            risk["score"],
        "severity":              risk["severity"],
        "severity_color":        risk["color"],
        "keyword_matches":       keyword_matches,
        "total_keyword_hits":    total_hits,
        "urls_found":            urls,
        "suspicious_urls":       suspicious_urls,
        "has_attachments":       has_attachments,
        "url_count":             len(urls),
        "suspicious_url_count":  len(suspicious_urls),
        "header_analysis":       header_analysis,
        "attachment_analysis":   attachment_analysis,
        "language_analysis":     language_analysis,
        "languages_detected":    lang_codes,
        "kit_fingerprinting":    kit_fingerprint,
    }