"""
Brand impersonation detector.

Detects lookalike domains, display-name spoofing, and known brand
impersonation patterns in email content.
"""
import difflib
import logging
import re

from src.db import get_connection

logger = logging.getLogger("brand_impersonation")
BRAND_TABLE = "brand_protection"

# Built-in high-value brand domains
KNOWN_BRANDS = [
    "google.com", "paypal.com", "amazon.com", "microsoft.com", "apple.com",
    "facebook.com", "twitter.com", "linkedin.com", "netflix.com", "dropbox.com",
    "salesforce.com", "adobe.com", "instagram.com", "whatsapp.com", "zoom.us",
    "github.com", "gitlab.com", "atlassian.com", "slack.com", "shopify.com",
    "cloudflare.com", "aws.amazon.com", "accounts.google.com", "login.microsoftonline.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "hsbc.com", "barclays.com",
    "paypal.com", "stripe.com", "square.com", "coinbase.com", "binance.com",
]


def init_brand_protection():
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {BRAND_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    # Seed built-in brands
    for domain in KNOWN_BRANDS:
        c.execute(
            f"INSERT OR IGNORE INTO {BRAND_TABLE} (domain, label) VALUES (?, ?)",
            (domain, domain.split(".")[0].title()),
        )
    conn.commit()
    conn.close()


def add_custom_brand(domain: str, label: str = "") -> bool:
    init_brand_protection()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            f"INSERT OR IGNORE INTO {BRAND_TABLE} (domain, label) VALUES (?, ?)",
            (domain.lower().strip(), label or domain.split(".")[0].title()),
        )
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.error("Failed to add brand: %s", e)
        return False
    finally:
        conn.close()


def remove_custom_brand(domain: str) -> bool:
    init_brand_protection()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"DELETE FROM {BRAND_TABLE} WHERE domain=?", (domain.lower().strip(),))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def get_all_brands() -> list[dict]:
    init_brand_protection()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"SELECT * FROM {BRAND_TABLE} ORDER BY domain")
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def extract_domains(text: str) -> list[str]:
    return re.findall(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)", text)


def is_lookalike(domain: str, known_domain: str) -> tuple[bool, float]:
    """Check if domain is a lookalike of known_domain using edit distance."""
    domain = domain.lower().strip()
    known_domain = known_domain.lower().strip()
    if domain == known_domain:
        return False, 0.0
    ratio = difflib.SequenceMatcher(None, domain, known_domain).ratio()
    if ratio >= 0.7:
        return True, ratio
    return False, ratio


def _check_homograph(domain: str) -> list[str]:
    suspicious = []
    if re.search(r"[аеоорсухАВЕКМНОРСТУХ]", domain):
        suspicious.append("homograph_characters")
    if domain.count(".") > 3:
        suspicious.append("excessive_subdomains")
    if "--" in domain:
        suspicious.append("punycode")
    return suspicious


def analyze_sender_domain(sender_email: str) -> dict:
    """Analyze a sender email address for brand impersonation."""
    result = {
        "sender": sender_email,
        "domain": "",
        "matches": [],
        "lookalikes": [],
        "homograph_flags": [],
        "risk_score": 0,
        "brand_match": None,
    }
    match = re.match(r".+@(.+)", sender_email)
    if not match:
        return result
    domain = match.group(1).lower()
    result["domain"] = domain

    brands = get_all_brands()
    for brand in brands:
        known = brand["domain"]
        is_likely, score = is_lookalike(domain, known)
        if is_likely:
            result["lookalikes"].append({
                "known": known,
                "label": brand["label"],
                "similarity": round(score, 3),
            })
            result["risk_score"] = max(result["risk_score"], int(score * 100))
            result["brand_match"] = brand["label"]

    result["homograph_flags"] = _check_homograph(domain)
    if result["homograph_flags"]:
        result["risk_score"] = max(result["risk_score"], 60)

    if result["risk_score"] >= 50:
        result["matches"] = result["lookalikes"]

    return result


def analyze_email_content(text: str) -> list[dict]:
    """Scan email body for brand name mentions and check for impersonation."""
    findings = []
    brands = get_all_brands()
    text_lower = text.lower()

    for brand in brands:
        label = brand["label"].lower()
        domain_name = brand["domain"].split(".")[0].lower()

        if label in text_lower or domain_name in text_lower:
            domains_in_text = extract_domains(text)
            for d in domains_in_text:
                if d == brand["domain"]:
                    continue
                is_likely, score = is_lookalike(d, brand["domain"])
                if is_likely:
                    findings.append({
                        "brand": brand["label"],
                        "found_domain": d,
                        "similarity": round(score, 3),
                        "type": "content_impersonation",
                        "severity": "high" if score >= 0.85 else "medium",
                    })

    return findings


def run_brand_impersonation_check(email_text: str, sender: str = "") -> dict:
    init_brand_protection()
    result = {
        "sender_analysis": analyze_sender_domain(sender) if sender else {},
        "content_findings": analyze_email_content(email_text),
        "total_risk": 0,
        "impersonation_detected": False,
    }
    scores = []
    if result["sender_analysis"].get("risk_score"):
        scores.append(result["sender_analysis"]["risk_score"])
    for f in result["content_findings"]:
        scores.append(int(f["similarity"] * 100))
    result["total_risk"] = max(scores) if scores else 0
    result["impersonation_detected"] = result["total_risk"] >= 50
    return result
