"""Screenshot Analysis — OCR + full phishing pipeline for uploaded images."""

from __future__ import annotations

import base64
import io
import logging
import re

from PIL import Image

logger = logging.getLogger(__name__)

BRAND_DOMAINS = {
    "paypal": r"paypal",
    "amazon": r"amazon",
    "microsoft": r"microsoft",
    "apple": r"apple",
    "google": r"google",
    "netflix": r"netflix",
    "facebook": r"facebook",
    "linkedin": r"linkedin",
    "instagram": r"instagram",
    "twitter": r"twitter|x\.com",
    "dropbox": r"dropbox",
    "adobe": r"adobe",
    "dhl": r"dhl",
    "fedex": r"fedex",
    "irs": r"irs\.gov",
    "bank of america": r"bank\s*of\s*america",
    "chase": r"chase",
    "wells fargo": r"wells\s*fargo",
}

SUSPICIOUS_URL_PATTERNS = [
    r"http://(?!https)",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl|short\.io|rb\.gy|cutt\.ly",
    r"secure-.*\.com",
    r"login-.*\.com",
    r"verify-.*\.com",
    r"update-.*\.com",
    r"account-.*\.com",
    r"banking-.*\.com",
    r"signin-.*\.com",
    r"auth-.*\.com",
]

URGENCY_PATTERNS = [
    r"\b(immediately|urgent|asap|right now|act now)\b",
    r"\b(expire[sd]?|deadline|last chance|final notice)\b",
    r"\b(suspended|terminated|closed|blocked|locked)\b",
    r"\b(limited time|offer expires|click now)\b",
]

PAYMENT_PATTERNS = [
    r"\b(payment|invoice|bill|charge|overdue|refund)\b",
    r"\b(wire\s*transfer|ach|direct deposit)\b",
    r"\b(paypal|venmo|cashapp|zelle)\b",
    r"\b(credit card|debit card|bank account|routing number)\b",
    r"\$\s*\d+[\.,]?\d*",
]

IMPERSONATION_PATTERNS = [
    r"(?i)(ceo|cfo|president|director|manager|hr|it support|help desk|security team)",
]

SENDER_PATTERNS = [
    r"(?i)(from|sender|sent by|from address)[:\s]*([^\n\r]+)",
    r"(?i)(subject|re:)[:\s]*([^\n\r]+)",
]


def _extract_urls(text: str) -> list[str]:
    url_pattern = r"https?://[^\s<>\"{}|\\^`\[\]]+"
    return re.findall(url_pattern, text, re.IGNORECASE)


def _detect_brand_impersonation(text: str) -> list[dict]:
    results = []
    text_lower = text.lower()
    for brand, pattern in BRAND_DOMAINS.items():
        if re.search(pattern, text_lower):
            results.append({"brand": brand, "matched": True})
    return results


def _check_urls(urls: list[str]) -> list[dict]:
    results = []
    for url in urls:
        suspicious = False
        matched_patterns = []
        for pat in SUSPICIOUS_URL_PATTERNS:
            if re.search(pat, url, re.IGNORECASE):
                suspicious = True
                matched_patterns.append(pat)
        results.append({
            "url": url,
            "suspicious": suspicious,
            "matched_patterns": matched_patterns[:3],
        })
    return results


def _detect_urgency(text: str) -> list[str]:
    hits = []
    for pat in URGENCY_PATTERNS:
        matches = re.findall(pat, text, re.IGNORECASE)
        hits.extend(m for m in matches if m)
    return hits


def _detect_payment_requests(text: str) -> list[str]:
    hits = []
    for pat in PAYMENT_PATTERNS:
        matches = re.findall(pat, text, re.IGNORECASE)
        hits.extend(m for m in matches if m)
    return list(set(hits))[:10]


def _detect_sender_info(text: str) -> dict:
    info = {"sender": None, "subject": None}
    for pat in SENDER_PATTERNS:
        match = re.search(pat, text)
        if match:
            key = match.group(1).strip().lower()
            val = match.group(2).strip()
            if "from" in key or "sender" in key or "sent by" in key:
                if not info["sender"]:
                    info["sender"] = val
            elif "subject" in key or "re:" in val.lower():
                info["subject"] = val
    return info


def _calculate_risk_score(url_results: list[dict], urgency_hits: list,
                           payment_hits: list, brand_hits: list,
                           has_impersonation: bool) -> dict:
    score = 0
    reasons = []

    suspicious_urls = [u for u in url_results if u["suspicious"]]
    if suspicious_urls:
        score += min(len(suspicious_urls) * 15, 40)
        reasons.append(f"{len(suspicious_urls)} suspicious URL(s) detected")

    if urgency_hits:
        score += min(len(urgency_hits) * 5, 20)
        reasons.append(f"urgency language detected ({len(urgency_hits)} instances)")

    if payment_hits:
        score += min(len(payment_hits) * 3, 15)
        reasons.append(f"payment/financial language detected")

    if brand_hits:
        score += len(brand_hits) * 5
        reasons.append(f"brand impersonation detected: {', '.join(b['brand'] for b in brand_hits[:3])}")

    if has_impersonation:
        score += 10
        reasons.append("authority figure impersonation detected")

    score = min(score, 100)
    if score >= 70:
        severity = "CRITICAL"
    elif score >= 45:
        severity = "HIGH"
    elif score >= 20:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {"score": score, "severity": severity, "reasons": reasons}


def analyze_screenshot_image(image_bytes: bytes, mime_type: str = "image/png") -> dict:
    """Analyze a screenshot image for phishing indicators.

    Attempts AI vision first (if OPENAI_API_KEY configured), then falls back
    to heuristic analysis on the extracted text from the image.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))
        width, height = img.size
        format_name = img.format or "PNG"
    except Exception as e:
        return {
            "success": False,
            "error": f"Could not read image: {e}",
            "risk_score": 0,
            "severity": "LOW",
        }

    # Try AI vision-based analysis
    try:
        from src.ai_analyzer import analyze_screenshot as ai_vision
        b64 = base64.b64encode(image_bytes).decode("utf-8")
        vision_result = ai_vision(b64, mime_type)
        extracted_text = vision_result.get("detectedTextOcr", "")
        if not extracted_text or extracted_text.startswith("AI vision"):
            extracted_text = ""
    except Exception:
        vision_result = None
        extracted_text = ""

    # Run heuristic analysis on extracted text
    urls = _extract_urls(extracted_text)
    url_analysis = _check_urls(urls)
    urgency_hits = _detect_urgency(extracted_text)
    payment_hits = _detect_payment_requests(extracted_text)
    brand_hits = _detect_brand_impersonation(extracted_text)
    sender_info = _detect_sender_info(extracted_text)

    has_impersonation = bool(re.search(
        r"(?i)(ceo|cfo|president|director|manager|hr|it support|help desk|security team)",
        extracted_text,
    ))

    risk = _calculate_risk_score(url_analysis, urgency_hits, payment_hits,
                                  brand_hits, has_impersonation)

    # Generate threat explanation
    explanation_parts = []
    if risk["severity"] in ("CRITICAL", "HIGH"):
        explanation_parts.append(f"This screenshot shows signs of a phishing attack.")
    elif risk["severity"] == "MEDIUM":
        explanation_parts.append("This screenshot contains some suspicious elements.")
    else:
        explanation_parts.append("No significant phishing indicators detected in this screenshot.")

    if risk["reasons"]:
        explanation_parts.append("Key findings:")
        explanation_parts.extend(f"- {r}" for r in risk["reasons"])

    # Generate recommendations
    recommendations = []
    if risk["score"] >= 45:
        recommendations.append("Do not interact with any links in this email")
        recommendations.append("Forward the original email to your IT security team")
    if payment_hits:
        recommendations.append("Verify any payment requests through a separate communication channel")
    if suspicious_urls := [u for u in url_analysis if u["suspicious"]]:
        recommendations.append("Do not click any links — they appear to lead to suspicious destinations")
    if not recommendations:
        recommendations.append("No action needed — this appears legitimate")

    return {
        "success": True,
        "image_format": format_name,
        "dimensions": f"{width}x{height}",
        "extracted_text": extracted_text[:2000] if extracted_text else "(no text extracted)",
        "urls_found": urls,
        "url_analysis": url_analysis,
        "urgency_hits": urgency_hits,
        "payment_hits": payment_hits,
        "brand_impersonation": brand_hits,
        "sender_info": sender_info,
        "has_authority_impersonation": has_impersonation,
        "risk_score": risk["score"],
        "severity": risk["severity"],
        "risk_reasons": risk["reasons"],
        "explanation": "\n".join(explanation_parts),
        "recommendations": recommendations,
        "ai_vision_used": bool(extracted_text and vision_result),
    }
