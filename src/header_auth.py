"""
PhishGuard AI — Email Authentication Header Analyzer

Parses SPF, DKIM, and DMARC results from email headers to detect
spoofing and impersonation attempts.

Usage:
    from src.header_auth import analyze_auth_headers
"""
import re  # noqa: I001
import logging
from typing import Optional

logger = logging.getLogger("header-auth")


def _extract_header(text: str, header_name: str) -> str:
    """Extract the value of a specific header from raw email text."""
    pattern = re.compile(
        rf"^{re.escape(header_name)}:\s*(.*?)(?:\n(?![ \t])|\Z)",
        re.MULTILINE | re.IGNORECASE,
    )
    match = pattern.search(text)
    if match:
        return match.group(1).strip()
    # Handle folded headers (continuation lines start with space/tab)
    pattern_folded = re.compile(
        rf"^{re.escape(header_name)}:\s*(.*?)(?:\n(?!\s)|\Z)",
        re.MULTILINE | re.IGNORECASE | re.DOTALL,
    )
    match = pattern_folded.search(text)
    if match:
        return match.group(1).strip().replace("\n", " ").replace("\r", "")
    return ""


def _parse_auth_results(header_value: str) -> dict:
    """Parse an Authentication-Results header into structured data."""
    result = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "spf_smtp_from": None,
        "dkim_header_from": None,
        "dmarc_from": None,
    }

    if not header_value:
        return result

    try:
        spf_match = re.search(r"(?:spf)=(\w+)", header_value, re.IGNORECASE)
        if spf_match:
            result["spf"] = spf_match.group(1).lower()

        dkim_match = re.search(r"(?:dkim)=(\w+)", header_value, re.IGNORECASE)
        if dkim_match:
            result["dkim"] = dkim_match.group(1).lower()

        dmarc_match = re.search(r"(?:dmarc)=(\w+)", header_value, re.IGNORECASE)
        if dmarc_match:
            result["dmarc"] = dmarc_match.group(1).lower()

        spf_smtp = re.search(r"smtp\.mailfrom[^;]+", header_value, re.IGNORECASE)
        if spf_smtp:
            result["spf_smtp_from"] = spf_smtp.group(0).strip()

        dkim_hfrom = re.search(r"header\.from[^;]+", header_value, re.IGNORECASE)
        if dkim_hfrom:
            result["dkim_header_from"] = dkim_hfrom.group(0).strip()

        dmarc_f = re.search(r"dmarc\.from[^;]+", header_value, re.IGNORECASE)
        if dmarc_f:
            result["dmarc_from"] = dmarc_f.group(0).strip()
    except Exception as _exc:
        logger.debug("Failed to parse auth results header: %s", _exc)

    return result


def _parse_received_spf(header_value: str) -> Optional[str]:
    """Parse Received-SPF header to extract pass/fail/neutral."""
    if not header_value:
        return None
    match = re.match(r"(\w+)", header_value.strip())
    return match.group(1).lower() if match else None


def analyze_auth_headers(text: str) -> dict:
    """
    Analyze email headers for SPF, DKIM, and DMARC authentication.

    Returns a dict with:
        spf_status: pass/fail/softfail/neutral/none
        dkim_status: pass/fail/none
        dmarc_status: pass/fail/bestguesspass/none
        overall: PASS / WARNING / FAIL / UNKNOWN
        details: human-readable explanation
        risk_contribution: 0-40 (how much this contributes to overall risk)
    """
    auth_results_raw = _extract_header(text, "Authentication-Results")
    received_spf_raw = _extract_header(text, "Received-SPF")
    dkim_raw = _extract_header(text, "DKIM-Signature")
    from_raw = _extract_header(text, "From")

    parsed = _parse_auth_results(auth_results_raw)
    received_spf = _parse_received_spf(received_spf_raw)

    statuses = []
    risk = 0

    # SPF analysis
    spf = parsed.get("spf") or received_spf
    if spf:
        statuses.append(("SPF", spf.upper()))
        if spf == "pass":
            risk += 0
        elif spf in ("softfail", "neutral"):
            risk += 10
            statuses.append(("SPF", "SOFTFAIL/NEUTRAL"))
        elif spf == "fail":
            risk += 25
        else:
            risk += 5
    else:
        statuses.append(("SPF", "MISSING"))
        risk += 15

    # DKIM analysis
    dkim = parsed.get("dkim")
    if dkim:
        statuses.append(("DKIM", dkim.upper()))
        if dkim == "pass":
            risk += 0
        else:
            risk += 20
    elif dkim_raw:
        statuses.append(("DKIM", "SIGNED"))
        risk += 5
    else:
        statuses.append(("DKIM", "MISSING"))
        risk += 10

    # DMARC analysis
    dmarc = parsed.get("dmarc")
    if dmarc:
        statuses.append(("DMARC", dmarc.upper()))
        if dmarc == "pass":
            risk += 0
        elif dmarc == "bestguesspass":
            risk += 5
        else:
            risk += 20
    else:
        statuses.append(("DMARC", "MISSING"))
        risk += 15

    risk = min(risk, 40)

    # Determine overall
    any_fail = spf == "fail" or dkim == "fail" or dmarc == "fail"
    spf_ok = spf == "pass" or received_spf == "pass"
    dkim_ok = dkim == "pass"
    dmarc_ok = dmarc in ("pass", "bestguesspass")

    if any_fail:
        overall = "FAIL"
    elif spf_ok and dkim_ok and dmarc_ok:
        overall = "PASS"
    elif not any_fail and (spf_ok or dkim_ok or dmarc_ok):
        overall = "WARNING"
    else:
        overall = "WARNING"

    details_parts = []
    if spf == "fail":
        details_parts.append("SPF verification FAILED — sending server not authorised")
    if dkim == "fail":
        details_parts.append("DKIM signature INVALID — email may have been tampered with")
    if dmarc == "fail":
        details_parts.append("DMARC policy FAILED — domain alignment broken")
    if not details_parts:
        if overall == "PASS":
            details_parts.append("All authentication checks passed")
        else:
            details_parts.append("Some authentication checks missing or inconclusive")

    return {
        "spf_status": spf or "missing",
        "dkim_status": dkim or "missing",
        "dmarc_status": dmarc or "missing",
        "overall": overall,
        "details": " | ".join(details_parts),
        "risk_contribution": risk,
        "raw_auth_results": auth_results_raw[:200] if auth_results_raw else "",
        "has_dkim_signature": bool(dkim_raw),
        "has_from_header": bool(from_raw),
    }
