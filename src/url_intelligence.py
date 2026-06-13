"""URL Intelligence Engine — standalone deep-dive URL analysis.

Analyzes a single URL for phishing indicators: TLD risk, domain heuristics,
suspicious keywords, homograph attacks, brand impersonation, redirect chains.
Returns a Safe / Suspicious / Malicious verdict with detailed explanations.
"""

from __future__ import annotations

import logging
import re
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# High-risk TLDs commonly used in phishing
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # Freenom free TLDs
    "xyz", "top", "club", "live", "online", "site", "website",
    "work", "review", "download", "stream", "trade", "bid",
    "win", "loan", "men", "mom", "click", "link",
}

MEDIUM_RISK_TLDS = {
    "info", "biz", "icu", "pro", "company", "network", "world",
    "today", "cloud", "host", "press", "science", "party",
    "racing", "accountant", "date", "faith", "ren", "cam",
}

SUSPICIOUS_KEYWORDS = [
    r"login", r"signin", r"verify", r"account", r"secure",
    r"update", r"confirm", r"authenticate", r"validate",
    r"password", r"credential", r"banking", r"payment",
    r"invoice", r"refund", r"claim", r"reward", r"prize",
    r"free", r"gift", r"bonus", r"wallet", r"recover",
    r"unlock", r"alert", r"warning", r"suspended", r"limited",
    r"support", r"helpdesk", r"service", r"billing",
    r"chase", r"wellsfargo", r"paypal", r"amazon",
]

BRAND_DOMAINS = [
    (r"paypal", ["paypal.com", "paypalobjects.com"]),
    (r"amazon", ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
                  "amazon.ca", "amazon.co.jp", "amazonaws.com"]),
    (r"microsoft", ["microsoft.com", "live.com", "outlook.com", "office.com",
                     "office365.com", "azure.com", "msn.com"]),
    (r"google", ["google.com", "gmail.com", "youtube.com", "drive.google.com"]),
    (r"apple", ["apple.com", "icloud.com"]),
    (r"netflix", ["netflix.com", "nflx.com"]),
    (r"facebook", ["facebook.com", "fb.com", "messenger.com"]),
    (r"linkedin", ["linkedin.com"]),
    (r"instagram", ["instagram.com"]),
    (r"twitter|x\.com", ["twitter.com", "x.com"]),
    (r"dropbox", ["dropbox.com", "dropboxapi.com"]),
    (r"adobe", ["adobe.com", "adobe.io"]),
    (r"dhl", ["dhl.com"]),
    (r"fedex", ["fedex.com"]),
    (r"chase", ["chase.com"]),
    (r"wells\s*fargo", ["wellsfargo.com"]),
    (r"bank of america", ["bankofamerica.com"]),
]

HOMOGRAPH_CHARS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a",
}


def _parse_url(url: str) -> dict:
    """Parse a URL into components."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    # Strip port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    subdomain = ".".join(domain.split(".")[:-2]) if len(domain.split(".")) > 2 else ""
    tld = domain.split(".")[-1] if "." in domain else ""
    return {
        "full_url": url,
        "domain": domain,
        "subdomain": subdomain,
        "tld": tld,
        "path": parsed.path or "/",
        "query": parsed.query,
        "has_https": url.startswith("https://"),
    }


def _score_tld_risk(tld: str) -> tuple[int, str]:
    """Score risk based on TLD."""
    if tld in HIGH_RISK_TLDS:
        return 25, f"High-risk TLD (.{tld}) commonly used in phishing"
    if tld in MEDIUM_RISK_TLDS:
        return 12, f"Medium-risk TLD (.{tld})"
    if len(tld) > 6:
        return 5, f"Unusual TLD length (.{tld})"
    return 0, ""


def _detect_suspicious_keywords(url: str) -> list[str]:
    """Detect suspicious keywords in the URL path and domain."""
    url_lower = url.lower()
    hits = []
    for kw in SUSPICIOUS_KEYWORDS:
        if re.search(kw, url_lower):
            hits.append(kw)
    return hits


def _detect_homograph_attack(domain: str) -> list[dict]:
    """Detect potential homograph/confusable character attacks."""
    findings = []
    # Check for mixed scripts
    scripts = set()
    for ch in domain:
        if "\u0400" <= ch <= "\u04FF":
            scripts.add("cyrillic")
        elif "\u0370" <= ch <= "\u03FF":
            scripts.add("greek")
        elif "\u4E00" <= ch <= "\u9FFF":
            scripts.add("cjk")
        elif "\u0600" <= ch <= "\u06FF":
            scripts.add("arabic")
    if len(scripts) > 1:
        findings.append({
            "type": "mixed_scripts",
            "scripts": list(scripts),
            "detail": f"Domain contains mixed script types: {', '.join(scripts)}",
        })

    # Check for confusable substitutions
    for orig, subst in HOMOGRAPH_CHARS.items():
        if orig in domain:
            confusable = domain.replace(orig, subst.upper())
            for brand_pattern, _ in BRAND_DOMAINS:
                if re.search(brand_pattern, confusable):
                    findings.append({
                        "type": "confusable",
                        "character": orig,
                        "detail": f"Character '{orig}' may be a confusable substitution "
                                  f"to trick brand detection ({confusable})",
                    })
                    break

    # Check for Punycode (IDN)
    if domain.startswith("xn--"):
        findings.append({
            "type": "punycode",
            "detail": "Domain uses internationalized (Punycode) encoding, which can hide homograph attacks",
        })

    return findings


def _detect_brand_impersonation(domain: str, path: str) -> list[dict]:
    """Check if URL is impersonating a known brand."""
    results = []
    for brand_pattern, legit_domains in BRAND_DOMAINS:
        if re.search(brand_pattern, domain, re.IGNORECASE):
            is_legitimate = any(ld in domain for ld in legit_domains)
            results.append({
                "brand": brand_pattern.replace(r"\s*", " ").replace(r"\.", ".").replace("\\\\", "\\"),
                "in_domain": True,
                "is_legitimate": is_legitimate,
                "detail": f"{'Legitimate' if is_legitimate else 'Suspicious'} — "
                          f"{'matches' if is_legitimate else 'does not match'} "
                          f"known {brand_pattern.replace(r'\\s*', ' ').strip()} domain",
            })
        elif re.search(brand_pattern, path, re.IGNORECASE):
            results.append({
                "brand": brand_pattern.replace(r"\s*", " ").replace(r"\.", ".").replace("\\\\", "\\"),
                "in_domain": False,
                "is_legitimate": False,
                "detail": f"Brand name appears in URL path but not domain — possible redirect to phishing page",
            })
    return results


def _check_redirect_chain(url: str) -> dict:
    """Follow redirect chain via HEAD request."""
    try:
        import requests
        try:
            resp = requests.head(url, allow_redirects=True, timeout=10,
                                  headers={"User-Agent": "Mozilla/5.0"})
            chain = []
            if resp.history:
                for r in resp.history:
                    chain.append(r.url)
            chain.append(resp.url)
            return {
                "success": True,
                "final_url": resp.url,
                "status_code": resp.status_code,
                "redirect_count": len(resp.history),
                "redirect_chain": chain,
                "redirects": len(resp.history) > 0,
            }
        except requests.exceptions.SSLError:
            return {
                "success": True,
                "final_url": url,
                "status_code": 0,
                "redirect_count": 0,
                "redirect_chain": [],
                "redirects": False,
                "ssl_error": True,
            }
    except ImportError:
        return {"success": False, "error": "requests not available"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _check_domain_heuristics(domain: str) -> list[dict]:
    """Check domain for suspicious patterns."""
    findings = []

    # IP address as domain
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        findings.append({
            "type": "ip_address",
            "risk": 20,
            "detail": "Domain is an IP address — legitimate organizations rarely use raw IPs",
        })

    # Unusual subdomain count
    parts = domain.split(".")
    if len(parts) > 4:
        findings.append({
            "type": "too_many_subdomains",
            "risk": 10,
            "detail": f"Unusual number of subdomain levels ({len(parts) - 2}) — often used to hide malicious intent",
        })

    # Long domain
    if len(domain) > 40:
        findings.append({
            "type": "long_domain",
            "risk": 5,
            "detail": "Domain is unusually long",
        })

    # Contains hyphenated segments
    hyphen_count = domain.count("-")
    if hyphen_count > 2:
        findings.append({
            "type": "excessive_hyphens",
            "risk": 8,
            "detail": f"Domain contains {hyphen_count} hyphens — a common obfuscation technique",
        })

    # Random-looking domain (high entropy)
    alpha_count = sum(1 for c in domain.split(".")[0] if c.isalpha())
    digit_count = sum(1 for c in domain.split(".")[0] if c.isdigit())
    if digit_count > alpha_count and alpha_count > 0:
        findings.append({
            "type": "random_domain",
            "risk": 12,
            "detail": "Domain prefix has more digits than letters — looks algorithmically generated",
        })

    return findings


def analyze_url(url_string: str) -> dict:
    """Analyze a single URL for phishing indicators.

    Returns a dict with verdict (safe/suspicious/malicious), risk score,
    detailed findings, and explanations.
    """
    parsed = _parse_url(url_string)
    findings = []
    total_score = 0

    # 1. HTTPS check
    if not parsed["has_https"]:
        total_score += 10
        findings.append({"type": "no_https", "risk": 10,
                         "detail": "URL does not use HTTPS — data sent in plain text"})

    # 2. TLD risk
    tld_score, tld_detail = _score_tld_risk(parsed["tld"])
    if tld_score > 0:
        total_score += tld_score
        findings.append({"type": "risky_tld", "risk": tld_score, "detail": tld_detail})

    # 3. Suspicious keywords
    kw_hits = _detect_suspicious_keywords(parsed["full_url"])
    if kw_hits:
        kw_score = min(len(kw_hits) * 5, 25)
        total_score += kw_score
        findings.append({
            "type": "suspicious_keywords",
            "risk": kw_score,
            "detail": f"Suspicious keywords found: {', '.join(kw_hits[:6])}",
            "keywords": kw_hits,
        })

    # 4. Domain heuristics
    domain_findings = _check_domain_heuristics(parsed["domain"])
    for df in domain_findings:
        total_score += df["risk"]
        findings.append(df)

    # 5. Brand impersonation
    brand_matches = _detect_brand_impersonation(parsed["domain"], parsed["path"])
    for bm in brand_matches:
        if not bm["is_legitimate"]:
            total_score += 20
            findings.append({
                "type": "brand_impersonation",
                "risk": 20,
                "detail": bm["detail"],
                "brand": bm["brand"],
            })

    # 6. Homograph attacks
    homograph_findings = _detect_homograph_attack(parsed["domain"])
    for hf in homograph_findings:
        total_score += 15
        findings.append({"type": "homograph", "risk": 15, "detail": hf["detail"]})

    # 7. Redirect chain
    redirect_info = _check_redirect_chain(parsed["full_url"])
    if redirect_info.get("success"):
        if redirect_info.get("redirects"):
            total_score += 8
            findings.append({
                "type": "redirect_chain",
                "risk": 8,
                "detail": f"URL redirects through {redirect_info['redirect_count']} hop(s) — "
                          f"final destination: {redirect_info['final_url'][:80]}",
                "redirect_count": redirect_info["redirect_count"],
                "final_url": redirect_info["final_url"],
            })
        if redirect_info.get("ssl_error"):
            total_score += 15
            findings.append({
                "type": "ssl_error",
                "risk": 15,
                "detail": "SSL certificate error when connecting to the URL",
            })
        if redirect_info.get("status_code", 200) in (404, 410):
            total_score += 5
            findings.append({
                "type": "dead_link",
                "risk": 5,
                "detail": "URL returns a 404 (not found) — the page may have been taken down",
            })
    elif redirect_info.get("error"):
        findings.append({
            "type": "redirect_check_failed",
            "risk": 0,
            "detail": f"Could not check redirect chain: {redirect_info['error'][:100]}",
        })

    # Determine verdict
    total_score = min(total_score, 100)
    if total_score >= 60:
        verdict = "Malicious"
    elif total_score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # Build explanation
    explanation_lines = [f"## URL Intelligence Report"]
    explanation_lines.append(f"**Verdict:** {verdict} (Risk Score: {total_score}/100)")
    explanation_lines.append("")
    explanation_lines.append(f"**Target URL:** {parsed['full_url']}")
    explanation_lines.append(f"**Domain:** {parsed['domain']}")
    explanation_lines.append(f"**TLD:** .{parsed['tld']}")
    explanation_lines.append(f"**HTTPS:** {'Yes' if parsed['has_https'] else 'No'}")
    explanation_lines.append("")
    if findings:
        explanation_lines.append("### Findings")
        for f in findings:
            risk_tag = f"`+{f['risk']}`" if f["risk"] > 0 else ""
            explanation_lines.append(f"- {f['detail']} {risk_tag}")
    explanation_lines.append("")
    if kw_hits:
        explanation_lines.append(f"### Suspicious Keywords Found")
        explanation_lines.append(f"{', '.join(kw_hits)}")
    if brand_matches:
        explanation_lines.append(f"### Brand Analysis")
        for bm in brand_matches:
            explanation_lines.append(f"- {bm['detail']}")

    return {
        "url": url_string,
        "parsed": parsed,
        "verdict": verdict,
        "risk_score": total_score,
        "findings": findings,
        "suspicious_keywords": kw_hits,
        "brand_matches": brand_matches,
        "homograph_attacks": homograph_findings,
        "redirect_analysis": redirect_info,
        "domain_findings": domain_findings,
        "explanation_text": "\n".join(explanation_lines),
        "reasons": [f["detail"] for f in findings if f["risk"] > 0],
    }
