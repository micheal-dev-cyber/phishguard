# src/header_parser.py
import re
import socket
from datetime import datetime

def parse_email_headers(raw_headers: str) -> dict:
    """
    Parse raw email headers and extract security-relevant fields.
    """
    results = {
        "from": "",
        "reply_to": "",
        "return_path": "",
        "message_id": "",
        "date": "",
        "subject": "",
        "received_hops": [],
        "spf": {"result": "none", "domain": ""},
        "dkim": {"result": "none", "domain": ""},
        "dmarc": {"result": "none"},
        "x_originating_ip": "",
        "findings": [],
        "risk_score": 0,
        "auth_summary": []
    }

    lines = raw_headers.replace("\r\n", "\n").replace("\r", "\n")
    # Unfold headers (continuation lines start with whitespace)
    unfolded = re.sub(r'\n[ \t]+', ' ', lines)

    header_map = {}
    for line in unfolded.split('\n'):
        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip().lower()
            value = value.strip()
            if key not in header_map:
                header_map[key] = []
            header_map[key].append(value)

    # Extract basic fields
    results["from"]        = header_map.get("from", [""])[0]
    results["reply_to"]    = header_map.get("reply-to", [""])[0]
    results["return_path"] = header_map.get("return-path", [""])[0]
    results["message_id"]  = header_map.get("message-id", [""])[0]
    results["date"]        = header_map.get("date", [""])[0]
    results["subject"]     = header_map.get("subject", [""])[0]
    results["x_originating_ip"] = header_map.get("x-originating-ip", [""])[0]

    # Parse Authentication-Results
    auth_results = " ".join(header_map.get("authentication-results", []))
    results["spf"]   = _parse_auth_result(auth_results, "spf")
    results["dkim"]  = _parse_auth_result(auth_results, "dkim")
    results["dmarc"] = _parse_auth_result(auth_results, "dmarc")

    # Parse Received-SPF header as fallback
    received_spf = " ".join(header_map.get("received-spf", []))
    if results["spf"]["result"] == "none" and received_spf:
        if "pass" in received_spf.lower():
            results["spf"]["result"] = "pass"
        elif "fail" in received_spf.lower():
            results["spf"]["result"] = "fail"
        elif "softfail" in received_spf.lower():
            results["spf"]["result"] = "softfail"
        elif "neutral" in received_spf.lower():
            results["spf"]["result"] = "neutral"

    # Parse Received hops
    received_list = header_map.get("received", [])
    for hop in received_list:
        hop_info = _parse_received_hop(hop)
        if hop_info:
            results["received_hops"].append(hop_info)

    # Security analysis
    results["findings"], results["risk_score"] = _analyze_security(results)
    results["auth_summary"] = _build_auth_summary(results)

    return results


def _parse_auth_result(auth_string: str, protocol: str) -> dict:
    result = {"result": "none", "domain": ""}
    pattern = rf'{protocol}=(\w+)'
    match = re.search(pattern, auth_string, re.IGNORECASE)
    if match:
        result["result"] = match.group(1).lower()
    domain_pattern = rf'{protocol}.*?header\.(?:i|from|d)=([^\s;]+)'
    dm = re.search(domain_pattern, auth_string, re.IGNORECASE)
    if dm:
        result["domain"] = dm.group(1)
    return result


def _parse_received_hop(hop_string: str) -> dict:
    info = {"raw": hop_string[:120], "from_host": "", "by_host": "", "ip": "", "timestamp": ""}
    from_match = re.search(r'from\s+(\S+)', hop_string, re.IGNORECASE)
    by_match   = re.search(r'by\s+(\S+)', hop_string, re.IGNORECASE)
    ip_match   = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', hop_string)
    time_match = re.search(r';\s*(.+)$', hop_string)

    if from_match: info["from_host"] = from_match.group(1)
    if by_match:   info["by_host"]   = by_match.group(1)
    if ip_match:   info["ip"]        = ip_match.group(1)
    if time_match: info["timestamp"] = time_match.group(1).strip()[:50]
    return info


def _analyze_security(results: dict) -> tuple:
    findings = []
    score = 0

    # SPF check
    spf = results["spf"]["result"]
    if spf == "fail":
        findings.append("🔴 SPF FAIL — Sender IP not authorized to send for this domain")
        score += 35
    elif spf == "softfail":
        findings.append("🟠 SPF SOFTFAIL — Sender IP is not recommended for this domain")
        score += 20
    elif spf == "none":
        findings.append("🟡 SPF NONE — No SPF record found, cannot verify sender")
        score += 10
    elif spf == "pass":
        findings.append("🟢 SPF PASS — Sender IP is authorized")

    # DKIM check
    dkim = results["dkim"]["result"]
    if dkim == "fail":
        findings.append("🔴 DKIM FAIL — Email signature is invalid or tampered")
        score += 35
    elif dkim == "none":
        findings.append("🟡 DKIM NONE — No DKIM signature found")
        score += 10
    elif dkim == "pass":
        findings.append("🟢 DKIM PASS — Email signature is valid")

    # DMARC check
    dmarc = results["dmarc"]["result"]
    if dmarc == "fail":
        findings.append("🔴 DMARC FAIL — Email failed domain alignment policy")
        score += 30
    elif dmarc == "none":
        findings.append("🟡 DMARC NONE — No DMARC policy found")
        score += 5
    elif dmarc == "pass":
        findings.append("🟢 DMARC PASS — Email passed domain alignment")

    # From vs Reply-To mismatch
    from_domain   = _extract_domain(results["from"])
    reply_domain  = _extract_domain(results["reply_to"])
    return_domain = _extract_domain(results["return_path"])

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(f"🔴 Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — classic phishing tactic")
        score += 40

    if return_domain and from_domain and return_domain != from_domain:
        findings.append(f"🟠 Return-Path domain ({return_domain}) differs from From domain ({from_domain})")
        score += 15

    # Too many hops
    hop_count = len(results["received_hops"])
    if hop_count > 8:
        findings.append(f"🟠 Unusual routing — {hop_count} relay hops detected (normal is 2-5)")
        score += 15

    return findings, min(score, 100)


def _build_auth_summary(results: dict) -> list:
    summary = []
    for proto in ["spf", "dkim", "dmarc"]:
        r = results[proto]["result"]
        icon = "✅" if r == "pass" else "❌" if r in ("fail",) else "⚠️"
        summary.append({"protocol": proto.upper(), "result": r.upper(), "icon": icon})
    return summary


def _extract_domain(email_str: str) -> str:
    match = re.search(r'@([\w.\-]+)', email_str)
    return match.group(1).lower() if match else ""