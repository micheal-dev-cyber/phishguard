# src/header_parser.py
import re

def parse_email_headers(raw_headers: str) -> dict:
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

    # FIX 1: Isolate headers from the body. The body always starts after a double newline.
    lines = raw_headers.replace("\r\n", "\n").replace("\r", "\n")
    header_part = lines.split("\n\n")[0] 

    # Unfold multi-line headers (RFC 2822 compliance)
    unfolded = re.sub(r'\n[ \t]+', ' ', header_part)

    header_map = {}
    for line in unfolded.split('\n'):
        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip().lower()
            value = value.strip()
            if key not in header_map:
                header_map[key] = []
            header_map[key].append(value)

    results["from"]             = header_map.get("from", [""])[0]
    results["reply_to"]         = header_map.get("reply-to", [""])[0]
    results["return_path"]      = header_map.get("return-path", [""])[0]
    results["message_id"]       = header_map.get("message-id", [""])[0]
    results["date"]             = header_map.get("date", [""])[0]
    results["subject"]          = header_map.get("subject", [""])[0]
    results["x_originating_ip"] = header_map.get("x-originating-ip", [""])[0]

    auth_results         = " ".join(header_map.get("authentication-results", []))
    results["spf"]       = _parse_auth_result(auth_results, "spf")
    results["dkim"]      = _parse_auth_result(auth_results, "dkim")
    results["dmarc"]     = _parse_auth_result(auth_results, "dmarc")

    received_spf = " ".join(header_map.get("received-spf", []))
    if results["spf"]["result"] == "none" and received_spf:
        for val in ["pass", "fail", "softfail", "neutral"]:
            if val in received_spf.lower():
                results["spf"]["result"] = val
                break

    for hop in header_map.get("received", []):
        hop_info = _parse_received_hop(hop)
        if hop_info:
            results["received_hops"].append(hop_info)

    results["findings"], results["risk_score"] = _analyze_security(results)
    results["auth_summary"] = _build_auth_summary(results)
    return results


def _parse_auth_result(auth_string: str, protocol: str) -> dict:
    result = {"result": "none", "domain": ""}
    match = re.search(rf'{protocol}=(\w+)', auth_string, re.IGNORECASE)
    if match:
        result["result"] = match.group(1).lower()
    dm = re.search(rf'{protocol}.*?header\.(?:i|from|d)=([^\s;]+)', auth_string, re.IGNORECASE)
    if dm:
        result["domain"] = dm.group(1)
    return result


def _parse_received_hop(hop_string: str) -> dict:
    # FIX 2: Removed string truncation so Streamlit can display the full hop code block
    info = {"raw": hop_string, "from_host": "", "by_host": "", "ip": "", "timestamp": ""}
    fm = re.search(r'from\s+(\S+)', hop_string, re.IGNORECASE)
    bm = re.search(r'by\s+(\S+)', hop_string, re.IGNORECASE)
    im = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', hop_string)
    tm = re.search(r';\s*(.+)$', hop_string)
    
    if fm: info["from_host"] = fm.group(1)
    if bm: info["by_host"]   = bm.group(1)
    if im: info["ip"]        = im.group(1)
    if tm: info["timestamp"] = tm.group(1).strip()[:50]
    return info


def _analyze_security(results: dict) -> tuple:
    findings = []
    score    = 0

    spf = results["spf"]["result"]
    if spf == "fail":
        findings.append("🔴 SPF FAIL — Sender IP not authorized to send for this domain")
        score += 35
    elif spf == "softfail":
        findings.append("🟠 SPF SOFTFAIL — Sender IP not recommended for this domain")
        score += 20
    elif spf == "none":
        findings.append("🟡 SPF NONE — No SPF record found, cannot verify sender")
        score += 10
    else:
        findings.append("🟢 SPF PASS — Sender IP is authorized")

    dkim = results["dkim"]["result"]
    if dkim == "fail":
        findings.append("🔴 DKIM FAIL — Email signature is invalid or tampered")
        score += 35
    elif dkim == "none":
        findings.append("🟡 DKIM NONE — No DKIM signature found")
        score += 10
    else:
        findings.append("🟢 DKIM PASS — Email signature is valid")

    dmarc = results["dmarc"]["result"]
    if dmarc == "fail":
        findings.append("🔴 DMARC FAIL — Email failed domain alignment policy")
        score += 30
    elif dmarc == "none":
        findings.append("🟡 DMARC NONE — No DMARC policy found")
        score += 5
    else:
        findings.append("🟢 DMARC PASS — Email passed domain alignment")

    from_domain   = _extract_domain(results["from"])
    reply_domain  = _extract_domain(results["reply_to"])
    return_domain = _extract_domain(results["return_path"])

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(f"🔴 Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — classic phishing tactic")
        score += 40

    if return_domain and from_domain and return_domain != from_domain:
        findings.append(f"🟠 Return-Path domain ({return_domain}) differs from From domain ({from_domain})")
        score += 15

    hop_count = len(results["received_hops"])
    if hop_count > 8:
        findings.append(f"🟠 Unusual routing — {hop_count} relay hops detected (normal is 2-5)")
        score += 15

    x_ip = results.get("x_originating_ip", "")
    if x_ip:
        findings.append(f"🟡 Originating IP found in headers: {x_ip} — verify this IP's reputation")

    return findings, min(score, 100)


def _build_auth_summary(results: dict) -> list:
    summary = []
    for proto in ["spf", "dkim", "dmarc"]:
        r = results[proto]["result"]
        icon = "✅" if r == "pass" else "❌" if r == "fail" else "⚠️"
        summary.append({"protocol": proto.upper(), "result": r.upper(), "icon": icon})
    return summary


def _extract_domain(email_str: str) -> str:
    match = re.search(r'@([\w.\-]+)', email_str)
    return match.group(1).lower() if match else ""