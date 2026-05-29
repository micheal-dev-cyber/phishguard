import re
import socket
import logging
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger("link-checker")

REDIRECT_DEPTH_LIMIT = 5
TIMEOUT_SECONDS = 5


def resolve_redirect_chain(url: str, max_depth: int = REDIRECT_DEPTH_LIMIT) -> list:
    import requests
    chain = [url]
    visited = {url}
    for _ in range(max_depth):
        try:
            resp = requests.head(url, allow_redirects=False, timeout=TIMEOUT_SECONDS)
            location = resp.headers.get("Location") or resp.headers.get("location")
            if not location:
                break
            if location.startswith("/"):
                parsed = urlparse(url)
                location = f"{parsed.scheme}://{parsed.netloc}{location}"
            if location in visited:
                break
            visited.add(location)
            chain.append(location)
            url = location
        except requests.RequestException:
            break
    return chain


def check_dns_reputation(domain: str) -> Optional[dict]:
    try:
        addr = socket.getaddrinfo(domain, 80, socket.AF_INET)
        ip = addr[0][4][0]
        return {"domain": domain, "ip": ip, "resolves": True}
    except (socket.gaierror, OSError):
        return {"domain": domain, "ip": None, "resolves": False}


def check_url_safety(url: str) -> dict:
    result = {
        "url": url,
        "redirect_chain": [],
        "resolves": False,
        "is_ip_based": False,
        "has_ip_in_path": False,
        "suspicious_tld": False,
        "suspicious_keywords": False,
        "risk_score": 0,
    }

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    result["is_ip_based"] = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))

    path_ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parsed.path)
    result["has_ip_in_path"] = len(path_ips) > 0

    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".date", ".click", ".loan", ".download", ".review", ".science", ".party"}
    for tld in suspicious_tlds:
        if hostname.endswith(tld):
            result["suspicious_tld"] = True
            break

    suspicious_words = ["login", "signin", "verify", "update", "confirm", "secure", "account", "banking", "password", "credential"]
    domain_lower = hostname.lower()
    path_lower = parsed.path.lower()
    combined = domain_lower + path_lower
    found_keywords = [w for w in suspicious_words if w in combined]
    if found_keywords:
        result["suspicious_keywords"] = True

    if result["is_ip_based"]:
        result["risk_score"] += 30
    if result["has_ip_in_path"]:
        result["risk_score"] += 15
    if result["suspicious_tld"]:
        result["risk_score"] += 25
    if result["suspicious_keywords"]:
        result["risk_score"] += 10 * len(found_keywords)

    try:
        chain = resolve_redirect_chain(url)
        result["redirect_chain"] = chain
        if len(chain) > 2:
            result["risk_score"] += 15
    except Exception as e:
        logger.debug("Redirect resolution failed for %s: %s", url, e)

    dns = check_dns_reputation(hostname)
    if dns:
        result["resolves"] = dns["resolves"]
        if not dns["resolves"]:
            result["risk_score"] += 40

    result["risk_score"] = min(result["risk_score"], 100)
    return result
