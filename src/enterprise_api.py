"""
PhishGuard AI — Enterprise REST API Adapter (stdlib only)

Provides handle_scan_request() that runs the full multi-layered detection
pipeline and returns a clean JSON verdict. Framework-agnostic — callable
from api_proxy.py, FastAPI, Flask, uvicorn, or any HTTP handler.

Usage from api_proxy.py:
    from src.enterprise_api import handle_scan_request
    body = json.loads(self.rfile.read(...))
    response = handle_scan_request(body)
    self._send_json(response)

Usage from FastAPI/Flask:
    from src.enterprise_api import handle_scan_request
    return JSONResponse(handle_scan_request(request.json))
"""

from src.aitm_detector import detect_aitm_harvester
from src.detector import analyze_email
from src.env import ENV
from src.osint import run_osint
from src.perplexity_analyzer import compute_perplexity_score
from src.threat_intel import check_multiple_urls, get_threat_summary


def handle_scan_request(body: dict) -> dict:
    text = (body.get("text") or "").strip()
    urls = body.get("urls") or []

    if not text and not urls:
        return {"error": "Provide 'text' and/or 'urls' fields"}

    heuristic = {}
    if text:
        heuristic = analyze_email(text)
        text_urls = heuristic.get("urls_found", []) or heuristic.get("suspicious_urls", [])
        urls = list(dict.fromkeys(urls + text_urls))

    ai_text = compute_perplexity_score(text) if text else {}

    aitm = detect_aitm_harvester(email_text=text, urls=urls)

    risk_score = heuristic.get("risk_score", 0)
    ai_prob = ai_text.get("ai_probability", 0) if ai_text else 0
    aitm_conf = aitm.get("confidence", 0) if aitm else 0

    composite_score = risk_score
    if ai_prob >= 70:
        composite_score = min(composite_score + 10, 100)
    if aitm_conf >= 50:
        composite_score = max(composite_score, aitm_conf)

    has_vt = bool(ENV.VIRUSTOTAL_API_KEY)
    vt_results = None
    osint_data = None
    if has_vt and urls:
        vt_results = check_multiple_urls(urls, max_urls=5)
        vt_summary = get_threat_summary(vt_results)
        if vt_summary.get("has_threats"):
            composite_score = min(composite_score + 15, 100)

    if has_vt and text:
        osint_data = run_osint(text)
        osint_risk = osint_data.get("osint_risk_score", 0)
        if osint_risk > composite_score:
            composite_score = osint_risk

    return {
        "verdict": {
            "risk_score": composite_score,
            "severity": _severity_label(composite_score),
            "ai_written_probability": ai_prob,
            "aitm_confidence": aitm_conf,
            "is_threat": composite_score >= 50,
        },
        "layers": {
            "heuristic": {
                "score": risk_score,
                "severity": heuristic.get("severity", "UNKNOWN"),
                "keyword_hits": heuristic.get("total_keyword_hits", 0),
                "urls_found": heuristic.get("urls_found", []),
                "suspicious_urls": heuristic.get("suspicious_urls", []),
            } if heuristic else None,
            "ai_text_detection": {
                "probability": ai_prob,
                "score": ai_text.get("score", 0),
                "indicators": ai_text.get("indicators", []),
            } if ai_text else None,
            "aitm_detection": {
                "confidence": aitm_conf,
                "severity": aitm.get("severity", ""),
                "label": aitm.get("label", ""),
                "indicators": aitm.get("indicators", []),
            } if aitm else None,
        },
        "reputation": {
            "virustotal_urls": [
                {
                    "url": r.get("url"),
                    "status": r.get("status"),
                    "malicious": r.get("malicious", 0),
                    "suspicious": r.get("suspicious", 0),
                }
                for r in (vt_results or []) if isinstance(r, dict)
            ] if vt_results else None,
            "osint": {
                "osint_risk_score": osint_data.get("osint_risk_score", 0),
                "high_risk_domains": len(osint_data.get("high_risk_domains", [])),
                "blacklisted_domains": len(osint_data.get("blacklisted", [])),
            } if osint_data else None,
        },
        "meta": {
            "service": "phishguard-enterprise-api",
            "version": "3.0.0",
            "api_version": "v1",
        },
    }


def _severity_label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"
