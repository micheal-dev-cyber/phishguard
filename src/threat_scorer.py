import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def compute_combined_threat_score(
    linguistic_score: int,
    vt_results: Optional[List[Dict[str, Any]]] = None,
    linguistic_weight: float = 0.55,
    vt_weight: float = 0.45,
) -> Dict[str, Any]:
    """
    Combine the heuristic linguistic threat score with VirusTotal URL reputation
    scores into a single weighted composite score (0–100).

    Parameters
    ----------
    linguistic_score : int
        The heuristic risk score from the email analysis engine (0–100).
    vt_results : list[dict], optional
        List of per-URL VirusTotal results as returned by check_multiple_urls().
    linguistic_weight : float
        Weight assigned to the linguistic analysis (default 0.55).
    vt_weight : float
        Weight assigned to the URL reputation analysis (default 0.45).

    Returns
    -------
    dict with keys:
        - composite_score (int) — final blended score 0–100
        - linguistic_contribution (float)
        - vt_contribution (float)
        - vt_url_count (int)
        - vt_malicious_count (int)
        - vt_suspicious_count (int)
        - vt_max_malicious_score (int) — highest single-URL malicious vendor count
        - has_vt_data (bool)
        - severity (str)
        - severity_color (str)
    """
    vt_url_count = 0
    vt_malicious_count = 0
    vt_suspicious_count = 0
    vt_max_malicious_score = 0

    if vt_results:
        vt_url_count = len(vt_results)
        for r in vt_results:
            mal = r.get("malicious", 0)
            sus = r.get("suspicious", 0)
            vt_malicious_count += mal
            vt_suspicious_count += sus
            if mal > vt_max_malicious_score:
                vt_max_malicious_score = mal

    # Compute VT-derived threat score (0–100)
    if vt_url_count > 0:
        # Malicious vendor ratio as a proportion of total vendors scanned
        vendor_ratio = 0.0
        for r in vt_results:
            total = r.get("total_vendors", 1) or 1
            mal = r.get("malicious", 0)
            vendor_ratio += mal / total
        avg_ratio = vendor_ratio / vt_url_count
        vt_score = min(round(avg_ratio * 100), 100)
    else:
        vt_score = 0

    # Weighted composite
    linguistic_contribution = round(linguistic_score * linguistic_weight, 1)
    vt_contribution = round(vt_score * vt_weight, 1)
    composite_score = min(round(linguistic_contribution + vt_contribution), 100)

    if composite_score >= 75:
        severity = "CRITICAL"
        severity_color = "#ff4444"
    elif composite_score >= 50:
        severity = "HIGH"
        severity_color = "#ff8800"
    elif composite_score >= 25:
        severity = "MEDIUM"
        severity_color = "#ffaa00"
    else:
        severity = "LOW"
        severity_color = "#44aa44"

    return {
        "composite_score": composite_score,
        "linguistic_contribution": linguistic_contribution,
        "vt_contribution": vt_contribution,
        "vt_score": vt_score,
        "vt_url_count": vt_url_count,
        "vt_malicious_count": vt_malicious_count,
        "vt_suspicious_count": vt_suspicious_count,
        "vt_max_malicious_score": vt_max_malicious_score,
        "has_vt_data": vt_url_count > 0,
        "severity": severity,
        "severity_color": severity_color,
    }


def format_combined_report(combined: Dict[str, Any]) -> str:
    """Generate a human-readable summary string from the combined threat score."""
    parts = [
        f"**Composite Threat Score:** {combined['composite_score']}/100 ({combined['severity']})",
        f"- Linguistic contribution: {combined['linguistic_contribution']} pts",
    ]
    if combined["has_vt_data"]:
        parts.append(
            f"- VT reputation contribution: {combined['vt_contribution']} pts "
            f"(VT score: {combined['vt_score']}/100, "
            f"{combined['vt_malicious_count']} malicious / "
            f"{combined['vt_suspicious_count']} suspicious across "
            f"{combined['vt_url_count']} URL(s))"
        )
    else:
        parts.append("- No VirusTotal data available; score is purely linguistic.")
    return "\n".join(parts)
