import json
from datetime import datetime, timezone
from typing import Optional

from src.threat_intel_sharing import (
    _stix_id,
    build_indicator,
    build_observed_data,
    build_relationship,
    build_stix_bundle,
    compute_linguistic_baseline,
)

STIX_EXPORTER_VERSION = "3.0.0"


def build_enterprise_stix_bundle(
    email_text: str = "",
    results: Optional[dict] = None,
    osint_data: Optional[dict] = None,
    vt_results: Optional[list] = None,
    attachment_result: Optional[dict] = None,
    sender_anomaly: Optional[dict] = None,
    perplexity_result: Optional[dict] = None,
) -> dict:
    if results is None:
        results = {}

    ling_hash = compute_linguistic_baseline(email_text)

    objects = []

    indicator = _build_enriched_indicator(results, ling_hash, osint_data, sender_anomaly, perplexity_result)
    objects.append(indicator)

    observed = _build_enriched_observed_data(
        email_text, results, osint_data, vt_results, attachment_result, perplexity_result
    )
    objects.append(observed)

    relationship = build_relationship(indicator["id"], observed["id"])
    objects.append(relationship)

    enrichment_obj = _build_enrichment_object(results, osint_data, vt_results, attachment_result, sender_anomaly, perplexity_result)
    if enrichment_obj:
        objects.append(enrichment_obj)

    bundle = build_stix_bundle(objects)

    bundle["custom_properties"] = {
        "x_phishguard_exporter_version": STIX_EXPORTER_VERSION,
        "x_phishguard_generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "x_phishguard_modules": ["sender_reputation", "url_threat_status", "attachment_verdict", "ai_authorship"],
    }

    return bundle


def _build_enriched_indicator(
    results: dict,
    ling_hash: str,
    osint_data: Optional[dict],
    sender_anomaly: Optional[dict],
    perplexity_result: Optional[dict],
) -> dict:
    severity = results.get("severity", "UNKNOWN")
    risk_score = results.get("risk_score", 0)
    pattern = f"[x-phishguard-linguistic-hash = '{ling_hash}']"

    sender_domain = None
    if osint_data:
        sender = osint_data.get("sender", "")
        if sender and "@" in sender:
            sender_domain = sender.split("@")[-1]

    indicator = build_indicator(
        ling_hash,
        pattern,
        severity=severity,
        risk_score=risk_score,
        sender_domain=sender_domain,
        subject=results.get("subject", ""),
        mitre_attack_ids=_get_mitre_attack_ids(severity),
    )

    indicator["custom_properties"]["x_phishguard_osint_risk_score"] = (
        osint_data.get("osint_risk_score", 0) if osint_data else 0
    )

    if sender_anomaly:
        indicator["custom_properties"]["x_phishguard_sender_anomaly_score"] = (
            sender_anomaly.get("anomaly_score", 0)
        )

    if perplexity_result:
        indicator["custom_properties"]["x_phishguard_ai_authorship_probability"] = (
            perplexity_result.get("ai_probability", 0)
        )

    return indicator


def _build_enriched_observed_data(
    email_text: str,
    results: dict,
    osint_data: Optional[dict],
    vt_results: Optional[list],
    attachment_result: Optional[dict],
    perplexity_result: Optional[dict],
) -> dict:
    urls = results.get("urls_found", []) or results.get("suspicious_urls", [])
    urls_clean = []
    for u in urls:
        if isinstance(u, dict):
            urls_clean.append(u.get("url", ""))
        else:
            urls_clean.append(str(u))

    sender = osint_data.get("sender", "") if osint_data else ""
    subject = results.get("subject", "")

    attachment_hashes = []
    if attachment_result and not attachment_result.get("error"):
        for key in ("sha256", "sha1", "md5"):
            val = attachment_result.get(key)
            if val:
                attachment_hashes.append(f"{key}:{val}")

    observed = build_observed_data(
        email_text[:2000],
        urls_clean,
        sender=sender,
        subject=subject,
        attachment_hashes=attachment_hashes,
    )

    observed["custom_properties"]["x_phishguard_total_urls"] = len(urls_clean)

    if vt_results:
        verified_malicious = sum(1 for v in vt_results if isinstance(v, dict) and v.get("status") == "malicious")
        verified_suspicious = sum(1 for v in vt_results if isinstance(v, dict) and v.get("status") == "suspicious")
        observed["custom_properties"]["x_phishguard_vt_malicious_count"] = verified_malicious
        observed["custom_properties"]["x_phishguard_vt_suspicious_count"] = verified_suspicious

        threat_names = []
        for v in vt_results:
            if isinstance(v, dict):
                threat_names.extend(v.get("threat_names", []))
        if threat_names:
            observed["custom_properties"]["x_phishguard_vt_threat_names"] = json.dumps(threat_names[:10])

    if attachment_result and not attachment_result.get("error"):
        att_verdict = "unknown"
        vt_rep = attachment_result.get("vt_reputation", {})
        if isinstance(vt_rep, dict):
            att_verdict = vt_rep.get("verdict", "unknown")
        observed["custom_properties"]["x_phishguard_attachment_verdict"] = att_verdict
        observed["custom_properties"]["x_phishguard_attachment_filename"] = attachment_result.get("filename", "")
        observed["custom_properties"]["x_phishguard_attachment_size"] = attachment_result.get("size", 0)
        observed["custom_properties"]["x_phishguard_attachment_sha256_prefix"] = (
            (attachment_result.get("sha256", "") or "")[:16]
        )

    if perplexity_result:
        observed["custom_properties"]["x_phishguard_ai_written_probability"] = perplexity_result.get("ai_probability", 0)
        observed["custom_properties"]["x_phishguard_ai_indicators"] = json.dumps(
            perplexity_result.get("indicators", [])[:5]
        )

    return observed


def _build_enrichment_object(
    results: dict,
    osint_data: Optional[dict],
    vt_results: Optional[list],
    attachment_result: Optional[dict],
    sender_anomaly: Optional[dict],
    perplexity_result: Optional[dict],
) -> Optional[dict]:
    enrichment_obj = {
        "type": "x-phishguard-enrichment",
        "spec_version": "2.1",
        "id": _stix_id("x-phishguard-enrichment", json.dumps(results.get("risk_score", 0))),
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "custom_properties": {},
    }

    enrichment_obj["custom_properties"]["x_phishguard_overall_risk_score"] = results.get("risk_score", 0)
    enrichment_obj["custom_properties"]["x_phishguard_severity"] = results.get("severity", "UNKNOWN")

    if results.get("urls_found"):
        enrichment_obj["custom_properties"]["x_phishguard_url_count"] = len(results["urls_found"])

    if results.get("has_attachments"):
        enrichment_obj["custom_properties"]["x_phishguard_has_attachments"] = True

    if osint_data:
        enrichment_obj["custom_properties"]["x_phishguard_osint_risk_score"] = osint_data.get("osint_risk_score", 0)
        enrichment_obj["custom_properties"]["x_phishguard_high_risk_domains"] = len(osint_data.get("high_risk_domains", []))
        enrichment_obj["custom_properties"]["x_phishguard_new_domains_found"] = len(osint_data.get("new_domains", []))
        enrichment_obj["custom_properties"]["x_phishguard_blacklisted_domains"] = len(osint_data.get("blacklisted", []))

    if vt_results:
        enrichment_obj["custom_properties"]["x_phishguard_total_urls_scanned"] = len(vt_results)

    if sender_anomaly:
        enrichment_obj["custom_properties"]["x_phishguard_sender_anomaly_score"] = sender_anomaly.get("anomaly_score", 0)
        enrichment_obj["custom_properties"]["x_phishguard_sender_is_anomalous"] = sender_anomaly.get("is_anomalous", False)
        enrichment_obj["custom_properties"]["x_phishguard_sender_financial_request"] = sender_anomaly.get("first_financial_request", False)

    if perplexity_result:
        enrichment_obj["custom_properties"]["x_phishguard_ai_written_score"] = perplexity_result.get("score", 0)

    if attachment_result and not attachment_result.get("error"):
        enrichment_obj["custom_properties"]["x_phishguard_attachment_vt_verdict"] = (
            attachment_result.get("vt_reputation", {}).get("verdict", "unknown")
            if isinstance(attachment_result.get("vt_reputation"), dict) else "unknown"
        )

    if enrichment_obj["custom_properties"]:
        return enrichment_obj
    return None


def _get_mitre_attack_ids(severity: str) -> list:
    base = ["T1566"]  # Phishing
    if severity == "CRITICAL":
        return base + ["T1566.001", "T1566.002", "T1557", "T1534"]
    if severity == "HIGH":
        return base + ["T1566.001", "T1566.002"]
    return base
