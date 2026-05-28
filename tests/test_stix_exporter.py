import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
from src.stix_exporter import build_enterprise_stix_bundle


def test_bundle_structure():
    bundle = build_enterprise_stix_bundle(
        email_text="Test email",
        results={"risk_score": 75, "severity": "HIGH", "urls_found": ["https://evil.com"], "subject": "Urgent"},
    )
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) >= 3
    assert bundle["custom_properties"]["x_phishguard_exporter_version"] == "3.0.0"


def test_contains_indicator():
    bundle = build_enterprise_stix_bundle(
        email_text="Suspicious email content here",
        results={"risk_score": 90, "severity": "CRITICAL"},
    )
    types = [o["type"] for o in bundle["objects"]]
    assert "indicator" in types
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert indicator["pattern_type"] == "x-phishguard-linguistic-hash"
    assert indicator["confidence"] == 90


def test_contains_observed_data():
    bundle = build_enterprise_stix_bundle(
        email_text="Observe this content",
        results={"risk_score": 50, "severity": "MEDIUM"},
    )
    types = [o["type"] for o in bundle["objects"]]
    assert "observed-data" in types
    observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    assert "0" in observed["objects"]


def test_contains_relationship():
    bundle = build_enterprise_stix_bundle(
        email_text="Test",
        results={"risk_score": 60, "severity": "HIGH"},
    )
    types = [o["type"] for o in bundle["objects"]]
    assert "relationship" in types


def test_osint_data_included():
    osint_data = {
        "sender": "attacker@evil-phish.xyz",
        "osint_risk_score": 85,
        "high_risk_domains": [{"domain": "evil-phish.xyz"}],
        "new_domains": [],
        "blacklisted": [],
    }
    bundle = build_enterprise_stix_bundle(
        email_text="Test",
        results={"risk_score": 80, "severity": "HIGH"},
        osint_data=osint_data,
    )
    enrichment = next((o for o in bundle["objects"] if o["type"] == "x-phishguard-enrichment"), None)
    assert enrichment is not None
    cp = enrichment["custom_properties"]
    assert cp["x_phishguard_osint_risk_score"] == 85
    assert cp["x_phishguard_high_risk_domains"] == 1


def test_vt_results_included():
    vt_results = [
        {"url": "https://evil.com", "status": "malicious", "malicious": 8, "suspicious": 3, "threat_names": ["Phishing", "Malware"]},
    ]
    bundle = build_enterprise_stix_bundle(
        email_text="Test",
        results={"risk_score": 85, "severity": "CRITICAL", "urls_found": ["https://evil.com"]},
        vt_results=vt_results,
    )
    observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    cp = observed["custom_properties"]
    assert cp["x_phishguard_vt_malicious_count"] == 1
    assert cp["x_phishguard_vt_suspicious_count"] == 0
    assert "Phishing" in cp["x_phishguard_vt_threat_names"]


def test_attachment_result_included():
    attachment_result = {
        "filename": "invoice.pdf",
        "size": 12345,
        "md5": "abc123def456",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "vt_reputation": {"verdict": "malicious"},
    }
    bundle = build_enterprise_stix_bundle(
        email_text="Test",
        results={"risk_score": 70, "severity": "HIGH"},
        attachment_result=attachment_result,
    )
    observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    cp = observed["custom_properties"]
    assert cp["x_phishguard_attachment_verdict"] == "malicious"
    assert cp["x_phishguard_attachment_filename"] == "invoice.pdf"
    assert cp["x_phishguard_attachment_sha256_prefix"] == "abcdef1234567890"


def test_sender_anomaly_included():
    sender_anomaly = {
        "anomaly_score": 85,
        "is_anomalous": True,
        "first_financial_request": True,
    }
    bundle = build_enterprise_stix_bundle(
        email_text="Test",
        results={"risk_score": 75, "severity": "HIGH"},
        sender_anomaly=sender_anomaly,
    )
    enrichment = next((o for o in bundle["objects"] if o["type"] == "x-phishguard-enrichment"), None)
    assert enrichment is not None
    cp = enrichment["custom_properties"]
    assert cp["x_phishguard_sender_anomaly_score"] == 85
    assert cp["x_phishguard_sender_is_anomalous"] is True
    assert cp["x_phishguard_sender_financial_request"] is True


def test_perplexity_result_included():
    perplexity_result = {
        "ai_probability": 87,
        "score": 0.87,
        "indicators": ["Low burstiness", "High lexical diversity"],
    }
    bundle = build_enterprise_stix_bundle(
        email_text="Test",
        results={"risk_score": 60, "severity": "MEDIUM"},
        perplexity_result=perplexity_result,
    )
    enrichment = next((o for o in bundle["objects"] if o["type"] == "x-phishguard-enrichment"), None)
    assert enrichment is not None
    assert enrichment["custom_properties"]["x_phishguard_ai_written_score"] == 0.87


def test_mitre_attack_ids():
    bundle = build_enterprise_stix_bundle(
        email_text="Test",
        results={"risk_score": 95, "severity": "CRITICAL"},
    )
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    labels = indicator.get("labels", [])
    assert "T1557" in labels  # AitM
    assert "T1566" in labels


def test_minimal_input():
    bundle = build_enterprise_stix_bundle(
        email_text="",
        results={},
    )
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 3


def test_serializable():
    bundle = build_enterprise_stix_bundle(
        email_text="JSON test content",
        results={"risk_score": 50, "severity": "LOW"},
    )
    json_str = json.dumps(bundle, indent=2)
    parsed = json.loads(json_str)
    assert parsed["type"] == "bundle"
