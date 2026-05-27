"""
PhishGuard AI — Global Threat Intelligence Sharing (STIX 2.1 / Collective Defense)

Serialises confirmed phishing attacks into STIX 2.1 CTI objects, fingerprints
linguistic body hashes (SHA-384) for exact-match immunisation, and broadcasts
into a shared database state to immunise all connected enterprise nodes.

Architecture:
  ┌──────────────┐     STIX 2.1 JSON     ┌──────────────────┐
  │  Detector    │ ──────────────────→   │  Intel Serialiser │
  │  (HIGH/CRIT) │                       │  (this module)    │
  └──────────────┘                       └────────┬─────────┘
                                                  │ write + broadcast
                                                  ↓
                                          ┌──────────────────┐
                                          │  threat_intel     │
                                          │  DB table         │
                                          └──────────────────┘
                                                  │
                                           broadcast to all
                                           connected tenants
                                                  ↓
                                          ┌──────────────────┐
                                          │  Each node        │
                                          │  immunises via    │
                                          │  linguistic hash  │
                                          └──────────────────┘
"""

import json
import hashlib
import hmac
import uuid
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

logger = logging.getLogger("threat-intel")

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "phishguard.db"

# ── STIX 2.1 Pattern constants ─────────────────────────────────────────────

STIX_PATTERN_TYPES = {
    "linguistic_hash": "x-phishguard-linguistic-hash",
    "sender_domain": "domain-name:value",
    "url_pattern": "url:value",
    "subject_pattern": "x-phishguard-subject-fingerprint",
    "attachment_hash": "file:hashes.SHA-256",
}

PHISHGUARD_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c4")


def _fingerprint(text: str) -> str:
    """Cryptographic body fingerprint via SHA-384 (NIST-approved)."""
    return hashlib.sha384(text.encode("utf-8")).hexdigest()


def _hmac_tag(key: bytes, data: str) -> str:
    """Authenticate an intel object with HMAC-SHA256."""
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def _stix_id(prefix: str, seed: str) -> str:
    """Deterministic UUIDv5 for deduplication."""
    return f"{prefix}--{uuid.uuid5(PHISHGUARD_NAMESPACE, seed)}"


# ── STIX 2.1 object builders ───────────────────────────────────────────────

def build_indicator(
    linguistic_fingerprint: str,
    pattern: str,
    pattern_type: str = "x-phishguard-linguistic-hash",
    severity: str = "HIGH",
    risk_score: int = 75,
    sender_domain: Optional[str] = None,
    subject: Optional[str] = None,
    mitre_attack_ids: Optional[list] = None,
    hmac_key: Optional[bytes] = None,
) -> dict:
    seed = f"{linguistic_fingerprint}:{severity}:{sender_domain or 'unknown'}"
    sid = _stix_id("indicator", seed)

    labels = ["phishing", "phishguard"]
    if mitre_attack_ids:
        labels.extend(mitre_attack_ids)

    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": sid,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "name": f"PhishGuard AI — {severity} severity phishing pattern ({linguistic_fingerprint[:12]}...)",
        "description": (
            f"Automatically detected phishing email. "
            f"Linguistic fingerprint: {linguistic_fingerprint[:24]}... | "
            f"Domain: {sender_domain or 'N/A'} | "
            f"Score: {risk_score}/100"
        ),
        "pattern": pattern,
        "pattern_type": pattern_type,
        "pattern_version": "2.1",
        "valid_from": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "labels": labels,
        "confidence": min(risk_score, 100),
        "indicator_types": ["malicious-activity"],
        "custom_properties": {
            "x_phishguard_linguistic_hash": linguistic_fingerprint,
            "x_phishguard_risk_score": risk_score,
            "x_phishguard_sender_domain": sender_domain or "",
            "x_phishguard_subject": subject or "",
            "x_phishguard_version": "3.0.0",
        },
    }

    if hmac_key:
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        obj["x_phishguard_hmac"] = _hmac_tag(hmac_key, canonical)

    return obj


def build_observed_data(
    email_text: str,
    urls: list,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    attachment_hashes: Optional[list] = None,
) -> dict:
    ling_hash = _fingerprint(email_text)
    seed = f"observed-{ling_hash}"
    sid = _stix_id("observed-data", seed)

    obs = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": sid,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "first_observed": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_observed": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "email-message",
                "is_multipart": False,
                "subject": subject or "",
                "body": email_text[:500],
                "body_multipart": [],
            }
        },
        "custom_properties": {
            "x_phishguard_linguistic_hash": ling_hash,
            "x_phishguard_urls": json.dumps(urls[:20]),
            "x_phishguard_attachment_hashes": json.dumps(attachment_hashes or []),
        },
    }

    if sender:
        obs["objects"]["1"] = {
            "type": "email-addr",
            "value": sender,
            "custom_properties": {"x_phishguard_role": "sender"},
        }

    return obs


def build_relationship(indicator_id: str, observed_data_id: str) -> dict:
    seed = f"rel-{indicator_id}-{observed_data_id}"
    sid = _stix_id("relationship", seed)
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": sid,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "relationship_type": "based-on",
        "source_ref": indicator_id,
        "target_ref": observed_data_id,
    }


def build_stix_bundle(objects: list) -> dict:
    return {
        "type": "bundle",
        "spec_version": "2.1",
        "id": _stix_id("bundle", json.dumps([o["id"] for o in objects], sort_keys=True)),
        "objects": objects,
    }


# ── Pattern builders ───────────────────────────────────────────────────────

def build_linguistic_pattern(fingerprint: str) -> str:
    return f"[{STIX_PATTERN_TYPES['linguistic_hash']} = '{fingerprint}']"


def build_url_pattern(url: str) -> str:
    escaped = url.replace("'", "\\'").replace("\\", "\\\\")
    return f"[{STIX_PATTERN_TYPES['url_pattern']} = '{escaped}']"


def build_domain_pattern(domain: str) -> str:
    return f"[{STIX_PATTERN_TYPES['sender_domain']} = '{domain}']"


# ── Linguistic baseline hash (normalised) ──────────────────────────────────

def compute_linguistic_baseline(email_text: str) -> str:
    normalised = email_text.lower().strip()
    normalised = " ".join(normalised.split())
    return _fingerprint(normalised)


# ── Collective immunity check ──────────────────────────────────────────────

def check_collective_immunity(email_text: str) -> dict:
    """Check if email text matches any known STIX indicator by linguistic hash."""
    ling_hash = compute_linguistic_baseline(email_text)
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    try:
        c.execute(
            "SELECT stix_id, severity, risk_score, sender_domain FROM threat_intel "
            "WHERE linguistic_hash = ? AND is_active = 1",
            (ling_hash,),
        )
        row = c.fetchone()
        if row:
            return {
                "immune": True,
                "stix_id": row[0],
                "severity": row[1],
                "risk_score": row[2],
                "sender_domain": row[3],
                "match_type": "exact_linguistic_hash",
            }
        return {"immune": False}
    finally:
        conn.close()


def get_all_active_indicators(limit: int = 100) -> list:
    """Retrieve all active STIX indicators for downstream immunisation."""
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    try:
        c.execute(
            "SELECT stix_id, indicator_type, pattern, linguistic_hash, severity, "
            "risk_score, sender_domain, last_seen FROM threat_intel "
            "WHERE is_active = 1 ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        )
        return c.fetchall()
    finally:
        conn.close()


# ── Broadcast ──────────────────────────────────────────────────────────────

def broadcast_intel(
    stix_bundle: dict,
    linguistic_hash: str,
    severity: str,
    target_tenants: Optional[list] = None,
) -> dict:
    """Persist and broadcast a STIX bundle to the collective database.

    Every connected enterprise node reads from the same threat_intel table,
    providing real-time immunisation coverage.
    """
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    bundle_id = stix_bundle["id"]
    payload = json.dumps(stix_bundle)
    created = 0
    errors = []

    try:
        for obj in stix_bundle["objects"]:
            if obj["type"] != "indicator":
                continue

            pattern = obj.get("pattern", "")
            indicator_type = obj.get("pattern_type", "x-phishguard-linguistic-hash")
            sender_domain = obj.get("custom_properties", {}).get("x_phishguard_sender_domain", "")
            risk_score = obj.get("custom_properties", {}).get("x_phishguard_risk_score", 75)

            try:
                c.execute("""
                    INSERT OR IGNORE INTO threat_intel
                        (id, stix_id, indicator_type, pattern, linguistic_hash,
                         sender_domain, severity, risk_score, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                """, (
                    obj["id"],
                    obj["id"],
                    indicator_type,
                    pattern,
                    linguistic_hash,
                    sender_domain,
                    severity,
                    risk_score,
                ))
                if c.rowcount > 0:
                    created += 1
                else:
                    c.execute(
                        "UPDATE threat_intel SET last_seen = datetime('now'), "
                        "broadcast_count = broadcast_count + 1 WHERE stix_id = ?",
                        (obj["id"],),
                    )
            except Exception as exc:
                errors.append(str(exc))
                logger.error("Error inserting STIX indicator %s: %s", obj["id"], exc)

        tc = json.dumps(target_tenants or ["*"])
        c.execute("""
            INSERT INTO intel_broadcasts (stix_id, broadcast_type, target_tenants,
                                          payload_size, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            bundle_id,
            "collective_immunisation",
            tc,
            len(payload.encode("utf-8")),
            "completed" if not errors else "partial",
            "; ".join(errors[:5]) if errors else "",
        ))
        conn.commit()

        logger.info(
            "Broadcast complete — %d new indicators, bundle size %d bytes",
            created, len(payload.encode("utf-8")),
        )
        return {"created": created, "errors": errors, "bundle_id": bundle_id}

    except Exception as exc:
        logger.error("Broadcast failed: %s", exc)
        return {"created": 0, "errors": [str(exc)], "bundle_id": bundle_id}
    finally:
        conn.close()


# ── High-level pipeline ────────────────────────────────────────────────────

def immunise_from_analysis(
    email_text: str,
    results: dict,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    hmac_key: Optional[bytes] = None,
) -> dict:
    """Full pipeline: compute fingerprint → build STIX bundle → broadcast."""
    if results.get("severity") not in ("HIGH", "CRITICAL"):
        return {"immunised": False, "reason": "severity_too_low"}

    ling_hash = compute_linguistic_baseline(email_text)
    domains = set()
    for u in results.get("suspicious_urls", []):
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        parts = url.split("/")
        if len(parts) >= 3:
            domains.add(parts[2].lower())

    sender_domain = sender.split("@")[-1] if sender and "@" in sender else None

    pattern = build_linguistic_pattern(ling_hash)
    indicator = build_indicator(
        ling_hash,
        pattern,
        severity=results["severity"],
        risk_score=results["risk_score"],
        sender_domain=sender_domain,
        subject=subject,
        hmac_key=hmac_key,
    )

    observed = build_observed_data(
        email_text[:2000],
        [u.get("url", "") if isinstance(u, dict) else u for u in results.get("suspicious_urls", [])],
        sender=sender,
        subject=subject,
    )

    relationship = build_relationship(indicator["id"], observed["id"])

    bundle = build_stix_bundle([indicator, observed, relationship])

    broadcast_result = broadcast_intel(bundle, ling_hash, results["severity"])

    return {
        "immunised": True,
        "linguistic_hash": ling_hash,
        "bundle_id": bundle["id"],
        "indicators_created": broadcast_result["created"],
    }
