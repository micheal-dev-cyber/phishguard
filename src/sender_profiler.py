"""
PhishGuard AI — Behavioral Sender Profiling & Anomaly Detection Graph

Monitors sender communication patterns, builds historical baselines per sender,
and detects anomalous behavioural deviations (tone shift, urgency spike,
salutation change, financial request from a never-financial sender).

Architecture:
  ┌──────────────┐     email parsed      ┌──────────────────┐
  │  Incoming     │ ──────────────────→  │  Sender Profiler  │
  │  Email        │                      │  (this module)    │
  └──────────────┘                      └────────┬─────────┘
                                                  │ update profile
                                                  ↓
                                          ┌──────────────────┐
                                          │  sender_profiles  │
                                          │  DB table         │
                                          └──────────────────┘
                                                  │
                                          ┌──────────────────┐
                                          │  Communication    │
                                          │  Log (90d window) │
                                          └──────────────────┘
                                                  │
                                          ┌──────────────────┐
                                          │  Deviation        │
                                          │  Analysis         │
                                          └──────────────────┘
"""

import hashlib
import json
import logging
import re
import statistics
from datetime import datetime
from typing import Optional

from src.db import get_connection

logger = logging.getLogger("sender-profiler")

# ── Pattern constants ──────────────────────────────────────────────────────

SALUTATION_PATTERNS = [
    r"\b(dear\s+\w+)\b",
    r"\b(hi\s+\w+)\b",
    r"\b(hello\s+\w+)\b",
    r"\b(greetings)\b",
    r"\b(to\s+whom\s+it\s+may\s+concern)\b",
    r"\b(dear\s+(sir|madam|customer|user|friend|valued))\b",
    r"\b(hey\s+\w+)\b",
    r"\b(good\s+(morning|afternoon|evening))\b",
]

FINANCIAL_KEYWORDS = [
    "invoice", "payment", "wire transfer", "bank account", "ach",
    "direct deposit", "billing", "overdue", "remittance", "payroll",
    "refund", "transaction", "credit card", "purchase order", "po#",
    "money", "dollars", "usd", "eur", "check", "cheque",
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "as soon as possible", "asap", "right now",
    "deadline", "expires", "last chance", "final notice", "time sensitive",
    "critical", "emergency", "priority", "respond now", "today",
]

TONE_CATEGORIES = {
    "formal": [r"\b(regarding|furthermore|nevertheless|accordingly)\b",
               r"\b(hereby|herewith|thereafter|herein)\b"],
    "informal": [r"\b(hey|yeah|gonna|wanna|cool|awesome)\b",
                 r"\b(btw|fyi|imo|tbh|lol)\b"],
    "urgent": [r"\b(urgent|immediately|asap|deadline|critical)\b"],
    "threatening": [r"\b(legal action|suspended|terminated|penalty|sue)\b",
                    r"\b(lawyer|court|lawsuit|police|fine)\b"],
    "friendly": [r"\b(thanks|appreciate|grateful|welcome|pleasure)\b",
                 r"\b(happy|glad|delighted|excited)\b"],
}


class SenderProfile:
    """Container for a sender's behavioural snapshot."""

    def __init__(self, row: Optional[tuple] = None):
        if row:
            (self.id, self.sender_email, self.sender_domain, self.display_name,
             self.first_contact, self.last_contact, self.total_emails,
             self.total_attachments, self.avg_response_hours,
             self.common_salutations, self.common_subjects,
             self.common_tone_tags, self.avg_urgency_score,
             self.avg_risk_score, self.trust_score,
             self.linguistic_baseline_hash, self.profile_version,
             self.created_at) = row[:18]
            self.common_salutations = json.loads(self.common_salutations or "[]")
            self.common_subjects = json.loads(self.common_subjects or "[]")
            self.common_tone_tags = json.loads(self.common_tone_tags or "[]")
        else:
            self.sender_email = ""
            self.sender_domain = ""
            self.display_name = ""
            self.total_emails = 0
            self.total_attachments = 0
            self.avg_response_hours = 0.0
            self.common_salutations = []
            self.common_subjects = []
            self.common_tone_tags = []
            self.avg_urgency_score = 0.0
            self.avg_risk_score = 0.0
            self.trust_score = 50.0
            self.linguistic_baseline_hash = None
            self.profile_version = 1


# ── Feature extraction ─────────────────────────────────────────────────────

def extract_salutation(text: str) -> Optional[str]:
    """Extract the first salutation/greeting from email text."""
    for pat in SALUTATION_PATTERNS:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            return match.group(0).strip()
    return None


def extract_tone_tags(text: str) -> list:
    """Classify the tone of an email into one or more categories."""
    text_lower = text.lower()
    tags = []
    for category, patterns in TONE_CATEGORIES.items():
        for pat in patterns:
            if re.search(pat, text_lower):
                tags.append(category)
                break
    return tags or ["neutral"]


def compute_urgency_score(text: str) -> float:
    """Compute a 0-100 urgency score based on keyword density."""
    text_lower = text.lower()
    word_count = len(text_lower.split()) or 1
    hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    raw = (hits / word_count) * 1000
    return min(round(raw, 1), 100)


def has_financial_request(text: str) -> bool:
    """Detect if the email contains financial action language."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in FINANCIAL_KEYWORDS)


def compute_response_time_hours(
    current_timestamp: datetime,
    last_contact: Optional[str],
) -> Optional[float]:
    """Compute hours since last contact (approximate response time)."""
    if not last_contact:
        return None
    try:
        last = datetime.fromisoformat(last_contact)
        delta = (current_timestamp - last).total_seconds() / 3600
        return round(min(delta, 8760), 1)
    except (ValueError, TypeError):
        return None


# ── Profile CRUD ───────────────────────────────────────────────────────────

def get_or_create_profile(sender_email: str, display_name: str = "") -> SenderProfile:
    """Get existing profile or create a skeleton."""
    domain = sender_email.split("@")[-1] if "@" in sender_email else "unknown"
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM sender_profiles WHERE sender_email = ?", (sender_email,))
        row = c.fetchone()
        if row:
            return SenderProfile(row)

        c.execute("""
            INSERT INTO sender_profiles
                (sender_email, sender_domain, display_name, first_contact, last_contact,
                 trust_score, created_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'), 50.0, datetime('now'))
        """, (sender_email, domain, display_name))
        conn.commit()

        c.execute("SELECT * FROM sender_profiles WHERE sender_email = ?", (sender_email,))
        return SenderProfile(c.fetchone())
    finally:
        conn.close()


def _update_profile_rolling(conn, sender_email: str, updates: dict):
    """Apply rolling-window aggregations to a profile."""
    _ALLOWED_COLS = {"total_emails", "total_risk", "avg_risk", "last_risk",
                     "max_risk", "high_risk_count", "categories", "last_body",
                     "last_subject", "last_display_name", "last_contact"}
    sql_parts = []
    params = []

    for key, value in updates.items():
        if key not in _ALLOWED_COLS:
            logger.warning("Ignoring unknown profile column: %s", key)
            continue
        sql_parts.append(f"{key} = ?")
        params.append(value)

    if sql_parts:
        sql_parts.append("last_contact = datetime('now')")
        sql_parts.append("profile_version = profile_version + 1")
        params.append(sender_email)
        conn.execute(
            f"UPDATE sender_profiles SET {', '.join(sql_parts)} WHERE sender_email = ?",
            params,
        )


def update_profile_after_scan(
    sender_email: str,
    display_name: str,
    subject: str,
    body: str,
    risk_score: int,
    has_attachment: bool = False,
    timestamp: Optional[str] = None,
) -> dict:
    """Full profile update pipeline after an email is analysed."""
    now = datetime.fromisoformat(timestamp) if timestamp else datetime.now()
    profile = get_or_create_profile(sender_email, display_name)

    salutation = extract_salutation(body)
    tone_tags = extract_tone_tags(body)
    urgency_score = compute_urgency_score(body)

    last_contact = profile.last_contact
    response_time = compute_response_time_hours(now, last_contact)

    body_hash = hashlib.sha384(body.encode("utf-8")).hexdigest()
    word_count = len(body.split())

    conn = get_connection()
    c = conn.cursor()
    try:
        # Insert communication log entry
        c.execute("""
            INSERT INTO sender_communications
                (sender_email, subject, body_hash, word_count, urgency_score,
                 risk_score, has_attachment, response_time_hours, salutation,
                 tone_tags, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sender_email,
            subject[:200],
            body_hash,
            word_count,
            urgency_score,
            risk_score,
            1 if has_attachment else 0,
            response_time,
            salutation or "",
            json.dumps(tone_tags),
            now.isoformat(),
        ))

        # Compute new rolling averages from the 90-day window
        c.execute("""
            SELECT urgency_score, risk_score, response_time_hours, salutation, tone_tags
            FROM sender_communications
            WHERE sender_email = ? AND timestamp >= datetime('now', '-90 days')
        """, (sender_email,))
        comms = c.fetchall()

        # Rolling aggregations
        urgency_scores = [r[0] for r in comms if r[0] is not None]
        risk_scores = [r[1] for r in comms if r[1] is not None]
        response_times = [r[2] for r in comms if r[2] is not None]
        salutations = list(set(r[3] for r in comms if r[3]))
        all_tone_tags = []
        for r in comms:
            try:
                all_tone_tags.extend(json.loads(r[4] or "[]"))
            except (json.JSONDecodeError, TypeError):
                pass
        tone_tag_freq = {}
        for t in all_tone_tags:
            tone_tag_freq[t] = tone_tag_freq.get(t, 0) + 1
        top_tones = sorted(tone_tag_freq, key=tone_tag_freq.get, reverse=True)[:3]

        new_total_emails = len(comms)
        avg_urgency = round(statistics.mean(urgency_scores), 1) if urgency_scores else 0.0
        avg_risk = round(statistics.mean(risk_scores), 1) if risk_scores else 0.0
        avg_response = round(statistics.mean(response_times), 1) if response_times else None

        # Linguistic baseline (last 5 emails' body hashes for fingerprint)
        c.execute("""
            SELECT body_hash FROM sender_communications
            WHERE sender_email = ? ORDER BY id DESC LIMIT 5
        """, (sender_email,))
        recent_hashes = [r[0] for r in c.fetchall() if r[0]]
        ling_baseline = hashlib.sha384(
            "".join(recent_hashes).encode("utf-8")
        ).hexdigest() if recent_hashes else None

        c.execute("""
            UPDATE sender_profiles SET
                display_name = ?,
                total_emails = ?,
                total_attachments = total_attachments + ?,
                avg_response_hours = ?,
                common_salutations = ?,
                common_tone_tags = ?,
                avg_urgency_score = ?,
                avg_risk_score = ?,
                linguistic_baseline_hash = ?,
                last_contact = datetime('now'),
                profile_version = profile_version + 1,
                trust_score = CAST(
                    MAX(0, MIN(100,
                        50
                        - (? * 0.2)
                        + (? * 0.3)
                    )) AS REAL
                )
            WHERE sender_email = ?
        """, (
            display_name or profile.display_name,
            new_total_emails,
            1 if has_attachment else 0,
            avg_response or profile.avg_response_hours,
            json.dumps(salutations[:10]),
            json.dumps(top_tones),
            avg_urgency,
            avg_risk,
            ling_baseline or profile.linguistic_baseline_hash,
            avg_risk,
            50 - avg_risk * 0.2,
            sender_email,
        ))
        conn.commit()

        return {
            "profile_updated": True,
            "sender": sender_email,
            "total_emails": new_total_emails,
            "avg_urgency": avg_urgency,
            "avg_risk": avg_risk,
            "top_tones": top_tones,
            "ling_baseline": ling_baseline[:16] if ling_baseline else None,
        }
    except Exception as exc:
        logger.error("Profile update failed for %s: %s", sender_email, exc)
        return {"profile_updated": False, "error": str(exc)}
    finally:
        conn.close()


# ── Anomaly detection ──────────────────────────────────────────────────────

def detect_behavioural_anomaly(
    sender_email: str,
    subject: str,
    body: str,
    risk_score: int,
    has_attachment: bool = False,
    timestamp: Optional[str] = None,
) -> dict:
    """Compare current email against the sender's historical baseline.

    Returns a scored anomaly report with specific flags.
    """
    profile = get_or_create_profile(sender_email)
    if profile.total_emails < 3:
        return {
            "anomaly_detected": False,
            "reason": "insufficient_baseline",
            "total_emails": profile.total_emails,
            "anomaly_score": 0,
            "flags": [],
        }

    anomalies = []
    anomaly_score = 0

    # 1. Salutation deviation
    current_salutation = extract_salutation(body)
    if current_salutation and profile.common_salutations:
        expected_salutations = profile.common_salutations
        if not any(s.lower() in current_salutation.lower() for s in expected_salutations):
            anomalies.append(f"salutation_deviation:expected={expected_salutations},got={current_salutation}")
            anomaly_score += 15

    # 2. Tone deviation
    current_tone = extract_tone_tags(body)
    if profile.common_tone_tags and current_tone:
        expected_tones = set(profile.common_tone_tags)
        current_tones = set(current_tone)
        overlap = expected_tones & current_tones
        if not overlap:
            anomalies.append(f"tone_deviation:expected={profile.common_tone_tags},got={current_tone}")
            anomaly_score += 20

    # 3. Urgency spike
    current_urgency = compute_urgency_score(body)
    if profile.avg_urgency_score > 0:
        urgency_ratio = current_urgency / max(profile.avg_urgency_score, 0.1)
        if urgency_ratio > 3.0:
            anomalies.append(f"urgency_spike:{current_urgency:.1f}vs_baseline_{profile.avg_urgency_score:.1f}")
            anomaly_score += 20
        elif urgency_ratio > 2.0:
            anomalies.append(f"urgency_elevated:{current_urgency:.1f}vs_baseline_{profile.avg_urgency_score:.1f}")
            anomaly_score += 10

    # 4. Financial request anomaly
    has_finance = has_financial_request(body)
    if has_finance:
        # Check if this sender has EVER made financial requests
        conn = get_connection()
        c = conn.cursor()
        try:
            c.execute("""
                SELECT COUNT(*) FROM sender_communications
                WHERE sender_email = ? AND id != (SELECT MAX(id) FROM sender_communications WHERE sender_email = ?)
                AND (subject LIKE '%invoice%' OR subject LIKE '%payment%'
                     OR subject LIKE '%wire%' OR subject LIKE '%bank%')
            """, (sender_email, sender_email))
            prev_financial = c.fetchone()[0]
            if prev_financial == 0:
                anomalies.append("first_time_financial_request")
                anomaly_score += 25
        finally:
            conn.close()

    # 5. Risk score spike
    if profile.avg_risk_score > 0:
        risk_ratio = risk_score / max(profile.avg_risk_score, 1)
        if risk_ratio > 2.5 and risk_score >= 50:
            anomalies.append(f"risk_spike:{risk_score}vs_baseline_{profile.avg_risk_score:.0f}")
            anomaly_score += 15

    # 6. Attachment anomaly
    if has_attachment and profile.total_attachments == 0:
        anomalies.append("first_time_attachment")
        anomaly_score += 10

    # 7. Response time anomaly (too fast or too slow)
    now = datetime.fromisoformat(timestamp) if timestamp else datetime.now()
    response_time = compute_response_time_hours(now, profile.last_contact)
    if response_time is not None and profile.avg_response_hours:
        if response_time < profile.avg_response_hours * 0.1:
            anomalies.append(f"abnormally_fast_reply:{response_time:.1f}h_vs_avg_{profile.avg_response_hours:.1f}h")
            anomaly_score += 10

    severity = (
        "CRITICAL" if anomaly_score >= 50 else
        "HIGH" if anomaly_score >= 30 else
        "MEDIUM" if anomaly_score >= 15 else
        "LOW"
    )

    return {
        "anomaly_detected": anomaly_score >= 15,
        "sender": sender_email,
        "anomaly_score": min(anomaly_score, 100),
        "severity": severity,
        "flags": anomalies,
        "total_emails_baseline": profile.total_emails,
        "current_urgency": current_urgency,
        "baseline_urgency": profile.avg_urgency_score,
        "current_tone": current_tone,
        "baseline_tone": profile.common_tone_tags,
        "current_salutation": current_salutation,
        "baseline_salutations": profile.common_salutations,
    }


def get_sender_history(sender_email: str, limit: int = 20) -> list:
    """Return communication history for a sender."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT timestamp, subject, word_count, urgency_score, risk_score,
                   has_attachment, response_time_hours, salutation, tone_tags
            FROM sender_communications
            WHERE sender_email = ?
            ORDER BY id DESC LIMIT ?
        """, (sender_email, limit))
        return c.fetchall()
    finally:
        conn.close()


def get_all_profiles_summary(limit: int = 50) -> list:
    """Return all sender profiles with trust scores."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT sender_email, sender_domain, total_emails, avg_urgency_score,
                   avg_risk_score, trust_score, last_contact, profile_version
            FROM sender_profiles
            ORDER BY total_emails DESC LIMIT ?
        """, (limit,))
        return c.fetchall()
    finally:
        conn.close()
