"""Tests for the Phishing DNA / Fuzzy Hashing module."""

import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.phishing_dna import (
    compute_threat_signature,
    compare_signatures,
    match_known_campaign,
    flagged_as_known_phishing,
)


class TestThreatSignature:
    def test_normalize_collapses_whitespace(self):
        sig = compute_threat_signature("Hello   World!!!\n\nClick here.")
        words = sig["words"]
        assert "hello" in words and "world" in words and "click" in words and "here" in words

    def test_trigrams_generated(self):
        sig = compute_threat_signature("abc")
        assert len(sig["trigrams"]) >= 1

    def test_sha256_digest(self):
        sig = compute_threat_signature("test email content")
        assert len(sig["sha256"]) == 64

    def test_preview_truncated(self):
        long = "x" * 300
        sig = compute_threat_signature(long)
        assert len(sig["preview"]) == 120


class TestCompareSignatures:
    def test_identical_texts_score_high(self):
        text = "Your account has been compromised. Click here to reset."
        s1 = compute_threat_signature(text)
        s2 = compute_threat_signature(text)
        score = compare_signatures(s1, s2)
        assert score["composite"] > 0.99

    def test_different_texts_score_low(self):
        s1 = compute_threat_signature("account compromised click here")
        s2 = compute_threat_signature("meeting tomorrow at 3pm")
        score = compare_signatures(s1, s2)
        assert score["composite"] < 0.5

    def test_similar_campaign_texts(self):
        s1 = compute_threat_signature(
            "Your account has been compromised. Click here to reset your password."
        )
        s2 = compute_threat_signature(
            "Your account has been compromised! Click here to reset password immediately."
        )
        score = compare_signatures(s1, s2)
        assert score["composite"] > 0.5


class TestMatchKnownCampaign:
    def test_no_signatures_returns_none(self):
        assert match_known_campaign("test", []) is None

    def test_matches_above_threshold(self):
        sig = compute_threat_signature("Urgent: reset your password now")
        match = match_known_campaign("Urgent: reset your password now", [sig])
        assert match is not None
        assert match["similarity"] >= 0.85


class TestFlaggedAsKnownPhishing:
    def test_learns_new_signature(self):
        store = {}
        flagged, match = flagged_as_known_phishing("test email", store)
        assert not flagged
        assert match is None
        assert len(store["phishing_signatures"]) == 1

    def test_detects_known_campaign(self):
        store = {}
        flagged_as_known_phishing(
            "Your PayPal account is limited. Click here to verify.", store
        )
        flagged, match = flagged_as_known_phishing(
            "Your PayPal account is limited. Click here to verify now.", store
        )
        assert flagged
        assert match is not None
        assert match["similarity"] >= 0.85
