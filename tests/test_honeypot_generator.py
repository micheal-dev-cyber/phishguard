"""Tests for the Reverse Honeypot Generator."""

import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.honeypot_generator import generate_honeypot


class TestHoneypotGenerator:
    def test_returns_required_keys(self):
        result = generate_honeypot("Your account has been suspended. Click http://evil.com")
        assert "subject" in result
        assert "body" in result
        assert "sender_name" in result
        assert "sender_title" in result
        assert "sender_email" in result
        assert "payload_type" in result
        assert "payload_data" in result

    def test_body_is_nonempty(self):
        result = generate_honeypot("Urgent: verify your credentials now")
        assert len(result["body"]) > 20

    def test_payload_type_is_valid(self):
        result = generate_honeypot("Click here to reset password")
        assert result["payload_type"] in (
            "credentials", "credit_card", "vpn_token", "internal_note"
        )

    def test_sender_email_contains_dmz(self):
        result = generate_honeypot("Your invoice is attached")
        assert "phishguard-dmz.com" in result["sender_email"]

    def test_different_inputs_can_yield_different_types(self):
        types = set()
        for _ in range(10):
            result = generate_honeypot(f"Test email {_}")
            types.add(result["payload_type"])
        # At least 2 different payload types across 10 calls
        assert len(types) >= 2

    def test_payload_data_is_json_serializable(self):
        import json
        result = generate_honeypot("Your account is limited")
        data = result["payload_data"]
        if isinstance(data, str):
            parsed = json.loads(data)
            assert isinstance(parsed, dict)
