"""Tests for the unified AI provider module."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.providers import get_available_provider, get_completion, get_chat_completion
from src.env import ENV


class TestProviderDiscovery:
    def test_no_keys_returns_none(self):
        assert get_available_provider() == "none"

    def test_groq_detected(self):
        old = ENV.GROQ_API_KEY
        ENV.GROQ_API_KEY = "gsk_test"
        try:
            assert get_available_provider() == "groq"
        finally:
            ENV.GROQ_API_KEY = old

    def test_openrouter_detected(self):
        old_groq = ENV.GROQ_API_KEY
        old_or = ENV.OPENROUTER_API_KEY
        ENV.GROQ_API_KEY = ""
        ENV.OPENROUTER_API_KEY = "sk-or-test"
        try:
            assert get_available_provider() == "openrouter"
        finally:
            ENV.GROQ_API_KEY = old_groq
            ENV.OPENROUTER_API_KEY = old_or


class TestGetCompletion:
    def test_no_keys_returns_error_message(self):
        result = get_completion("system", "user hello")
        assert result.startswith("⚠")

    def test_chat_completion_no_keys(self):
        msgs = [{"role": "user", "content": "hello"}]
        result = get_chat_completion(msgs, system_prompt="test")
        assert result.startswith("⚠")


class TestEnvKeys:
    def test_groq_key_in_env(self):
        assert hasattr(ENV, "GROQ_API_KEY")

    def test_openrouter_key_in_env(self):
        assert hasattr(ENV, "OPENROUTER_API_KEY")

    def test_virustotal_key_in_env(self):
        assert hasattr(ENV, "VIRUSTOTAL_API_KEY")
