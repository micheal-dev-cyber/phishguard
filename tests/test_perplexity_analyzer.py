"""Tests for the AI-Generated Text Detector (Perplexity Analyzer)."""

import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.perplexity_analyzer import compute_perplexity_score


class TestPerplexityAnalyzer:
    def test_empty_text(self):
        result = compute_perplexity_score("")
        assert result["ai_probability"] == 0

    def test_short_text(self):
        result = compute_perplexity_score("Hi")
        assert result["ai_probability"] == 0

    def test_human_like_text_scores_low(self):
        text = (
            "Hey John, just got your email. The meeting is at 3pm in room 4B. "
            "I'll bring the quarterly reports. See you there. Oh, and can you "
            "remind Sarah about the presentation? She might have forgotten."
        )
        result = compute_perplexity_score(text)
        assert result["ai_probability"] < 50

    def test_ai_like_text_scores_higher(self):
        text = (
            "First, it is important to note that the proliferation of sophisticated "
            "phishing attacks has necessitated a comprehensive approach to cybersecurity. "
            "Furthermore, organisations must implement multi-factor authentication, "
            "conduct regular security awareness training, and deploy advanced threat "
            "detection systems. In addition, it is crucial to understand that no single "
            "solution provides complete protection. Therefore, a defence-in-depth "
            "strategy is recommended. Moreover, keeping software updated and patching "
            "vulnerabilities promptly cannot be overstated. In summary, cybersecurity "
            "is an ongoing process that requires constant vigilance and adaptation."
        )
        result = compute_perplexity_score(text)
        assert result["ai_probability"] >= 40

    def test_returns_expected_keys(self):
        result = compute_perplexity_score("This is a test sentence for analysis purposes.")
        assert "ai_probability" in result
        assert "burstiness" in result
        assert "lexical_diversity" in result
        assert "hedging_count" in result
        assert "transition_count" in result
        assert "signals" in result
        assert "summary" in result

    def test_signals_non_empty_for_formal_text(self):
        text = (
            "First, we need to consider the implications. Furthermore, "
            "it is worth noting that the data suggests otherwise. In addition, "
            "it is crucial to understand the context. Finally, we must conclude that "
            "further research is needed."
        )
        result = compute_perplexity_score(text)
        assert len(result["signals"]) > 0
