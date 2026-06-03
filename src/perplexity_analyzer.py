"""AI-Generated Text Detector — Perplexity analysis via linguistic patterns.

Detects hallmarks of LLM-written text (ChatGPT, Claude, etc.) using
surface-level features: burstiness, lexical diversity, hedging, formulaic
transitions, and repetitive sentence structures.  No external API required.
"""

from __future__ import annotations

import math
import re

# ── Pattern sets ─────────────────────────────────────────────────────────

# Hedging / cautious phrases common in LLM output
HEDGING_PATTERNS = [
    r"\bi(t['’]?s\s+)?important\s+to\s+note\b",
    r"\bi(t['’]?s\s+)?worth\s+noting\b",
    r"\bi(t['’]?s\s+)?crucial\s+to\s+understand\b",
    r"\bin\s+the\s+realm\s+of\b",
    r"\bin\s+the\s+context\s+of\b",
    r"\bwhen\s+it\s+comes\s+to\b",
    r"\b(as\s+)?a\s+notable\s+example\b",
    r"\bas\s+of\s+(my\s+)?last\s+(knowledge\s+)?update\b",
    r"\bi\s+(don['’]t\s+)?have\s+access\s+to\b",
    r"\bplease\s+note\s+that\b",
    r"\bit['’]s\s+essential\s+to\b",
    r"\bkeep\s+in\s+mind\b",
    r"\bthat\s+being\s+said\b",
    r"\bin\s+summary\b",
    r"\bto\s+summarize\b",
    r"\bin\s+conclusion\b",
    r"\bfurthermore\b",
    r"\bmoreover\b",
    r"\bnevertheless\b",
    r"\bhowever\b",
    r"\btherefore\b",
    r"\badditionally\b",
    r"\bconsequently\b",
]

# Formulaic transition phrases over-represented in LLM text
TRANSITION_PATTERNS = [
    r"\bfirst(ly)?\b",
    r"\bsecond(ly)?\b",
    r"\bthird(ly)?\b",
    r"\bfinally\b",
    r"\bin\s+addition\b",
    r"\bon\s+the\s+(one\s+)?other\s+hand\b",
    r"\bfor\s+example\b",
    r"\bfor\s+instance\b",
    r"\bsuch\s+as\b",
    r"\bin\s+other\s+words\b",
    r"\bas\s+a\s+result\b",
    r"\bdue\s+to\b",
    r"\bin\s+order\s+to\b",
    r"\bin\s+particular\b",
    r"\bnotably\b",
    r"\bspecifically\b",
]

# List-like structures (numbered steps, bullet points) overused by LLMs
LIST_PATTERN = re.compile(
    r"(?:\d+\.\s+[A-Z]|[-\*]\s+[A-Z])", re.MULTILINE
)

# Overly polite / canned phrases
POLITE_FILLER = [
    r"\bi['’]?d\s+be\s+happy\s+to\b",
    r"\bfeel\s+free\s+to\b",
    r"\bdon['’]?t\s+hesitate\s+to\b",
    r"\bplease\s+do\s+not\s+hesitate\b",
    r"\bi['’]?m\s+here\s+to\s+help\b",
]


# ── Scoring ──────────────────────────────────────────────────────────────


def compute_perplexity_score(text: str) -> dict:
    """Analyse *text* for AI-generation signals.

    Returns a dict with:
      - ai_probability:  0-100 score estimating likelihood text is AI-written
      - burstiness:      variance in sentence length (high = human-like)
      - lexical_diversity:  unique word ratio (high = human-like)
      - hedging_count:   number of hedging / cautious phrases
      - transition_count:  formulaic transition phrases
      - avg_sentence_len:  mean words per sentence
      - signals:         list of detected signal names
      - summary:         short textual verdict
    """
    signals: list[str] = []
    score = 0  # 0-100, higher = more likely AI

    # Sentence segmentation
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    sentences = [s for s in sentences if len(s) > 5]
    if not sentences:
        return {
            "ai_probability": 0,
            "burstiness": 0.0,
            "lexical_diversity": 0.0,
            "hedging_count": 0,
            "transition_count": 0,
            "avg_sentence_len": 0.0,
            "signals": ["text too short to analyse"],
            "summary": "Insufficient text for perplexity analysis.",
        }

    sentence_lengths = [len(s.split()) for s in sentences]
    avg_sl = sum(sentence_lengths) / len(sentence_lengths)

    # 1. Burstiness (variance of sentence lengths)
    if len(sentence_lengths) > 1:
        var = sum((x - avg_sl) ** 2 for x in sentence_lengths) / len(sentence_lengths)
        burstiness = math.sqrt(var) / (avg_sl + 0.01)
    else:
        burstiness = 0.0

    # Low burstiness = uniform sentence length = AI-like
    if burstiness < 0.4:
        score += 20
        signals.append("low burstiness (uniform sentence lengths)")
    elif burstiness < 0.7:
        score += 10
        signals.append("moderate burstiness")

    # 2. Lexical diversity
    words = re.findall(r"\b[a-z]{3,}\b", text.lower())
    if words:
        unique_ratio = len(set(words)) / len(words)
    else:
        unique_ratio = 0.0

    # Very high lexical diversity can be AI too (LLMs use rich vocab)
    if unique_ratio > 0.75:
        score += 15
        signals.append("high lexical diversity (characteristic of LLM)")
    elif unique_ratio < 0.35:
        score += 10  # Repetitive = also suspicious
        signals.append("low lexical diversity (repetitive phrasing)")

    # 3. Hedging phrases
    hedging_count = 0
    for pat in HEDGING_PATTERNS:
        hedging_count += len(re.findall(pat, text.lower()))
    if hedging_count > 3:
        score += 15
        signals.append(f"{hedging_count} hedging/cautious phrases")
    elif hedging_count > 1:
        score += 8

    # 4. Formulaic transitions
    transition_count = 0
    for pat in TRANSITION_PATTERNS:
        transition_count += len(re.findall(pat, text.lower()))
    if transition_count > 4:
        score += 15
        signals.append(f"{transition_count} formulaic transitions")
    elif transition_count > 1:
        score += 7

    # 5. List-like structures
    list_count = len(LIST_PATTERN.findall(text))
    if list_count > 2:
        score += 10
        signals.append("enumerated list structure")

    # 6. Polite filler
    polite_count = 0
    for pat in POLITE_FILLER:
        polite_count += len(re.findall(pat, text.lower()))
    if polite_count > 1:
        score += 10
        signals.append("overly polite / canned phrasing")

    # 7. Overly balanced pros/cons pattern
    pros_cons = len(re.findall(r"\b(pros?|cons?|advantages?|disadvantages?)\b", text.lower()))
    if pros_cons > 2:
        score += 10
        signals.append("balanced pros/cons structure")

    # Clamp
    ai_probability = min(score, 100)

    # Summary
    if ai_probability >= 70:
        summary = "High probability of AI-generated text."
    elif ai_probability >= 40:
        summary = "Moderate AI-generation signals detected."
    elif ai_probability >= 15:
        summary = "Weak AI-generation signals."
    else:
        summary = "Likely human-written text."

    return {
        "ai_probability": ai_probability,
        "burstiness": round(burstiness, 4),
        "lexical_diversity": round(unique_ratio, 4),
        "hedging_count": hedging_count,
        "transition_count": transition_count,
        "avg_sentence_len": round(avg_sl, 2),
        "signals": signals[:8],
        "summary": summary,
    }
