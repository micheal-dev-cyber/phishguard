"""Phishing DNA / Fuzzy Hashing — linguistic threat signature matching.

Computes a normalized "Threat Signature" from email text using
character n-gram overlap with known phishing campaigns stored in
session state. If similarity >= 85%, flags as known variant.
"""

from __future__ import annotations

import re
import hashlib
from difflib import SequenceMatcher
from typing import Optional


# ── Signature computation ────────────────────────────────────────────────


def _normalize(text: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation runs."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def compute_threat_signature(text: str) -> dict:
    """Return a dict with n-gram fingerprints for a given text.

    Keys:
      - sha256: hex digest of normalized text
      - trigrams: set of character trigrams
      - bigrams:  set of character bigrams
      - words:    set of normalized tokens
      - length:   character count of normalized text
      - preview:  first 120 chars of raw text
    """
    norm = _normalize(text)
    return {
        "sha256": hashlib.sha256(norm.encode()).hexdigest(),
        "trigrams": {norm[i:i+3] for i in range(len(norm) - 2)},
        "bigrams": {norm[i:i+2] for i in range(len(norm) - 1)},
        "words": set(norm.split()),
        "length": len(norm),
        "preview": text[:120],
    }


# ── Similarity scoring ───────────────────────────────────────────────────


def _jaccard(a: set, b: set) -> float:
    """Jaccard similarity between two sets."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _sequence_similarity(a: str, b: str) -> float:
    """Normalized difflib ratio on normalized text."""
    return SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()


def compare_signatures(sig_a: dict, sig_b: dict) -> dict:
    """Compare two threat signatures, return per-metric + composite scores.

    Returns::
      trigram_sim:  Jaccard on trigrams (0-1)
      bigram_sim:   Jaccard on bigrams  (0-1)
      word_sim:     Jaccard on words    (0-1)
      seq_sim:      difflib sequence matcher (0-1)
      composite:    weighted average   (0-1)
      length_ratio: min/max length ratio
    """
    trigram_sim = _jaccard(sig_a["trigrams"], sig_b["trigrams"])
    bigram_sim = _jaccard(sig_a["bigrams"], sig_b["bigrams"])
    word_sim = _jaccard(sig_a["words"], sig_b["words"])
    seq_sim = _sequence_similarity(
        sig_a.get("preview", ""), sig_b.get("preview", "")
    )

    # Weighted composite: trigrams carry most weight for fingerprinting
    composite = (
        trigram_sim * 0.35
        + bigram_sim * 0.20
        + word_sim * 0.25
        + seq_sim * 0.20
    )

    la = sig_a.get("length", 1)
    lb = sig_b.get("length", 1)
    length_ratio = min(la, lb) / max(la, lb) if max(la, lb) > 0 else 0.0

    return {
        "trigram_sim": round(trigram_sim, 4),
        "bigram_sim": round(bigram_sim, 4),
        "word_sim": round(word_sim, 4),
        "seq_sim": round(seq_sim, 4),
        "composite": round(composite, 4),
        "length_ratio": round(length_ratio, 4),
    }


# ── Known campaign matching ──────────────────────────────────────────────


MATCH_THRESHOLD = 0.85


def match_known_campaign(
    text: str,
    known_signatures: Optional[list] = None,
) -> Optional[dict]:
    """Check *text* against a list of known phishing signatures.

    *known_signatures* should be a list of dicts previously returned by
    ``compute_threat_signature()``.  If ``None``, returns ``None``.

    Returns the first match where ``composite >= MATCH_THRESHOLD``
    as ``{"match": dict, "similarity": float, "signature": dict}``,
    or ``None``.
    """
    if not known_signatures:
        return None
    sig = compute_threat_signature(text)
    for known in known_signatures:
        score = compare_signatures(sig, known)
        if score["composite"] >= MATCH_THRESHOLD:
            return {
                "match": known,
                "similarity": score["composite"],
                "signature": sig,
            }
    return None


def flagged_as_known_phishing(
    text: str,
    session_store: dict,
    store_key: str = "phishing_signatures",
) -> tuple:
    """High-level helper for the analysis pipeline.

    Checks *text* against *session_store[store_key]* (a list).  If
    matched and the match composite >= 85 %, returns ``(True, match)``.

    Always appends the current text's signature to the store so the
    library grows over time.
    """
    known = session_store.get(store_key, [])
    match = match_known_campaign(text, known)
    # Always learn — append current signature
    sig = compute_threat_signature(text)
    known.append(sig)
    session_store[store_key] = known
    if match:
        return True, match
    return False, None
