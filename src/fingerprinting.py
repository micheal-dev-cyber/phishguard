"""Phishing Kit Fingerprinting — match email content against known kit signatures."""

from __future__ import annotations

import json
import os
import re


def _load_kits() -> list[dict]:
    path = os.path.join(os.path.dirname(__file__), "..", "data", "phishing_kits.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)["kits"]


def _match_patterns(patterns: list[str], text: str) -> int:
    count = 0
    for pat in patterns:
        try:
            if re.search(pat, text, re.IGNORECASE):
                count += 1
        except re.error:
            if pat.lower() in text.lower():
                count += 1
    return count


def fingerprint_email(
    email_text: str,
    email_html: str = "",
    headers: dict | None = None,
) -> dict:
    """Scan email content for known phishing kit signatures.

    Returns:
        dict with keys:
          - kit_matches: list of matched kit names
          - matches: detailed list of {name, confidence, severity, matched_patterns}
          - total_kits_detected: int
          - highest_confidence: float
    """
    kits = _load_kits()
    combined = email_text + " " + email_html
    headers_str = json.dumps(headers or {})

    matches = []

    for kit in kits:
        sig = kit["signatures"]

        categories_data = [
            ("html", sig.get("html_patterns", [])),
            ("css", sig.get("css_patterns", [])),
            ("form_fields", sig.get("form_fields", [])),
            ("js", sig.get("js_patterns", [])),
            ("file_paths", sig.get("file_paths", [])),
            ("headers", sig.get("header_patterns", [])),
        ]

        category_ratios = []
        matched_patterns = {}

        for cat_name, patterns in categories_data:
            matched = 0
            for pat in patterns:
                if cat_name == "headers":
                    if pat.lower() in headers_str.lower():
                        matched += 1
                elif cat_name == "file_paths":
                    if pat.lower() in combined.lower() or pat.lower() in headers_str.lower():
                        matched += 1
                elif cat_name in ("css", "form_fields"):
                    if pat.lower() in combined.lower():
                        matched += 1
                else:
                    try:
                        if re.search(pat, combined, re.IGNORECASE):
                            matched += 1
                    except re.error:
                        if pat.lower() in combined.lower():
                            matched += 1

            total = len(patterns)
            matched_patterns[cat_name] = matched
            if total > 0:
                category_ratios.append(matched / total)

        if category_ratios:
            raw_confidence = sum(category_ratios) / len(category_ratios)
        else:
            raw_confidence = 0.0

        if raw_confidence > 0.1:
            scaled = raw_confidence * 100
            if scaled > 100:
                scaled = 100
            matches.append({
                "name": kit["name"],
                "description": kit["description"],
                "severity": kit["severity"],
                "confidence": round(scaled, 1),
                "matched_patterns": matched_patterns,
            })

    matches.sort(key=lambda m: m["confidence"], reverse=True)

    return {
        "kit_matches": [m["name"] for m in matches],
        "matches": matches,
        "total_kits_detected": len(matches),
        "highest_confidence": max((m["confidence"] for m in matches), default=0.0),
    }
