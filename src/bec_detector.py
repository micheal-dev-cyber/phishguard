"""Business Email Compromise (BEC) Detection Engine.

Detects targeted financial fraud patterns including:
- Invoice fraud and fake billing
- Wire transfer requests
- CEO / executive fraud
- Fake supplier / vendor emails
- Account payment changes
- Gift card scams
"""

from __future__ import annotations

import re
from typing import Any


BEC_PATTERNS = {
    "wire_transfer": {
        "patterns": [
            r"\bwire\s*(transfer|payment)\b",
            r"\bbank\s*(transfer|details?|account|routing)\b",
            r"\b(ach|cryptocurrency|swift|sepa)\s*(transfer|payment)?\b",
            r"\b(send|initiate|process|execute)\s*(payment|transfer|funds)\b",
        ],
        "label": "Wire Transfer Request",
        "weight": 30,
        "description": "Requests to wire money or initiate bank transfers — a hallmark of BEC fraud.",
    },
    "ceo_fraud": {
        "patterns": [
            r"\b(ceo|cfo|president|director)\s*(request|ask|instruct|need)\b",
            r"\bour\s*(ceo|cfo|president|executive)\b",
            r"\b(urgent|confidential)\s*(request|matter|payment)\b",
            r"\b(i['']?m\s+in\s+a\s+meeting|tied\s+up|unavailable)\b",
            r"\b(approve|authorize)\s*(payment|transfer|invoice)\b",
        ],
        "label": "CEO / Executive Fraud",
        "weight": 35,
        "description": "Impersonation of senior executives authorizing financial transactions.",
    },
    "invoice_fraud": {
        "patterns": [
            r"\b(invoice|bill|statement)\s*(attached|overdue|pending|due)\b",
            r"\b(outstanding|unpaid)\s*(balance|invoice|amount)\b",
            r"\b(payment\s*)?(overdue|past\s*due|lapsed)\b",
            r"\b(updated|changed|new)\s*(billing|payment|bank)\s*(details?|info)\b",
            r"\b(please\s*)?(remit|pay|settle)\s*(the|this|above)?\s*(invoice|amount|bill)\b",
        ],
        "label": "Invoice / Billing Fraud",
        "weight": 25,
        "description": "Fake invoices or billing notices designed to trick accounts payable.",
    },
    "supplier_fraud": {
        "patterns": [
            r"\b(supplier|vendor|contractor)\s*(update|change|details)\b",
            r"\bpurchas(e|ing)\s*(order|requisition)\b",
            r"\b(vendor|supplier|payee)\s*(form|change|update|registration)\b",
            r"\b(new\s*)?(banking|payment)\s*(details?|information|info)\s*(attached|below|here)\b",
            r"\b(please\s*)?(update|change|amend)\s*(our|the)\s*(payment|banking)\s*(info|details)\b",
        ],
        "label": "Fake Supplier / Vendor",
        "weight": 25,
        "description": "Impersonation of legitimate suppliers requesting payment details changes.",
    },
    "gift_card": {
        "patterns": [
            r"\bgift\s*card[s]?\b",
            r"\b(itunes|google\s*play|amazon)\s*gift\b",
            r"\b(purchase|buy|get)\s*gift\s*card\b",
            r"\b(scratch|redeem|pin|code)\s*(off|number)\b",
        ],
        "label": "Gift Card Request",
        "weight": 40,
        "description": "Requests to purchase gift cards — a near-certain sign of BEC/gift card fraud.",
    },
    "payment_change": {
        "patterns": [
            r"\b(change|update|modify)\s*(our|my|the)\s*(banking|payment|direct\s*deposit)\b",
            r"\b(new|different)\s*(bank|account|routing)\s*(details?|number)\b",
            r"\b(please\s*)?(direct|send)\s*(payment|funds)\s*to\b",
            r"\b(routing|account)\s*(#|number|no)\s*:?\s*\d{6,}\b",
        ],
        "label": "Payment Account Change",
        "weight": 30,
        "description": "Requests to change banking details for future payments — classic BEC pivot.",
    },
    "urgency_secrecy": {
        "patterns": [
            r"\b(confidential|urgent|time-sensitive|highly\s*sensitive)\b",
            r"\b(do\s*not\s*(discuss|share|tell|mention))\b",
            r"\b(keep\s*this\s*|handle\s*discreetly)\b",
            r"\b(only\s*you|trust\s*only)\s*(can|should)\b",
        ],
        "label": "Urgency / Secrecy Pressure",
        "weight": 20,
        "description": "Pressure to bypass normal procedures and keep the request secret.",
    },
    "social_engineering": {
        "patterns": [
            r"\b(i\s*need\s*your\s*help|need\s*a\s*favor)\b",
            r"\b(can\s*you\s*|please\s*)\s*(handle|take\s*care\s*of|process)\s*(this|the|a)\b",
            r"\b(i['']?m\s*(out\s*of|away\s*from|not\s*in)\s*(the\s*)?office)\b",
            r"\b(are\s*you\s*|will\s*you\s*be\s*)(available|around|at\s*desk)\b",
        ],
        "label": "Social Engineering Hook",
        "weight": 15,
        "description": "Manipulative language designed to exploit helpfulness or authority.",
    },
}


def detect_bec(email_text: str, results: dict | None = None) -> dict:
    """Run all BEC detection patterns against email text.

    Args:
        email_text: The raw email text to analyze
        results: Optional pre-computed analysis results for enrichment

    Returns:
        Dict with keys:
            bec_detected (bool): Whether BEC patterns were found
            confidence (int): 0-100 confidence score
            patterns_found (list): Which BEC categories matched
            risk_score (int): BEC-specific risk score 0-100
            total_weight (int): Sum of matched pattern weights
            details (list): Human-readable BEC findings
    """
    text_lower = email_text.lower()

    patterns_found = {}
    for bec_type, config in BEC_PATTERNS.items():
        matches = []
        for pat in config["patterns"]:
            found = re.findall(pat, text_lower)
            if found:
                matches.extend(found if isinstance(found[0], str) else [m[0] for m in found if m and m[0]])

        if matches:
            patterns_found[bec_type] = {
                "label": config["label"],
                "weight": config["weight"],
                "matches": list(set(matches))[:5],
                "description": config["description"],
            }

    if not patterns_found:
        return {
            "bec_detected": False,
            "confidence": 0,
            "patterns_found": [],
            "risk_score": 0,
            "total_weight": 0,
            "details": [],
            "bec_type": None,
        }

    total_weight = sum(p["weight"] for p in patterns_found.values())
    risk_score = min(total_weight, 100)

    confidence = min(int(total_weight * 1.5), 100)

    details = [
        f"💰 **{p['label']}** — {p['description']}"
        for p in patterns_found.values()
    ]

    bec_types = list(patterns_found.keys())

    primary_bec_type = max(patterns_found.items(), key=lambda x: x[1]["weight"])[0] if patterns_found else None

    return {
        "bec_detected": True,
        "confidence": confidence,
        "patterns_found": bec_types,
        "risk_score": risk_score,
        "total_weight": total_weight,
        "details": details,
        "bec_type": primary_bec_type,
        "pattern_details": patterns_found,
    }
