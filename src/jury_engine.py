import json
import logging
import os
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

LINGUISTIC_PATTERNS = {
    "translation_artifacts": {
        "patterns": [
            r"\b(kindly|do the needful|revert back|prepone|cousin)\b",
            r"\b(dear (sir|madam|valued customer|user|friend))\b",
            r"\b(we are (writing|contacting|reaching out) to (inform|notify|alert|request))\b",
            r"\b(your (account|profile|access) (has been|have been|will be))\b",
            r"\b(please be (advised|informed|notified))\b",
        ],
        "label": "Translation Artifacts",
        "weight": 0.30,
    },
    "grammar_anomalies": {
        "patterns": [
            r"\b[a-z]+\s+[a-z]+\s+[a-z]+ly\b",
            r"\b(although|however|therefore|moreover|nevertheless)\s*,",
            r"\b(but|and|or|so)\s{2,}",
            r"\b(is|are|was|were)\s+(is|are|was|were)\b",
            r"\b(your\s+(are|is)|you'?re\s+(account|password))\b",
        ],
        "label": "Grammar Anomalies",
        "weight": 0.25,
    },
    "ai_generation_markers": {
        "patterns": [
            r"\b(I (hope|trust|believe|understand) this (message|email|communication) finds you (well|safe))\b",
            r"\b(should you have any (questions|concerns|queries), please do not hesitate)\b",
            r"\b(feel free to (reach out|contact|get back))\b",
            r"\b(I (would|should) like to (bring to your attention|inform you|notify you))\b",
            r"\b(please (find|see) (below|attached|enclosed))\b",
        ],
        "label": "AI Generation Markers",
        "weight": 0.25,
    },
    "inconsistent_register": {
        "patterns": [
            r"\b(wherein|hereby|herewith|thereof|thereto|aforesaid)\b",
            r"\b(pursuant to|in accordance with|with reference to)\b",
            r"(?:^|\n)\s{0,3}[a-z]",
            r"\b(per|via|vs\.|etc)\b",
        ],
        "label": "Inconsistent Register",
        "weight": 0.20,
    },
}

CORPORATE_PATTERNS = {
    "domain_impersonation": {
        "patterns": [
            r"\@[a-z]+-[a-z]+\.(com|org|net|info)\b",
            r"\@[a-z]+\.[a-z]{2,3}\.[a-z]{2,3}\b",
            r"(paypal|amazon|microsoft|apple|google|netflix|linkedin)[^a-z]",
            r"\b(secure|login|verify|update|confirm|account)\-.*?\.(com|org)\b",
        ],
        "label": "Domain Impersonation",
        "weight": 0.30,
    },
    "executive_spoofing": {
        "patterns": [
            r"\b(CEO|CFO|COO|president|director|Vice President|VP)\b",
            r"\b(confidential|sensitive|private|internal only|privileged)\b",
            r"\b(authorized (transaction|payment|transfer|wire))\b",
            r"\b(urgent (request|matter|action|attention|approval))\b",
        ],
        "label": "Executive Spoofing",
        "weight": 0.30,
    },
    "invoice_payment_bec": {
        "patterns": [
            r"\b(outstanding (invoice|payment|balance)|past due|overdue)\b",
            r"\b(wire (transfer|instruction)|ach|direct deposit)\b",
            r"\b(banking (details|information|account)|payment (details|information))\b",
            r"\b(invoice (attached|enclosed|pending|#\d+))\b",
        ],
        "label": "Invoice/Payment BEC",
        "weight": 0.25,
    },
    "vendor_compromise": {
        "patterns": [
            r"\b(vendor|supplier|provider|contractor) (update|change|form|details)\b",
            r"\b(updated (banking|payment|remittance) (information|details))\b",
            r"\b(please (remit|send|transfer|wire) (payment|funds) to)\b",
            r"\b(new (banking|account|payment) (details|information|instructions))\b",
        ],
        "label": "Vendor Compromise",
        "weight": 0.15,
    },
}


def _heuristic_jury(text: str, patterns: Dict, fallback_weight: float) -> Tuple[int, List[str], float]:
    """Run heuristic pattern matching for a jury panel."""
    text_lower = text.lower()
    total_hits = 0
    all_findings = []

    for category_id, category in patterns.items():
        hits = 0
        category_findings = []
        for pattern in category["patterns"]:
            try:
                matches = re.findall(pattern, text_lower)
                if matches:
                    hits += len(matches)
                    category_findings.append(matches[0] if isinstance(matches[0], str) else matches[0][0])
            except re.error:
                continue

        if hits > 0:
            total_hits += hits
            all_findings.append({
                "category": category["label"],
                "hits": hits,
                "examples": list(set(category_findings))[:3],
            })

    raw_score = min(total_hits * 10, 100)
    confidence = min(0.5 + (total_hits * 0.05), 0.95)
    return raw_score, all_findings, confidence


LINGUISTIC_SYSTEM_PROMPT = """You are PhishGuard Linguistic Jury, an expert in forensic text analysis.
Analyse the email below for linguistic evidence of phishing, social engineering, or AI generation.

Evaluate:
1. **Translation Artifacts** — non-native grammar patterns, literal translations, awkward phrasing
2. **AI Generation Markers** — formulaic structures, overly polite templates, LLM-typical constructions
3. **Register Inconsistencies** — mixing formal and informal language in unusual ways
4. **Grammar & Spelling Anomalies** — mistakes that follow non-native patterns vs. intentional typos

Return a JSON object:
{
  "linguistic_risk_score": 0-100,
  "confidence": 0.0-1.0,
  "findings": ["specific linguistic red flag 1", "specific linguistic red flag 2"],
  "explanation": "concise technical explanation of the linguistic assessment"
}"""

CORPORATE_SYSTEM_PROMPT = """You are PhishGuard Corporate Context Jury, an expert in Business Email Compromise detection.
Analyse the email below for corporate context anomalies and BEC indicators.

Evaluate:
1. **Domain Impersonation** — lookalike domains, brand name abuse in sender addresses
2. **Executive Impersonation** — requests from C-level executives that bypass normal channels
3. **Invoice/Payment Manipulation** — unusual payment requests, changed banking details
4. **Vendor Compromise** — vendor communication with altered payment instructions
5. **Authority Bypass** — requests that skip standard approval processes

Return a JSON object:
{
  "corporate_risk_score": 0-100,
  "confidence": 0.0-1.0,
  "findings": ["specific BEC red flag 1", "specific BEC red flag 2"],
  "explanation": "concise technical explanation of the corporate context assessment"
}"""


def _call_llm_jury(system_prompt: str, email_text: str, max_retries: int = 1) -> Optional[Dict]:
    """Call an LLM (OpenAI or Anthropic) for jury analysis with fallback."""
    # Try OpenAI first
    try:
        import openai
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Email content:\n\n{email_text[:4000]}"},
            ],
            temperature=0.1,
            max_tokens=800,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content.strip()
        return json.loads(raw)
    except Exception as e:
        logger.exception("jury_engine: OpenAI LLM call failed: %s", e)

    # Try Anthropic as fallback
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            system=system_prompt,
            messages=[{"role": "user", "content": f"Email content:\n\n{email_text[:4000]}"}],
        )
        raw = response.content[0].text.strip()
        return json.loads(raw)
    except Exception as e:
        logger.exception("jury_engine: Anthropic LLM call failed: %s", e)

    return None


def _linguistic_heuristic(text: str) -> Dict:
    """Heuristic linguistic analysis when LLM is unavailable."""
    score, findings, confidence = _heuristic_jury(text, LINGUISTIC_PATTERNS, 0.5)
    finding_texts = []
    for f in findings:
        for ex in f.get("examples", []):
            finding_texts.append(f"{f['category']}: '{ex}'")
    return {
        "linguistic_risk_score": score,
        "confidence": round(confidence, 2),
        "findings": finding_texts[:5],
        "explanation": f"Heuristic linguistic analysis detected {len(findings)} anomaly categories "
                       f"({sum(f['hits'] for f in findings)} total pattern hits).",
    }


def _corporate_heuristic(text: str) -> Dict:
    """Heuristic corporate context analysis when LLM is unavailable."""
    score, findings, confidence = _heuristic_jury(text, CORPORATE_PATTERNS, 0.5)
    finding_texts = []
    for f in findings:
        for ex in f.get("examples", []):
            finding_texts.append(f"{f['category']}: '{ex}'")
    return {
        "corporate_risk_score": score,
        "confidence": round(confidence, 2),
        "findings": finding_texts[:5],
        "explanation": f"Heuristic corporate context analysis detected {len(findings)} BEC indicator "
                       f"categories ({sum(f['hits'] for f in findings)} total pattern hits).",
    }


def evaluate_linguistic_jury(email_text: str) -> Dict:
    """
    Evaluate linguistic anomalies in the email text.
    Uses LLM when available, falls back to heuristic pattern matching.
    """
    if not email_text.strip():
        return {"linguistic_risk_score": 0, "confidence": 0, "findings": [], "explanation": "No text provided."}

    if os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        result = _call_llm_jury(LINGUISTIC_SYSTEM_PROMPT, email_text)
        if result:
            return {
                "linguistic_risk_score": min(result.get("linguistic_risk_score", 50), 100),
                "confidence": min(result.get("confidence", 0.5), 1.0),
                "findings": result.get("findings", []),
                "explanation": result.get("explanation", ""),
            }

    return _linguistic_heuristic(email_text)


def evaluate_corporate_jury(email_text: str) -> Dict:
    """
    Evaluate corporate context anomalies / BEC indicators.
    Uses LLM when available, falls back to heuristic pattern matching.
    """
    if not email_text.strip():
        return {"corporate_risk_score": 0, "confidence": 0, "findings": [], "explanation": "No text provided."}

    if os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        result = _call_llm_jury(CORPORATE_SYSTEM_PROMPT, email_text)
        if result:
            return {
                "corporate_risk_score": min(result.get("corporate_risk_score", 50), 100),
                "confidence": min(result.get("confidence", 0.5), 1.0),
                "findings": result.get("findings", []),
                "explanation": result.get("explanation", ""),
            }

    return _corporate_heuristic(email_text)


def compute_ensemble_score(
    linguistic: Dict,
    corporate: Dict,
    linguistic_weight: float = 0.45,
    corporate_weight: float = 0.45,
    heuristic_weight: float = 0.10,
    heuristic_score: int = 0,
) -> Dict:
    """
    Combine linguistic and corporate jury scores into a final weighted ensemble score.
    The heuristic_score is the existing rule-based detection score (0-100).

    Returns dict with final_score, severity, component breakdown.
    """
    ling_score = linguistic.get("linguistic_risk_score", 0)
    corp_score = corporate.get("corporate_risk_score", 0)
    ling_conf = linguistic.get("confidence", 0.5)
    corp_conf = corporate.get("confidence", 0.5)

    # Confidence-weighted scores
    ling_contribution = ling_score * ling_conf * linguistic_weight
    corp_contribution = corp_score * corp_conf * corporate_weight
    heur_contribution = heuristic_score * heuristic_weight

    final_score = min(round(ling_contribution + corp_contribution + heur_contribution), 100)

    if final_score >= 75:
        severity = "CRITICAL"
        color = "#ff4444"
    elif final_score >= 50:
        severity = "HIGH"
        color = "#ff8800"
    elif final_score >= 25:
        severity = "MEDIUM"
        color = "#ffaa00"
    else:
        severity = "LOW"
        color = "#44aa44"

    return {
        "final_score": final_score,
        "severity": severity,
        "severity_color": color,
        "linguistic_score": ling_score,
        "linguistic_confidence": round(ling_conf, 2),
        "linguistic_contribution": round(ling_contribution, 1),
        "linguistic_findings": linguistic.get("findings", []),
        "linguistic_explanation": linguistic.get("explanation", ""),
        "corporate_score": corp_score,
        "corporate_confidence": round(corp_conf, 2),
        "corporate_contribution": round(corp_contribution, 1),
        "corporate_findings": corporate.get("findings", []),
        "corporate_explanation": corporate.get("explanation", ""),
        "heuristic_contribution": round(heur_contribution, 1),
        "weights": {
            "linguistic": linguistic_weight,
            "corporate": corporate_weight,
            "heuristic": heuristic_weight,
        },
    }
