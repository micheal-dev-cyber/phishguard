import requests
import os

try:
    import streamlit as st
    OPENROUTER_API_KEY = st.secrets.get(
        "OPENROUTER_API_KEY", os.getenv("OPENROUTER_API_KEY", "")
    )
except Exception:
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
AI_MODEL = "openrouter/auto"


def ai_analyze_email(email_text: str, detection_results: dict) -> str:
    """Use AI to generate a professional phishing analysis report."""

    if not OPENROUTER_API_KEY:
        return "AI analysis unavailable — API key not configured."

    # Build keyword summary
    keyword_summary = ""
    for category, keywords in detection_results.get("keyword_matches", {}).items():
        keyword_summary += f"- {category.upper()}: {', '.join(keywords)}\n"

    # Build URL summary
    url_summary = ""
    if detection_results.get("suspicious_urls"):
        for item in detection_results["suspicious_urls"]:
            url_summary += f"- {item['url']}\n"
    else:
        url_summary = "None detected"

    prompt = f"""You are a senior cybersecurity analyst specializing in phishing and social engineering detection.

A user submitted an email for analysis. The automated scanner returned these results:

RISK SCORE: {detection_results['risk_score']}/100
SEVERITY: {detection_results['severity']}
KEYWORD HITS: {detection_results['total_keyword_hits']}
SUSPICIOUS URLS: {detection_results['suspicious_url_count']}
ATTACHMENTS MENTIONED: {detection_results['has_attachments']}

KEYWORD CATEGORIES TRIGGERED:
{keyword_summary if keyword_summary else "None"}

SUSPICIOUS URLS FOUND:
{url_summary}

EMAIL CONTENT (first 1500 characters):
\"\"\"
{email_text[:1500]}
\"\"\"

Write a professional security analysis report with these exact sections:

## Executive Summary
2-3 sentences summarizing the threat level and main attack vector.

## Attack Technique
Identify the specific phishing technique used (e.g. credential harvesting, urgency manipulation, brand impersonation, business email compromise). Explain how it works.

## Key Threat Indicators
List each suspicious element found and explain WHY it is dangerous.

## Social Engineering Analysis
Explain the psychological manipulation tactics used in this email to trick the victim.

## Potential Impact
What could happen if the victim follows the instructions in this email?

## Recommended Actions
Numbered list of specific steps the recipient should take right now.

## Confidence Level
State your confidence: HIGH / MEDIUM / LOW and explain why.

Be professional, specific, and actionable. Write as if this report will be sent to a company's IT security team."""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://phishguard.ai",
        "X-Title": "PhishGuard AI",
    }

    payload = {
        "model": AI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are an expert cybersecurity analyst. Write clear, professional security reports."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 1000,
        "temperature": 0.2,
    }

    try:
        response = requests.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=45
        )

        if response.status_code == 429:
            return (
                "AI service is busy (rate limit). "
                "Wait 30 seconds and try again. "
                "This is normal on free tier."
            )

        if response.status_code == 402:
            return "AI service requires credits. Go to openrouter.ai and add free credits."

        if response.status_code != 200:
            return f"AI service error {response.status_code}. Try again in a moment."

        data = response.json()

        if "choices" not in data:
            return f"Unexpected response from AI: {str(data)[:200]}"

        return data["choices"][0]["message"]["content"]

    except requests.exceptions.Timeout:
        return "AI analysis timed out after 45 seconds. Please try again."
    except requests.exceptions.ConnectionError:
        return "Could not connect to AI service. Check your internet connection."
    except Exception as e:
        return f"AI analysis failed: {str(e)}"