import requests
import os

try:
    import streamlit as st
    GROQ_API_KEY = st.secrets.get("GROQ_API_KEY", os.getenv("GROQ_API_KEY", ""))
except Exception:
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
AI_MODEL = "llama-3.1-8b-instant"


def ai_analyze_email(email_text: str, detection_results: dict) -> str:

    if not GROQ_API_KEY:
        return "AI analysis unavailable — add GROQ_API_KEY to Streamlit secrets."

    keyword_summary = ""
    for category, keywords in detection_results.get("keyword_matches", {}).items():
        keyword_summary += f"- {category.upper()}: {', '.join(keywords)}\n"

    url_summary = ""
    if detection_results.get("suspicious_urls"):
        for item in detection_results["suspicious_urls"]:
            url_summary += f"- {item['url']}\n"
    else:
        url_summary = "None detected"

    prompt = f"""You are a senior cybersecurity analyst specializing in phishing detection.

Automated scanner results:
- RISK SCORE: {detection_results['risk_score']}/100
- SEVERITY: {detection_results['severity']}
- KEYWORD HITS: {detection_results['total_keyword_hits']}
- SUSPICIOUS URLS: {detection_results['suspicious_url_count']}
- ATTACHMENTS: {detection_results['has_attachments']}

KEYWORDS TRIGGERED:
{keyword_summary if keyword_summary else "None"}

SUSPICIOUS URLS:
{url_summary}

EMAIL CONTENT:
\"\"\"
{email_text[:1500]}
\"\"\"

Write a professional security report with these exact sections:

## Executive Summary
2-3 sentences on threat level and attack vector.

## Attack Technique
Name the specific technique and explain how it works.

## Key Threat Indicators
List each suspicious element and explain why it is dangerous.

## Social Engineering Analysis
Explain the psychological manipulation tactics used.

## Potential Impact
What happens if the victim follows the instructions?

## Recommended Actions
Numbered list of steps to take right now.

## Confidence Level
HIGH / MEDIUM / LOW and why.

Be professional, specific, and actionable."""

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
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
            f"{GROQ_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 429:
            return "AI service is busy. Wait 30 seconds and try again."

        if response.status_code != 200:
            return f"AI service error {response.status_code}: {response.text[:200]}"

        data = response.json()

        if "choices" not in data:
            return f"Unexpected response: {str(data)[:200]}"

        return data["choices"][0]["message"]["content"]

    except requests.exceptions.Timeout:
        return "AI analysis timed out. Please try again."
    except requests.exceptions.ConnectionError:
        return "Could not connect to AI service."
    except Exception as e:
        return f"AI analysis failed: {str(e)}"