import requests
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, AI_MODEL


def ai_analyze_email(email_text: str, detection_results: dict) -> str:
    """Use AI to generate a professional phishing analysis."""

    prompt = f"""You are a senior cybersecurity analyst specializing in phishing detection.

Analyze this email and the pre-scan results below. Provide a professional security assessment.

=== EMAIL CONTENT ===
{email_text[:2000]}

=== PRE-SCAN RESULTS ===
Risk Score: {detection_results['risk_score']}/100
Severity: {detection_results['severity']}
Keyword Categories Hit: {list(detection_results['keyword_matches'].keys())}
Suspicious URLs: {detection_results['suspicious_url_count']}
Attachments Mentioned: {detection_results['has_attachments']}

=== YOUR TASK ===
Write a professional security report with:
1. Executive Summary (2-3 sentences)
2. Key Threat Indicators (bullet points)
3. Attack Technique Used (e.g. credential harvesting, urgency manipulation)
4. Recommended Actions (numbered list)
5. Confidence Level: HIGH / MEDIUM / LOW

Keep it concise, professional, and actionable.
"""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://phishguard.ai",
    }

    payload = {
        "model": AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 600,
        "temperature": 0.3,
    }

    try:
        response = requests.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI analysis unavailable: {str(e)}"