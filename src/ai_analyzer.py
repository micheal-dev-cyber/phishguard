# src/ai_analyzer.py
import requests
import json
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, AI_MODEL

def generate_ai_report(email_text, rule_findings=None):
    """
    Dispatches threat text and local heuristic findings to Mistral via OpenRouter.
    Returns a clean, structured incident response report.
    """
    if not OPENROUTER_API_KEY:
        return "⚠️ AI Warning: No OpenRouter API key found. Please configure your .env file or Streamlit deployment secrets."

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://phishguard.ai", 
        "X-Title": "PhishGuard Enterprise AI"
    }

    # Pass rule findings along to give the AI context on what we already found
    context_injection = ""
    if rule_findings:
        context_injection = f"Our local static analyzer already flagged these vulnerabilities: {', '.join(rule_findings)}.\n"

    prompt = f"""
You are an expert SecOps Incident Responder handling corporate mail security. 
Analyze this untrusted email content for social engineering, spear-phishing, or financial coercion patterns.

{context_injection}
---
RAW EMAIL BODY/CONTEXT:
{email_text}
---

Generate an analytical investigation profile structured exactly with these headers:
### 🔍 EXECUTIVE RISK BREAKDOWN
(Provide 2 clear, authoritative sentences on the core exploit intention)

### ⚠️ PSYCHOLOGICAL & TECHNICAL TACTICS
(Provide bullet points focusing on urgency vectors, credential harvesting setups, or authority fabrications)

### 🛡️ SECURE MITIGATION ACTIONS
(Provide bullet points listing immediate protective instructions for the target operator or internal IT administration)

Be objective, cold, and professional. Avoid conversational filler or introductory remarks.
"""

    payload = {
        "model": AI_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior, pragmatic security operations analyst."},
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            headers=headers,
            data=json.dumps(payload),
            timeout=15
        )
        
        if response.status_code == 200:
            response_json = response.json()
            return response_json['choices'][0]['message']['content'].strip()
        else:
            return f"❌ OpenRouter API Error: [{response.status_code}] - {response.text}"
            
    except requests.exceptions.Timeout:
        return "❌ Threat Engine Timeout: The remote OpenRouter connection timed out."
    except Exception as e:
        return f"❌ Critical Engine Exception: {str(e)}"