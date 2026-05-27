# src/copilot.py
from datetime import datetime


SYSTEM_PROMPT = """You are PhishGuard Copilot — an expert AI security analyst embedded inside the PhishGuard threat detection platform.

Your role:
- Help users understand phishing threats, suspicious emails, and cyber attacks
- Analyze email content, URLs, headers, and indicators of compromise
- Explain security concepts in clear, actionable language
- Give specific recommendations based on what the user shares
- Reference the current analysis results when available

Your personality:
- Direct and precise — no fluff, no filler
- Use security terminology correctly but explain it when needed
- Confident but honest about uncertainty
- Format responses with clear structure when helpful

What you can help with:
- "Is this email safe?" — analyze pasted content
- "What does this URL do?" — explain suspicious links
- "What should I do about this threat?" — action recommendations
- "Explain SPF/DKIM/DMARC" — security education
- "Why is the risk score so high?" — explain analysis results
- "Write a report about this incident" — incident documentation
- General phishing awareness and security training

Always prioritize the user's safety. If something looks dangerous, say so clearly.
Keep responses concise unless depth is specifically requested.
Use markdown formatting for structure."""


def build_context_message(results: dict = None) -> str:
    """Build a context string from current analysis results to inject into chat."""
    if not results:
        return ""
    score    = results.get("risk_score", 0)
    severity = results.get("severity", "")
    kw       = results.get("total_keyword_hits", 0)
    urls     = results.get("suspicious_url_count", 0)
    preview  = results.get("email_preview", "")[:200]
    matches  = results.get("keyword_matches", {})
    kw_list  = []
    for cat, words in matches.items():
        kw_list.append(f"{cat}: {', '.join(words[:5])}")

    lines = [
        f"[Current Analysis Context]",
        f"Risk Score: {score}/100 ({severity})",
        f"Keyword Hits: {kw}",
        f"Suspicious URLs: {urls}",
    ]
    if kw_list:
        lines.append("Keyword Categories: " + " | ".join(kw_list))
    if preview:
        lines.append(f"Email Preview: {preview}")
    return "\n".join(lines)


def get_copilot_response(
    messages: list,
    results: dict = None,
    stream: bool = False
) -> str:
    """
    Send messages to Claude and return the response.
    messages: list of {"role": "user"/"assistant", "content": str}
    results: optional current analysis context
    """
    try:
        import anthropic
        client = anthropic.Anthropic()
    except ImportError:
        return (
            "⚠ The `anthropic` package is not installed. "
            "Add `anthropic` to requirements.txt and redeploy."
        )
    except Exception as e:
        return f"⚠ Could not initialise Anthropic client: {e}"

    # Build system prompt — inject analysis context if available
    system = SYSTEM_PROMPT
    ctx = build_context_message(results)
    if ctx:
        system += f"\n\n{ctx}"

    # Convert messages to Anthropic format, skip empty
    api_messages = [
        {"role": m["role"], "content": m["content"]}
        for m in messages
        if m.get("content", "").strip()
    ]
    if not api_messages:
        return "Ask me anything about phishing or email security."

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            system=system,
            messages=api_messages,
        )
        return response.content[0].text
    except anthropic.AuthenticationError:
        return (
            "⚠ Invalid Anthropic API key. "
            "Add `ANTHROPIC_API_KEY` to Streamlit secrets."
        )
    except anthropic.RateLimitError:
        return "⚠ Rate limit reached. Please wait a moment and try again."
    except Exception as e:
        return f"⚠ Copilot error: {e}"


# ── Suggested prompts shown when chat is empty ────────────────────────────
SUGGESTED_PROMPTS = [
    "🔍 Analyze the email I just scanned",
    "🚨 Why is the risk score so high?",
    "🔗 Are the suspicious URLs dangerous?",
    "📋 Write an incident report for this threat",
    "🛡 What should I do right now to stay safe?",
    "📧 How do I spot phishing emails myself?",
    "🔐 Explain SPF, DKIM and DMARC",
    "🌐 What is URL spoofing and how does it work?",
]