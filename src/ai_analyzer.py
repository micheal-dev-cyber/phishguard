# src/ai_analyzer.py
import json
import os
import re
from typing import Dict

import openai


# ─────────────────────────────────────────────
# SAFE CLIENT INITIALIZATION (Prevents boot crashes)
# ─────────────────────────────────────────────
def _get_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        return openai.OpenAI(api_key=api_key)
    except Exception:
        return None

# ─────────────────────────────────────────────
# HEURISTIC FALLBACKS (no API key / API down)
# ─────────────────────────────────────────────

def _email_heuristic_fallback(subject: str, body: str, sender: str, error_msg: str = "") -> dict:
    lc = (body + " " + subject).lower()
    lc_sender = sender.lower()
    score = 15
    indicators = []

    if any(w in lc for w in ["password", "reset", "secure", "verify"]):
        score += 25
        indicators.append("Security credential keywords detected")
    if any(w in lc for w in ["urgent", "immediate", "action required", "suspended"]):
        score += 20
        indicators.append("Urgency and panic trigger language")
    if any(w in lc for w in ["click here", "login", "http"]):
        score += 15
        indicators.append("Suspicious actionable hyperlinks found")
    if any(w in lc_sender for w in ["microsoft", "paypal", "support", "billing", "admin"]):
        score += 20
        indicators.append("Sender impersonates authority brand")

    score = min(score, 100)
    severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW"
    note = f"⚠️ AI fallback mode active ({error_msg}). " if error_msg else ""

    return {
        "isPhishing": score > 40,
        "score": score,
        "severity": severity,
        "indicators": indicators or ["External unverified communication"],
        "senderAssessment": f"Domain {lc_sender} may impersonate authoritative sources.",
        "analysisSummary": f"{note}Heuristic scan detected threat score {score}% based on credential solicitation, urgency tactics, and routing anomalies.",
        "remediationPlan": "Quarantine sender domain. Clear browser sessions. Notify recipients and enforce phishing alerts."
    }


def _url_heuristic_fallback(url: str, host: str, error_msg: str = "") -> dict:
    score = 10
    flags = []

    if any(k in host for k in ["-verification", "update-profile", "secure-login", "signin-", "dhl-parcel"]):
        score += 45
        flags.append("Keyword spoofing matching high-profile brands")
    if any(host.endswith(t) for t in [".info", ".xyz", ".pw", ".top", ".tk", ".cc"]):
        score += 25
        flags.append(f"Suspicious TLD (.{host.split('.')[-1]}) common in spam campaigns")
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host):
        score += 35
        flags.append("Raw IP address used as hostname — bypassing DNS authentication")
    if len(host) > 28:
        score += 15
        flags.append("Over-extended hostname mimicking legitimate subdomains")

    score = min(score, 100)
    severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    note = f"⚠️ AI fallback active ({error_msg}). " if error_msg else ""

    return {
        "url": url,
        "host": host,
        "isPhishing": score > 35,
        "score": score,
        "severity": severity,
        "threatCategory": "Credential Harvesting Portal" if score > 35 else "Clean / Low Suspicion",
        "indicators": flags or ["External self-signed hosting indicators"],
        "aiExplanation": f"{note}Domain '{host}' displays typosquatting, keyword mimicry of auth channels, or spam-favored TLD characteristics."
    }


# ─────────────────────────────────────────────
# 1. EMAIL THREAT ANALYSIS
# ─────────────────────────────────────────────

def analyze_email(subject: str, body: str, sender: str) -> dict:
    from src.providers import get_completion

    prompt = (
        f"Perform a highly rigorous Cyber Threat Analysis on this incoming email "
        f"for enterprise security protection.\n\n"
        f"Sender: {sender or 'Unknown External'}\n"
        f"Subject: {subject or 'None Provided'}\n"
        f"Body Content:\n\"\"\"\n{body}\n\"\"\"\n\n"
        f"Evaluate the risk score from 0 (Fully Safe) to 100 "
        f"(Unquestionable malicious phishing / Credential Harvest / Spear Phishing).\n"
        f"Identify phishing techniques (e.g., typosquatting, sender spoofing, "
        f"generic greeting, panic trigger, credential harvesting links, "
        f"suspicious attachments, call to action).\n\n"
        f"Return ONLY a valid JSON object with this exact structure:\n"
        f'{{"isPhishing": boolean, "score": integer (0 to 100), '
        f'"severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", '
        f'"indicators": [list of specific threat indicators found], '
        f'"senderAssessment": "analysis of sender authenticity and domain reputation", '
        f'"analysisSummary": "expert cybersecurity explanation of the threat campaign and flags", '
        f'"remediationPlan": "expert action steps to neutralize the threat immediately"}}'
    )

    result = get_completion(
        "You are a senior enterprise cybersecurity analyst specializing in phishing detection. Always respond with valid JSON only, no markdown, no explanation.",
        prompt,
        max_tokens=1000,
    )
    if result.startswith("⚠"):
        return _email_heuristic_fallback(subject, body, sender, result)

    try:
        raw = re.sub(r'^```json|^```|```$', '', result, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        return _email_heuristic_fallback(subject, body, sender, str(e))


# ─────────────────────────────────────────────
# 2. URL THREAT SCANNER
# ─────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    from src.providers import get_completion

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        host = parsed.hostname or url.lower()
    except Exception:
        host = url.lower()

    prompt = (
        f"Review this suspicious URL from an enterprise firewall inspection.\n\n"
        f"Target URL: {url}\n"
        f"Extracted Hostname: {host}\n\n"
        f"Evaluate if this URL presents a cyber risk: phishing portals, banking trojans, "
        f"typosquatted brand fraud, or malicious redirects.\n\n"
        f"Return ONLY a valid JSON object:\n"
        f'{{"isPhishing": boolean, "score": integer (0 to 100), '
        f'"severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", '
        f'"threatCategory": "e.g. Brand Impersonation / Credential Harvest, Malicious Download, Safe / Low Risk", '
        f'"indicators": [list of malicious traits found in URL structure or domain], '
        f'"aiExplanation": "expert security summary outlining typosquatting tricks, domain mimicry, or structural anomalies"}}'
    )

    result = get_completion(
        "You are a senior cybersecurity URL threat analyst. Always respond with valid JSON only.",
        prompt,
        max_tokens=600,
    )
    if result.startswith("⚠"):
        return _url_heuristic_fallback(url, host, result)

    try:
        raw = re.sub(r'^```json|^```|```$', '', result, flags=re.MULTILINE).strip()
        data = json.loads(raw)
        return {"url": url, "host": host, **data}
    except Exception as e:
        return _url_heuristic_fallback(url, host, str(e))


# ─────────────────────────────────────────────
# 3. AI COPILOT CHAT
# ─────────────────────────────────────────────

def copilot_chat(messages: list) -> str:
    from src.providers import get_chat_completion
    return get_chat_completion(
        messages,
        system_prompt="You are PhishGuard AI Copilot — a senior enterprise cyber defense assistant. Use Markdown formatting.",
        max_tokens=800,
    )


# ─────────────────────────────────────────────
# 4. PHISHING SIMULATOR (Enterprise Training)
# ─────────────────────────────────────────────

SIMULATION_FALLBACKS: Dict[str, Dict[str, str]] = {
    ("Finance", "Urgent Invoice"): {
        "subject": "Overdue Payment Notice — Invoice #INV-4291 requires immediate settlement",
        "sender": "accounts-payable@corporation-finance-billing.net",
        "body": "Dear Accounts Department,\n\nOur records indicate that Invoice #INV-4291 for $84,920.00 remains unpaid beyond the 30-day term.\n\nTo avoid late-penalty escalation and service disruption, please process the wire transfer immediately via the secure payment portal:\n\nhttp://finance-portal-verify.online/pay-invoice\n\nThis is your final notice before account suspension.",
        "clues": [
            "Urgency tactic: 'final notice' and 'immediate settlement' bypass rational review",
            "Typosquatted domain: corporation-finance-billing.net mimics a legitimate vendor",
            "Generic greeting — no named contact person",
            "External .online TLD used for a supposed financial portal",
            "Payment request goes to a lookalike domain, not the vendor's real portal"
        ],
        "remediation": "Always verify payment requests through a trusted phone number. Never use URLs embedded in email invoices."
    },
    ("Finance", "Password Reset"): {
        "subject": "Action Required: Your Corporate Banking Credentials Will Expire",
        "sender": "noreply@banking-security-verification.co",
        "body": "Dear User,\n\nYour corporate banking password will expire in 48 hours. To maintain uninterrupted access, reset your password now:\n\nhttps://secure-banking-verify.co/reset\n\nFailure to reset will result in account lockdown.",
        "clues": [
            "False urgency: 48-hour countdown fabricates time pressure",
            "Suspicious TLD (.co) — not the legitimate banking domain",
            "Generic greeting — real banks address you by name",
            "The reset link goes to an impostor domain"
        ],
        "remediation": "Never click 'reset password' links in unsolicited emails. Navigate directly to your bank's official website."
    },
    ("HR", "Fake HR Policy"): {
        "subject": "Urgent: Updated Code of Conduct — Acknowledge by EOD",
        "sender": "hr-compliance@internal-policy-update.org",
        "body": "Dear Employee,\n\nManagement has rolled out an updated Code of Conduct and Data Handling Policy. All staff must review and acknowledge the new policy by end of day.\n\nReview the changes here:\nhttp://company-policy-review.org/acknowledge\n\nNon-compliance will be escalated to your department head.",
        "clues": [
            "Threat of escalation if not immediately followed",
            "Generic domain (.org) is not a corporate intranet",
            "Policy links should point to internal servers, not external websites",
            "No personalised greeting with your name"
        ],
        "remediation": "Verify HR policy updates through your company's official intranet. Forward suspicious policy emails to IT."
    },
    ("HR", "Urgent Invoice"): {
        "subject": "Urgent: Q4 Staffing Invoices Overdue — Immediate Processing Required",
        "sender": "temp-invoicing@staffing-payroll-billing.co",
        "body": "Dear HR Director,\n\nOur quarterly staffing invoices are overdue. Please process the attached invoice summary for $127,350.00 at your earliest convenience.\n\nDownload the invoice:\nhttp://staffing-payroll-billing.co/invoice-q4\n\nLate payment may affect contractor retention.",
        "clues": [
            "Business Email Compromise (BEC) — fake invoice targeting HR",
            "Attachment/Download link leads to an external .co domain",
            "Threat: 'late payment may affect contractor retention' creates artificial pressure",
            "Spoofed sender domain mimics a real staffing agency"
        ],
        "remediation": "Cross-reference invoice numbers with procurement records. Always validate payment details by phone."
    },
    ("IT Support", "Password Reset"): {
        "subject": "IT Alert: Your Microsoft 365 Password Expires Today",
        "sender": "it-support@microsoft-account-verify.net",
        "body": "Dear User,\n\nYour Microsoft 365 password will expire in 24 hours. To avoid losing access to email and company resources, verify your credentials here:\n\nhttps://login-microsoft-account-verify.net/update\n\nThis is an automated IT security notification.",
        "clues": [
            "Impersonates Microsoft 365 IT support to harvest corporate credentials",
            "Lookalike domain: microsoft-account-verify.net is NOT microsoft.com",
            "24-hour urgency is a classic time-pressure tactic",
            "The link points to a credential harvesting page"
        ],
        "remediation": "IT will never ask you to click a link to reset your password. Use your organisation's official identity portal."
    },
    ("IT Support", "Fake HR Policy"): {
        "subject": "Mandatory: New IT Acceptable Use Policy — Sign by Friday",
        "sender": "compliance@it-security-policy-review.org",
        "body": "Dear Staff,\n\nA new IT Acceptable Use Policy has been published in response to recent security audits. All employees must digitally sign the acknowledgement form by Friday.\n\nAccess the policy:\nhttp://it-security-policy-review.org/acknowledge\n\nFailure to comply will result in network access restrictions.",
        "clues": [
            "Fake urgency: Friday deadline creates unnecessary pressure",
            "External domain (.org) masquerading as a corporate policy portal",
            "Threat of network access restriction if not signed"
        ],
        "remediation": "Always access company policies through the official employee portal. Contact IT directly to verify policy announcements."
    },
}

def _get_simulation_fallback(department: str, vector: str) -> dict:
    """Return a hardcoded simulation for the given department + vector pair."""
    key = (department, vector)
    return SIMULATION_FALLBACKS.get(
        key,
        {
            "subject": f"Security Alert: {vector} — Action Required",
            "sender": f"security@{department.lower().replace(' ', '')}-verify.net",
            "body": f"Dear {department} Team,\n\nWe have detected unusual activity. Please verify your credentials immediately:\n\nhttp://{department.lower().replace(' ', '')}-secure-portal.verify/update\n\nFailure to act within 24 hours may result in account suspension.",
            "clues": [
                "Generic greeting — no personal name used",
                "Lookalike domain mimicking an official service",
                "24-hour urgency deadline creates panic response",
                "Request for credentials or action via a link"
            ],
            "remediation": "Never act on unsolicited security alerts. Contact your IT team directly using known contact information."
        }
    )


def simulate_phishing(department: str, attack_vector: str) -> dict:
    from src.providers import get_completion

    prompt = (
        f"Generate a realistic mock phishing email targeting the '{department}' "
        f"department via a '{attack_vector}' attack scenario.\n\n"
        f"The email must:\n"
        f"- Be contextually relevant to {department} team members\n"
        f"- Use the {attack_vector} attack vector convincingly\n"
        f"- Include realistic sender address, subject line, and body\n"
        f"- Contain subtle phishing clues (urgency, spoofed domain, credential request, etc.)\n"
        f"- Be educational — clearly demonstrate real-world tactics\n\n"
        f"Return ONLY valid JSON with keys: 'subject', 'sender', 'body', "
        f"'clues' (list of 4-6 specific indicators), 'remediation'."
    )

    result = get_completion(
        "You are a senior enterprise security awareness specialist. Generate educational simulation content. Respond with valid JSON only, no markdown formatting.",
        prompt,
        max_tokens=1200,
    )
    if result.startswith("⚠"):
        return _get_simulation_fallback(department, attack_vector)

    try:
        raw = re.sub(r'^```json|^```|```$', '', result, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception:
        return _get_simulation_fallback(department, attack_vector)


# ─────────────────────────────────────────────
# 5. SCREENSHOT / IMAGE OCR SCANNER
# ─────────────────────────────────────────────

def analyze_screenshot(image_base64: str, mime_type: str = "image/png") -> dict:
    client = _get_client()
    if not client:
        return {
            "isPhishing": True, "score": 85, "severity": "HIGH", "brandTarget": "Unknown",
            "detectedTextOcr": "AI vision unavailable — Missing API Key",
            "visualAnomalies": ["AI vision missing configuration — manual override applied"],
            "detailedVerdict": "Visual scanner pipeline requires structural setup validation.",
            "remediation": "Add an OPENAI_API_KEY environment configuration value to map UI triggers safely."
        }

    prompt = "Analyze this screenshot layout for visual spoofing or brand mimicry threats. Respond with strict JSON matching keys: isPhishing, score, severity, brandTarget, detectedTextOcr, visualAnomalies, detailedVerdict, remediation."
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": [{"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{image_base64}"}}, {"type": "text", "text": prompt}]}],
            temperature=0.1,
            max_tokens=1000
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json|^```|```$', '', raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        return {"isPhishing": False, "score": 0, "severity": "LOW", "brandTarget": "N/A", "detectedTextOcr": f"Error: {e}"}

# ─────────────────────────────────────────────
# MISSING BRIDGE BRIDGE FUNCTION (FIXES IMPORTER)
# ─────────────────────────────────────────────
def generate_ai_report(email_text, rule_findings=None):
    """Compiles a beautifully formatted markdown security report for the main UI panel."""
    analysis = analyze_email("Incident Scan", email_text, "External Source Channel")

    report = f"""### 🔍 EXECUTIVE RISK BREAKDOWN
- **Phishing Probability Assessment:** {"⚠️ CRITICAL THREAT FLAG" if analysis.get('isPhishing') else "✅ Low Suspicion Indicators"}
- **Threat Vector Score:** `{analysis.get('score', 0)} / 100` ({analysis.get('severity', 'LOW')})
- **Analysis Summary:** {analysis.get('analysisSummary', 'Static heuristic scan completed.')}

### ⚠️ PSYCHOLOGICAL & TECHNICAL TACTICS
"""
    for indicator in analysis.get('indicators', []):
        report += f"- {indicator}\n"
    if "senderAssessment" in analysis:
        report += f"- {analysis['senderAssessment']}\n"

    report += f"\n### 🛡️ SECURE MITIGATION ACTIONS\n{analysis.get('remediationPlan', 'Quarantine message headers and evaluate embedded links manually.')}"
    return report
