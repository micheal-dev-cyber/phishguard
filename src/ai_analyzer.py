# src/ai_analyzer.py
import os
import json
import re
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
    client = _get_client()
    if not client:
        return _email_heuristic_fallback(subject, body, sender, "OpenAI API Key missing")

    prompt = f"""Perform a highly rigorous Cyber Threat Analysis on this incoming email for enterprise security protection.

Sender: {sender or "Unknown External"}
Subject: {subject or "None Provided"}
Body Content:
\"\"\"
{body}
\"\"\"

Evaluate the risk score from 0 (Fully Safe) to 100 (Unquestionable malicious phishing / Credential Harvest / Spear Phishing).
Identify phishing techniques (e.g., typosquatting, sender spoofing, generic greeting, panic trigger, credential harvesting links, suspicious attachments, call to action).

Return ONLY a valid JSON object with this exact structure:
{{
  "isPhishing": boolean,
  "score": integer (0 to 100),
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "indicators": [list of specific threat indicators found],
  "senderAssessment": "analysis of sender authenticity and domain reputation",
  "analysisSummary": "expert cybersecurity explanation of the threat campaign and flags",
  "remediationPlan": "expert action steps to neutralize the threat immediately"
}}"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a senior enterprise cybersecurity analyst specializing in phishing detection. Always respond with valid JSON only, no markdown, no explanation."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=1000
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json|^```|```$', '', raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        return _email_heuristic_fallback(subject, body, sender, str(e))


# ─────────────────────────────────────────────
# 2. URL THREAT SCANNER
# ─────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        host = parsed.hostname or url.lower()
    except Exception:
        host = url.lower()

    client = _get_client()
    if not client:
        return _url_heuristic_fallback(url, host, "OpenAI API Key missing")

    prompt = f"""Review this suspicious URL from an enterprise firewall inspection.

Target URL: {url}
Extracted Hostname: {host}

Evaluate if this URL presents a cyber risk: phishing portals, banking trojans, typosquatted brand fraud, or malicious redirects.

Return ONLY a valid JSON object:
{{
  "isPhishing": boolean,
  "score": integer (0 to 100),
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "threatCategory": "e.g. Brand Impersonation / Credential Harvest, Malicious Download, Safe / Low Risk",
  "indicators": [list of malicious traits found in URL structure or domain],
  "aiExplanation": "expert security summary outlining typosquatting tricks, domain mimicry, or structural anomalies"
}}"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity URL threat analyst. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=600
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json|^```|```$', '', raw, flags=re.MULTILINE).strip()
        data = json.loads(raw)
        return {"url": url, "host": host, **data}
    except Exception as e:
        return _url_heuristic_fallback(url, host, str(e))


# ─────────────────────────────────────────────
# 3. AI COPILOT CHAT
# ─────────────────────────────────────────────

def copilot_chat(messages: list) -> str:
    client = _get_client()
    if not client:
        last = messages[-1]["content"].lower() if messages else ""
        if any(w in last for w in ["spf", "dkim", "dmarc", "header"]):
            return """### 🛡️ Email Authentication (SPF, DKIM, DMARC)
- **SPF**: Lists authorized IPs that can send mail for your domain.
- **DKIM**: Adds a cryptographic signature to verify the message wasn't tampered.
- **DMARC**: Policy that tells receivers what to do when SPF/DKIM fail.

*PhishGuard Tip*: Emails missing all three records should automatically trigger elevated threat scores."""
        return """### 👋 PhishGuard AI Copilot (Fallback Mode)
I can help you understand email headers, typosquatting, and mitigation rules. *(Connect OPENAI_API_KEY for dynamic contextual chat).*"""

    system_prompt = "You are PhishGuard AI Copilot — a senior enterprise cyber defense assistant. Use Markdown formatting."

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": system_prompt}] + messages,
            temperature=0.3,
            max_tokens=800
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"*Copilot connection error: {e}*"


# ─────────────────────────────────────────────
# 4. PHISHING SIMULATOR (Training Mode)
# ─────────────────────────────────────────────

SIMULATION_FALLBACKS = {
    "bank-scam": {
        "subject": "Action Required: Suspicious transactions detected on your Chase VISA",
        "sender": "chase-security-verification@chase-service-billing.cc",
        "body": "Dear Valued Cardmember,\n\nWe detected an unusual login attempt from IP 185.220.101.99. Verify your identity within 2 hours:\n\nhttp://chase-verification-account-secure.cc/verify-webscr",
        "clues": ["Urgency tactic: 2-hour deadline triggers panic response", "Typosquatted domain: chase-service-billing.cc", "Insecure HTTP protocol link"],
        "remediation": "Never follow financial management links from emails. Navigate to the authentic domain directly."
    },
    "crypto-scam": {
        "subject": "URGENT: MetaMask Wallet Upgrade Required — Risk of Token Loss",
        "sender": "accounts-no-reply@metamask-support-portal.cc",
        "body": "Dear MetaMask User,\n\nEnter your 12-word seed phrase to sync:\nhttps://metamask-wallet-reverify.ru/restore",
        "clues": ["Requesting private seed phrases", "Suspicious TLD tracking registry (.ru)"],
        "remediation": "Legitimate non-custodial wallets will never ask for your seed recovery phrase."
    },
    "fake-hr": {
        "subject": "Confidential: Q2 Performance Bonus Adjustments",
        "sender": "internal-reporting@corporation-benefits-payroll.net",
        "body": "Dear Colleague,\n\nPlease review your retroactive pay cycle adjustments here:\nhttp://internal-hr-benefits-portal.online/salary-ledger",
        "clues": ["Salary curiosity financial trap bait", "External .online landing space matching internal terminology"],
        "remediation": "Verify corporate financial adjustments strictly over voice or validated intranet solutions."
    },
    "fake-delivery": {
        "subject": "DHL: Outstanding customs fee for Parcel #402910",
        "sender": "dhl-packet-alert@dhl-tracking-system.cc",
        "body": "Dear Customer,\n\nYour parcel cannot dispatch until payment of €1.85 is complete:\nhttp://dhl-packet-status-tracking-office.info/secure-update",
        "clues": ["Baiting user with microtransaction friction fee", "Fake tracking layout architecture"],
        "remediation": "Track international courier accounts through the primary app environment only."
    }
}

def simulate_phishing(scenario_type: str) -> dict:
    client = _get_client()
    if not client:
        return SIMULATION_FALLBACKS.get(scenario_type, SIMULATION_FALLBACKS["bank-scam"])

    prompt = f"Generate an educational mock phishing email JSON for scenario: '{scenario_type}'."
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": "Respond with valid JSON containing keys 'subject', 'sender', 'body', 'clues' (list), and 'remediation'."}, {"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=1000
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json|^```|```$', '', raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception:
        return SIMULATION_FALLBACKS.get(scenario_type, SIMULATION_FALLBACKS["bank-scam"])


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