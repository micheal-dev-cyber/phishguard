# src/ai_analyzer.py
import os
import json
import re
import openai

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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
    if not os.getenv("OPENAI_API_KEY"):
        return _email_heuristic_fallback(subject, body, sender)

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

    if not os.getenv("OPENAI_API_KEY"):
        return _url_heuristic_fallback(url, host)

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
    """
    messages: list of {"role": "user"|"assistant", "content": str}
    """
    if not os.getenv("OPENAI_API_KEY"):
        last = messages[-1]["content"].lower() if messages else ""
        if any(w in last for w in ["spf", "dkim", "dmarc", "header"]):
            return """### 🛡️ Email Authentication (SPF, DKIM, DMARC)
- **SPF**: Lists authorized IPs that can send mail for your domain.
- **DKIM**: Adds a cryptographic signature to verify the message wasn't tampered.
- **DMARC**: Policy that tells receivers what to do when SPF/DKIM fail (reject, quarantine, or monitor).

*PhishGuard Tip*: Emails missing all three records should automatically trigger elevated threat scores."""
        if any(w in last for w in ["typosquat", "domain", "spoof", "brand"]):
            return """### 🌐 Typosquatting & Domain Spoofing
Attackers register domains visually similar to trusted brands (e.g. `paypa1.com`, `micros0ft-login.net`).

**Common tricks:**
- Character substitution: `l` → `1`, `o` → `0`, `m` → `rn`
- Subdomain abuse: `paypal.com.verify.attacker.com` — real domain is `attacker.com`
- Homograph attacks: Cyrillic letters that look identical to Latin ones"""
        return """### 👋 PhishGuard AI Copilot
I can help you with:
- Reading email headers (SPF, DKIM, DMARC)
- Identifying social engineering tactics
- Understanding typosquatting and domain spoofing
- Formulating remediation strategies

Try asking: *"Explain SPF and DKIM"* or *"What is typosquatting?"*"""

    system_prompt = """You are PhishGuard AI Copilot — a senior enterprise cyber defense assistant, malware analyst, and phishing intelligence expert.
Help analysts understand cybersecurity, phishing techniques, SPF/DKIM/DMARC flags, typosquatting, social engineering, and email/URL threat identification.
Be professional, precise, and educational. Use Markdown formatting. Only discuss cybersecurity topics."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": system_prompt}] + messages,
            temperature=0.3,
            max_tokens=800
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"*Copilot error: {e}. Tip: Always verify the raw sender domain and hover over suspect links before clicking.*"


# ─────────────────────────────────────────────
# 4. PHISHING SIMULATOR (Training Mode)
# ─────────────────────────────────────────────

SIMULATION_FALLBACKS = {
    "bank-scam": {
        "subject": "Action Required: Suspicious transactions detected on your Chase VISA",
        "sender": "chase-security-verification@chase-service-billing.cc",
        "body": """Dear Valued Cardmember,

We detected an unusual login attempt from IP 185.220.101.99 (St. Petersburg, Russia).
To prevent immediate account termination, verify your identity within 2 hours:

http://chase-verification-account-secure.cc/verify-webscr

Do not reply to this email.
Chase Fraud Protection Team""",
        "clues": [
            "Urgency tactic: 2-hour deadline triggers panic response",
            "Typosquatted domain: chase-service-billing.cc ≠ chase.com",
            "HTTP (not HTTPS) link — no SSL encryption",
            "IP address 185.220.101.99 linked to known threat actor infrastructure"
        ],
        "remediation": "Never follow bank links from emails. Verify directly at chase.com or call the number on your card."
    },
    "crypto-scam": {
        "subject": "URGENT: MetaMask Wallet Upgrade Required — Risk of Token Loss",
        "sender": "accounts-no-reply@metamask-support-portal.cc",
        "body": """Dear MetaMask User,

Due to Ethereum Core Upgrade v2.041, you must migrate your wallet.
Failure before May 31 will permanently lock your ERC-20 and ERC-721 tokens.

Enter your 12-word seed phrase to sync:
https://metamask-wallet-reverify.ru/restore

Security Team, MetaMask""",
        "clues": [
            "Requesting seed phrase — MetaMask NEVER does this",
            "Russian .ru domain — MetaMask uses metamask.io",
            "Fear of token loss used as social engineering trigger",
            "No personalized greeting — mass phishing template"
        ],
        "remediation": "Never share your seed phrase with anyone. Legitimate web3 services cannot request it."
    },
    "fake-hr": {
        "subject": "Confidential: Q2 Performance Bonus Adjustments",
        "sender": "internal-reporting@corporation-benefits-payroll.net",
        "body": """Dear Colleague,

Please review the updated performance calculations and employee bonuses for Q2.
Some adjustments apply retroactively next pay cycle.

Review here:
http://internal-hr-benefits-portal.online/salary-ledger

HR Operations Department""",
        "clues": [
            "Salary curiosity used as social engineering bait",
            ".online domain pretending to be internal corporate system",
            "Generic greeting — not personalized"
        ],
        "remediation": "Report unsolicited HR spreadsheet links to IT security. Verify via official internal portals only."
    },
    "fake-delivery": {
        "subject": "DHL: Outstanding customs fee for Parcel #402910",
        "sender": "dhl-packet-alert@dhl-tracking-system.cc",
        "body": """Dear Customer,

Your parcel #402910 has an outstanding customs balance of €1.85.
We cannot dispatch until payment is resolved.

Pay here:
http://dhl-packet-status-tracking-office.info/secure-update

DHL Express Customer Care""",
        "clues": [
            "Small fee (€1.85) designed to bypass skepticism",
            "Generic 'Dear Customer' greeting",
            ".info domain used as fake billing gateway"
        ],
        "remediation": "Never pay delivery fees from email links. Track parcels directly at dhl.com."
    }
}

def simulate_phishing(scenario_type: str) -> dict:
    if not os.getenv("OPENAI_API_KEY"):
        return SIMULATION_FALLBACKS.get(scenario_type, SIMULATION_FALLBACKS["bank-scam"])

    prompt = f"""Generate a highly realistic educational mock phishing email for scenario: '{scenario_type}'.
This is strictly for corporate cybersecurity awareness training.

Return ONLY a valid JSON object:
{{
  "subject": "Deceptive subject line bypassing standard cognitive defenses",
  "sender": "Simulated deceptive address e.g. update@paypa1-support.cc",
  "body": "Complete realistic mock email body with social engineering, links, urgency, and instructions",
  "clues": [
    "Clue 1: specific suspicious indicator inside the email",
    "Clue 2: typosquatted sender domain analysis",
    "Clue 3: social engineering emotion manipulation trigger",
    "Clue 4: technical anomaly in URL or formatting"
  ],
  "remediation": "Actionable guidance on why this was a trap and how to block it"
}}"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity trainer creating realistic phishing simulations for employee awareness. Respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json|^```|```$', '', raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        return SIMULATION_FALLBACKS.get(scenario_type, SIMULATION_FALLBACKS["bank-scam"])


# ─────────────────────────────────────────────
# 5. SCREENSHOT / IMAGE OCR SCANNER
# ─────────────────────────────────────────────

def analyze_screenshot(image_base64: str, mime_type: str = "image/png") -> dict:
    fallback = {
        "isPhishing": True,
        "score": 85,
        "severity": "HIGH",
        "brandTarget": "Unknown",
        "detectedTextOcr": "Unable to extract text — AI vision unavailable",
        "visualAnomalies": ["AI vision not configured — manual review required"],
        "detailedVerdict": "Screenshot analysis requires OpenAI API key with GPT-4o vision enabled.",
        "remediation": "Configure OPENAI_API_KEY to enable visual phishing detection."
    }

    if not os.getenv("OPENAI_API_KEY"):
        return fallback

    prompt = """Analyze this screenshot for cybersecurity inspection.
This may be a suspected login page, phishing email render, bank alert, or credential harvest form.

Perform OCR to transcribe any visible text.
Assess for: brand typosquatting, fake login forms, anomalous UI elements, low-quality logos, credential harvesting traps.

Return ONLY a valid JSON object:
{
  "isPhishing": boolean,
  "score": integer (0-100),
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "brandTarget": "brand being impersonated e.g. Microsoft, PayPal, Netflix, or Generic Suspicious",
  "detectedTextOcr": "complete transcribed text from the image",
  "visualAnomalies": ["anomaly 1", "anomaly 2", "anomaly 3"],
  "detailedVerdict": "cyber analyst explanation of the threat",
  "remediation": "steps to prevent and respond to this threat"
}"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{image_base64}"}},
                    {"type": "text", "text": prompt}
                ]}
            ],
            temperature=0.1,
            max_tokens=1000
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```json|^```|```$', '', raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        fallback["detailedVerdict"] = f"Vision analysis error: {e}"
        return fallback