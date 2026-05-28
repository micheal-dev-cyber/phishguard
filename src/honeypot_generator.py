"""Phishing Reverse Honeypot Generator — Counter-Measure Deployment.

When an email is confirmed as phishing, this module generates a realistic
"Deception Payload": a reply email containing fabricated credentials,
credit-card numbers, or internal data designed to waste the attacker's
time and track their intent.

Uses the existing provider chain (Groq/OpenRouter/OpenAI/Anthropic)
via :func:`src.providers.get_completion`.  Falls back to deterministic
fake-data generation if no LLM is available.
"""

from __future__ import annotations

import json
import re
import random
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("phishguard-honeypot")


# ── Deterministic fake-data generators (no LLM fallback) ─────────────────


FAKE_PASSWORDS = [
    "P@ssw0rd!2024", "Secure#1Pass", "Admin!23$5", "Welcome@2024!",
    "Qwerty!2345", "Chang3M3!$", "P@$$w0rd123", "LetM3!n2025",
]

FAKE_CREDIT_CARDS = [
    "4111-1111-1111-1111", "5500-0000-0000-0004", "3400-0000-0000-009",
    "6011-0000-0000-0004", "3714-4963-5398-431", "4532-1234-5678-9012",
]

FAKE_IPS = [
    "10.0.0.1", "192.168.1.100", "172.16.0.50", "10.10.10.10",
]

FAKE_EMPLOYEES = [
    ("James Wilson", "james.wilson@phishguard-dmz.com", "VP of Finance"),
    ("Sarah Chen", "s.chen@phishguard-dmz.com", "IT Administrator"),
    ("Michael Torres", "m.torres@phishguard-dmz.com", "Security Engineer"),
    ("Emily Davis", "e.davis@phishguard-dmz.com", "Accounting Manager"),
]

SYSTEM_PROMPT = """You are a red-team deception specialist. Generate a single
realistic-looking deceptive email reply that contains fabricated credentials
or financial data to waste an attacker's time. The email must look like a real
employee accidentally replied with sensitive information.

Rules:
- Use a realistic employee name, title, and email from a DMZ domain
- Include fake but believable passwords, credit card numbers, or VPN tokens
- Sound like a busy, careless employee who accidentally CC'd the wrong person
- Never include real data — everything must be fabricated
- Return ONLY valid JSON with keys: "subject", "body", "sender_name",
  "sender_title", "sender_email", "payload_type", "payload_data"
- Keep the email under 150 words, casual tone, with a typo or two for realism"""


def _generate_deterministic() -> dict:
    """Fallback honeypot payload — no LLM needed."""
    emp = random.choice(FAKE_EMPLOYEES)
    payload_type = random.choice(["credentials", "credit_card", "vpn_token", "internal_note"])
    now = datetime.now(timezone.utc)

    if payload_type == "credentials":
        payload = {
            "username": emp[1],
            "password": random.choice(FAKE_PASSWORDS),
            "portal": "https://vpn.phishguard-internal.com/auth",
        }
        body = (
            f"Hi, sorry for the confusion. I think I accidentally CC'd the "
            f"wrong thread. Anyway, here are my login credentials as you "
            f"requested — please reset the VPN access.\n\n"
            f"Username: {payload['username']}\n"
            f"Password: {payload['password']}\n"
            f"Portal: {payload['portal']}\n\n"
            f"Let me know if the portal works on your end. Thanks!"
        )
    elif payload_type == "credit_card":
        payload = {
            "card": random.choice(FAKE_CREDIT_CARDS),
            "expiry": f"{random.randint(1,12):02d}/{now.year + 2}",
            "cvv": f"{random.randint(100, 999)}",
            "billing_zip": f"{random.randint(10000, 99999)}",
        }
        body = (
            f"Apologies for the delayed response. Attached is the purchase "
            f"order as requested. The corp card details are:\n\n"
            f"Card: {payload['card']}\n"
            f"Exp: {payload['expiry']}\n"
            f"CVV: {payload['cvv']}\n"
            f"ZIP: {payload['billing_zip']}\n\n"
            f"Please process the payment before EOD. Let me know if you "
            f"need the authorisation code too. Cheers!"
        )
    elif payload_type == "vpn_token":
        ip = random.choice(FAKE_IPS)
        payload = {
            "vpn_ip": ip,
            "token": f"{random.randint(100000, 999999)}",
            "gateway": "gw.phishguard-corp.com",
            "protocol": "WireGuard",
        }
        body = (
            f"Hey, sorry for the short notice. I'm travelling and need the "
            f"corp VPN set up on my personal laptop. Can you whitelist this "
            f"IP for the WireGuard tunnel?\n\n"
            f"My public IP: {ip}\n"
            f"One-time token: {payload['token']}\n"
            f"Gateway: {payload['gateway']}\n\n"
            f"I need it asap — client presentation in an hour. Thx!"
        )
    else:
        payload = {
            "note": f"Internal audit report Q{random.randint(1,4)} {now.year}",
            "revenue": f"${random.randint(1, 50)}.{random.randint(0,99)}M",
            "employees": str(random.randint(200, 5000)),
        }
        body = (
            f"Please see the attached quarterly summary. The board has "
            f"approved the budget increase for next fiscal.\n\n"
            f"FYI — {payload['note']}: Revenue {payload['revenue']}, "
            f"headcount {payload['employees']} as of {now.strftime('%B %Y')}.\n\n"
            f"Keep this confidential until the public filing. "
            f"Let me know if the numbers look right."
        )

    return {
        "subject": f"Re: Your request — ({payload_type})",
        "body": body,
    "sender_name": emp[0],
    "sender_email": emp[1],
    "sender_title": emp[2],
        "payload_type": payload_type,
        "payload_data": json.dumps(payload),
    }


# ── LLM-powered generation ───────────────────────────────────────────────


PROMPT_TEMPLATE = """Generate a deceptive reply email to an attacker who sent
the following phishing email. The reply should look like a real employee
accidentally leaked sensitive information.

Phishing email:
\"\"\"
{email_text}
\"\"\"

Return ONLY valid JSON with these keys:
  - subject: str (reply subject line)
  - body: str (the deceptive email body, 80-150 words)
  - sender_name: str (fake employee name)
  - sender_title: str (fake job title)
  - sender_email: str (fake email @phishguard-dmz.com)
  - payload_type: str ("credentials", "credit_card", "vpn_token", or "internal_note")
  - payload_data: str (JSON string of the fabricated secrets)

Make it casual, include a typo or two, and ensure it sounds like a real
employee accidentally replying to the wrong thread."""


def generate_honeypot(email_text: str) -> dict:
    """Generate a deception payload for *email_text*.

    Tries the LLM provider chain first; falls back to deterministic
    generation if no AI provider is configured.
    """
    try:
        from src.providers import get_completion

        result = get_completion(SYSTEM_PROMPT, PROMPT_TEMPLATE.format(email_text=email_text), max_tokens=800)
        if result.startswith("⚠"):
            logger.info("No AI provider, using deterministic honeypot fallback")
            return _generate_deterministic()

        # Strip code fences
        cleaned = re.sub(r"^```json|^```|```$", "", result, flags=re.MULTILINE).strip()
        data = json.loads(cleaned)
        # Validate required keys
        required = {"subject", "body", "sender_name", "sender_title", "sender_email",
                     "payload_type", "payload_data"}
        if not required.issubset(data.keys()):
            raise ValueError(f"Missing keys: {required - data.keys()}")
        return data
    except Exception as e:
        logger.warning("LLM honeypot failed (%s), using deterministic fallback", e)
        return _generate_deterministic()
