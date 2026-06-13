"""Beginner Mode — simplified explanations for non-technical users.

Provides plain-English, jargon-free explanations of phishing concepts
and analysis results. Designed for users who say "I'm not a security person."
"""

from __future__ import annotations


PHRASING_LIBRARY = {
    "risk_score": {
        "technical": "Risk Score",
        "simple": "Danger Level",
        "explanation": "A number that shows how likely this email is a scam. 0 = totally safe, 100 = definitely a scam.",
    },
    "phishing": {
        "technical": "Phishing",
        "simple": "Email Scam",
        "explanation": "A fake email that tries to trick you into giving away passwords, money, or personal info. Like someone wearing a costume pretending to be someone you trust.",
    },
    "malware": {
        "technical": "Malware",
        "simple": "Computer Virus / Bad Software",
        "explanation": "A bad program that can harm your computer, steal your files, or spy on you. Opening the wrong attachment can install it without you knowing.",
    },
    "url": {
        "technical": "URL / Link",
        "simple": "Web Address / Link",
        "explanation": "The address of a website. Scammers use links that look real but take you to fake websites designed to steal your info.",
    },
    "spoofing": {
        "technical": "Email Spoofing / Domain Spoofing",
        "simple": "Fake Sender Address",
        "explanation": "Scammers can make an email look like it's from someone you know, but it's really from them. Like putting a fake return address on a letter.",
    },
    "mfa": {
        "technical": "Multi-Factor Authentication (MFA / 2FA)",
        "simple": "Two-Step Verification",
        "explanation": "An extra layer of protection for your accounts. Even if someone steals your password, they can't get in without a special code sent to your phone.",
    },
    "bec": {
        "technical": "Business Email Compromise (BEC)",
        "simple": "Fake Business Request",
        "explanation": "A scam where someone pretends to be your boss or a company you work with. They ask you to send money or buy gift cards. Always double-check with the real person before sending money.",
    },
    "credentials": {
        "technical": "Credentials / Login Details",
        "simple": "Username and Password",
        "explanation": "Your login information. Never share this — real companies and websites will never ask for it by email.",
    },
    "attachment": {
        "technical": "Email Attachment",
        "simple": "File Someone Sent You",
        "explanation": "A file attached to an email. Scammers hide viruses inside documents, PDFs, and zip files. Only open files from people you trust and were expecting.",
    },
    "encryption": {
        "technical": "Encryption",
        "simple": "Secret Code / Scrambling",
        "explanation": "A way to scramble information so only the right person can read it. Like writing a message in a secret code that only your friend can decode.",
    },
    "ransomware": {
        "technical": "Ransomware",
        "simple": "File-Holding Virus",
        "explanation": "A type of virus that locks all your files and demands money to unlock them. Don't pay — contact IT or law enforcement instead.",
    },
    "aitm": {
        "technical": "Adversary-in-the-Middle (AitM) Attack",
        "simple": "Live Interception Attack",
        "explanation": "A very advanced scam where the attacker sits between you and a real website. They capture everything you type — including your password AND the code from your phone. This can even break two-step verification.",
    },
    "urgency": {
        "technical": "Urgency / Time Pressure Tactic",
        "simple": "Rush Trick",
        "explanation": "Scammers try to make you panic so you act without thinking. They say things like 'act now!' or 'your account will be closed!' Real companies don't rush you like this.",
    },
    "homograph": {
        "technical": "Homograph Attack",
        "simple": "Lookalike Characters",
        "explanation": "Using letters from other alphabets that look the same as English letters. Like using a Cyrillic 'а' instead of a Latin 'a' in a web address. They look identical but take you to a different website.",
    },
}


def translate_technical_term(term: str) -> dict:
    """Get the simplified explanation for a technical term."""
    return PHRASING_LIBRARY.get(term, {
        "technical": term,
        "simple": term,
        "explanation": f"We don't have a simple explanation for '{term}' yet.",
    })


def simplify_verdict(results: dict) -> str:
    """Return a one-sentence plain-English verdict."""
    score = results.get("risk_score", 0)
    severity = results.get("severity", "LOW")

    if score >= 75:
        return (
            "**🚨 This is a scam email.** "
            "The signs are very clear. Don't click anything, don't reply, and don't open any files. "
            "Just delete it. If you're worried about your accounts, "
            "go to their website yourself (type the address in your browser) and check."
        )
    elif score >= 50:
        return (
            "**⚠️ This email might be a scam.** "
            "Some things don't look right. Be careful — don't click links or reply. "
            "If it says it's from a company, go to their official website to check instead."
        )
    elif score >= 25:
        return (
            "**👀 A few small warning signs.** "
            "Nothing major, but take a closer look at the sender's email address "
            "and think about whether you were expecting this message."
        )
    else:
        return (
            "**✅ This email looks normal.** "
            "We didn't find any obvious signs of a scam. "
            "Even so, always be careful with unexpected emails."
        )


def get_beginner_glossary() -> list[dict]:
    """Get a glossary of common terms in beginner-friendly language."""
    return [
        {
            "term": info["simple"],
            "also_known_as": info["technical"],
            "what_it_means": info["explanation"],
        }
        for info in PHRASING_LIBRARY.values()
    ]
