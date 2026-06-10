import pytest
from src.detector import analyze_email

AUTH_PASS = (
    "Authentication-Results: spf=pass smtp.mailfrom=company.com; "
    "dkim=pass header.d=company.com; dmarc=pass header.from=company.com\n"
    "Received-SPF: pass (company.com)\n"
    "DKIM-Signature: v=1; d=company.com\n"
)

NO_AUTH = "\n"

BENCHMARK_PHISHING = [
    ("urgent password reset", NO_AUTH + """
From: support@paypal-security.xyz
Reply-To: phisher@gmail.com
Subject: URGENT: Your account has been suspended

Dear customer,

Your PayPal account has been suspended due to suspicious activity.
You must verify your account immediately or it will be permanently closed.

Click here to restore access: http://paypal-security.xyz/reset

This is your final warning. Act now.
""", 50, 100),
    ("CEO fraud / BEC", NO_AUTH + """
From: ceo@company-legit.com
Reply-To: ceo.private@gmail.com
Subject: Urgent wire transfer needed

Hi,

I'm in a meeting and need you to process a wire transfer of $47,500
to the vendor below immediately. This is confidential.

Account: 83920181
Routing: 021000021

Let me know when it's done.
""", 40, 100),
    ("fake invoice with malware", NO_AUTH + """
From: billing@fake-invoice.net
Subject: Overdue Invoice INV-9241

Hi,

Your invoice INV-9241 is past due. Please review the attached document
and process payment within 24 hours.

Download here: http://192.168.1.1/invoice.exe

Failure to pay will result in service termination.
""", 60, 100),
    ("generic low-effort spam", NO_AUTH + """
From: winner@lotto-intl.xyz
Subject: YOU ARE A WINNER

Congratulations! You have won $5,000,000 in the international lottery.
Click to claim your prize now!!!
""", 25, 100),
    ("brand impersonation with urgency", NO_AUTH + """
From: security@netflix-account.com
Subject: Your Netflix account is on hold

Netflix,

We were unable to process your latest payment.
Update your billing info within 48 hours to keep your account.

https://netflix-account.com/update

The Netflix Team
""", 45, 100),
]

BENCHMARK_LEGITIMATE = [
    ("normal newsletter", AUTH_PASS + """
From: newsletter@company.com
Subject: This month's product updates

Hi there,

We're excited to share our latest product updates with you.
Check out the new features we've been working on.

Best,
The Team
""", 0, 20),
    ("personal email from friend", AUTH_PASS + """
From: friend@gmail.com
Subject: Lunch next week?

Hey,

Are you free for lunch next Tuesday? I was thinking we could
try that new Italian place downtown. Let me know what works.

Cheers,
Alex
""", 0, 10),
    ("professional work email", AUTH_PASS + """
From: colleague@corporate.com
Subject: Q3 report review

Team,

Please review the Q3 financial report by Friday.
Let me know if you have any questions.

Thanks,
Manager
""", 0, 15),
    ("receipt from known service", AUTH_PASS + """
From: receipts@amazon.com
Subject: Your Amazon.com order #123-4567890

Thanks for your order!
Your package will arrive on Monday.

Items ordered: USB-C Hub
Total: $24.99

Amazon Customer Service
""", 0, 25),
    ("password reset from legitimate service", AUTH_PASS + """
From: noreply@github.com
Subject: Password reset request

We received a request to reset your GitHub account password.
If you made this request, click the link below:

https://github.com/password_reset?token=abc123

If you didn't request this, you can safely ignore this email.
The GitHub Team
""", 0, 25),
]


class TestDetectionBenchmark:
    @pytest.mark.parametrize("name,text,min_score,max_score", BENCHMARK_PHISHING)
    def test_phishing_caught(self, name, text, min_score, max_score):
        result = analyze_email(text)
        s = result["risk_score"]
        assert min_score <= s <= max_score, (
            f"[{name}] score {s} outside expected [{min_score}, {max_score}]"
        )
        assert result["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "risk_score" in result
        assert "severity" in result
        assert "urls_found" in result
        assert "suspicious_urls" in result

    @pytest.mark.parametrize("name,text,min_score,max_score", BENCHMARK_LEGITIMATE)
    def test_legitimate_not_flagged(self, name, text, min_score, max_score):
        result = analyze_email(text)
        s = result["risk_score"]
        assert min_score <= s <= max_score, (
            f"[{name}] score {s} outside expected [{min_score}, {max_score}]"
        )

    def test_all_phishing_higher_than_all_legitimate(self):
        phishing_scores = [analyze_email(t)["risk_score"] for _, t, _, _ in BENCHMARK_PHISHING]
        legit_scores = [analyze_email(t)["risk_score"] for _, t, _, _ in BENCHMARK_LEGITIMATE]
        assert min(phishing_scores) > max(legit_scores), (
            f"Overlap: min_phish={min(phishing_scores)} max_legit={max(legit_scores)}"
        )

    def test_returns_all_expected_keys(self):
        result = analyze_email("test email")
        expected = {
            "risk_score", "severity", "severity_color",
            "keyword_matches", "total_keyword_hits",
            "urls_found", "suspicious_urls",
            "has_attachments", "url_count", "suspicious_url_count",
            "header_analysis", "auth_headers",
            "attachment_analysis", "language_analysis",
            "languages_detected", "kit_fingerprinting",
        }
        actual = set(result.keys())
        missing = expected - actual
        extra = actual - expected
        assert not missing, f"Missing keys: {missing}"
        assert not extra, f"Unexpected keys: {extra}"
