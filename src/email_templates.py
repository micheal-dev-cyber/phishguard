import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("email-templates")

BASE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<style>
  body {{ margin:0; padding:0; background:#020818; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; }}
  .wrap {{ max-width:560px; margin:0 auto; padding:32px 20px; }}
  .logo {{ font-size:22px; font-weight:800; color:#f0f6ff; letter-spacing:-0.5px; }}
  .logo span {{ color:#3b82f6; }}
  .card {{ background:linear-gradient(135deg,#0f172a,#1a1f2e); border:1px solid #1e3a5f; border-radius:16px; padding:36px 32px; margin:24px 0; }}
  h1 {{ color:#f0f6ff; font-size:22px; font-weight:700; margin:0 0 12px; }}
  p {{ color:#94a3b8; font-size:14px; line-height:1.7; margin:0 0 16px; }}
  .btn {{ display:inline-block; background:#3b82f6; color:#fff; text-decoration:none; padding:12px 28px; border-radius:10px; font-weight:600; font-size:14px; }}
  .btn:hover {{ background:#2563eb; }}
  .meta {{ color:#475569; font-size:12px; margin-top:24px; border-top:1px solid #1e293b; padding-top:16px; }}
  .meta a {{ color:#3b82f6; text-decoration:none; }}
</style></head>
<body>
<div class="wrap">
<div class="logo">🛡<span>PhishGuard</span></div>
<div class="card">
{content}
</div>
<div class="meta">
<p>© 2026 SecOpsNode · PhishGuard AI — Automated Email Security</p>
<p style='margin:0'>If you did not request this email, please ignore it. <a href='mailto:contact@phishguard.ai'>Contact support</a></p>
</div>
</div>
</body>
</html>"""


def _render(template: str, **kwargs) -> str:
    content = template.format(**kwargs)
    return BASE_HTML.format(content=content)


VERIFY_TEMPLATE = """\
<h1>Welcome to PhishGuard 🛡</h1>
<p>Please verify your email address to activate your account and start scanning for phishing threats.</p>
<p style='text-align:center;margin:24px 0'><a class="btn" href="{verify_url}">Verify Email Address</a></p>
<p style='color:#64748b;font-size:13px'>Or copy this link into your browser:</p>
<p style='color:#60a5fa;font-size:12px;word-break:break-all'>{verify_url}</p>
<p style='color:#64748b;font-size:13px;margin-top:20px'>This link expires in 24 hours. If you did not sign up for PhishGuard, please ignore this email.</p>
"""

WELCOME_TEMPLATE = """\
<h1>You're all set, {username}! 🎉</h1>
<p>Your email has been verified and your PhishGuard account is active. You now have <strong>{quota} free analyses</strong> to use.</p>
<p>Here's what to do next:</p>
<table style='width:100%;margin:16px 0'>
<tr><td style='padding:8px 0;color:#94a3b8;font-size:14px'>🔍</td><td style='padding:8px 0;color:#e2e8f0;font-size:14px'><strong>Run your first scan</strong> — paste any email to see our AI analysis</td></tr>
<tr><td style='padding:8px 0;color:#94a3b8;font-size:14px'>📊</td><td style='padding:8px 0;color:#e2e8f0;font-size:14px'><strong>Explore your dashboard</strong> — track threats and usage</td></tr>
<tr><td style='padding:8px 0;color:#94a3b8;font-size:14px'>👥</td><td style='padding:8px 0;color:#e2e8f0;font-size:14px'><strong>Invite your team</strong> — collaborate on threat detection</td></tr>
</table>
<p style='text-align:center;margin:24px 0'><a class="btn" href="{app_url}">Go to PhishGuard</a></p>
"""

RESET_TEMPLATE = """\
<h1>Reset Your Password</h1>
<p>We received a request to reset your PhishGuard password. Click the button below to set a new one.</p>
<p style='text-align:center;margin:24px 0'><a class="btn" href="{reset_url}">Reset Password</a></p>
<p style='color:#64748b;font-size:13px'>Or copy this link into your browser:</p>
<p style='color:#60a5fa;font-size:12px;word-break:break-all'>{reset_url}</p>
<p style='color:#64748b;font-size:13px;margin-top:20px'>This link expires in 1 hour. If you did not request a password reset, please ignore this email.</p>
"""

MAGIC_LINK_TEMPLATE = """\
<h1>Sign in to PhishGuard</h1>
<p>Click the button below to sign in instantly. No password needed.</p>
<p style='text-align:center;margin:24px 0'><a class="btn" href="{magic_url}">Sign In</a></p>
<p style='color:#64748b;font-size:13px'>Or copy this link into your browser:</p>
<p style='color:#60a5fa;font-size:12px;word-break:break-all'>{magic_url}</p>
<p style='color:#64748b;font-size:13px;margin-top:20px'>This link expires in 15 minutes. If you did not request this, please ignore it.</p>
"""

TRIAL_ENDING_TEMPLATE = """\
<h1>Your trial ends in {days} days</h1>
<p>Just a heads up — your PhishGuard AI trial will expire on <strong>{end_date}</strong>. After that, you'll lose access to your analysis history and threat reports.</p>
<p>Upgrade now to keep your team protected and unlock:</p>
<ul style='color:#94a3b8;font-size:14px;line-height:1.8'>
<li><strong style='color:#e2e8f0'>{next_plan_quota} analyses per month</strong> — {current_quota}× your current limit</li>
<li><strong style='color:#e2e8f0'>Priority support</strong> with faster response times</li>
<li><strong style='color:#e2e8f0'>Team access</strong> — collaborate with your security team</li>
</ul>
<p style='text-align:center;margin:24px 0'><a class="btn" href="{upgrade_url}">Upgrade Now</a></p>
"""

PAYMENT_SUCCESS_TEMPLATE = """\
<h1>Payment confirmed! 🎉</h1>
<p>Thank you for upgrading to <strong>{plan_label}</strong>. Your payment of <strong>{amount}</strong> has been processed successfully.</p>
<p>Here's what's new with your plan:</p>
<ul style='color:#94a3b8;font-size:14px;line-height:1.8'>
<li><strong style='color:#e2e8f0'>{quota} analyses per month</strong> — {features}</li>
<li><strong style='color:#e2e8f0'>All features unlocked</strong> — AI detection, OSINT, VT, reports</li>
</ul>
<p style='text-align:center;margin:24px 0'><a class="btn" href="{app_url}">Start Scanning</a></p>
"""

PAYMENT_FAILED_TEMPLATE = """\
<h1>Payment failed ⚠</h1>
<p>We were unable to process your payment of <strong>{amount}</strong> for your <strong>{plan_label}</strong> plan.</p>
<p>To avoid any interruption to your service, please update your payment method or check your billing details.</p>
<p style='text-align:center;margin:24px 0'><a class="btn" href="{billing_url}">Update Billing</a></p>
<p style='color:#64748b;font-size:13px'>If you have questions, contact us at <a href='mailto:contact@phishguard.ai'>contact@phishguard.ai</a></p>
"""


def render_html(template_name: str, **kwargs) -> str:
    templates = {
        "verify": VERIFY_TEMPLATE,
        "welcome": WELCOME_TEMPLATE,
        "reset": RESET_TEMPLATE,
        "magic_link": MAGIC_LINK_TEMPLATE,
        "trial_ending": TRIAL_ENDING_TEMPLATE,
        "payment_success": PAYMENT_SUCCESS_TEMPLATE,
        "payment_failed": PAYMENT_FAILED_TEMPLATE,
    }
    tpl = templates.get(template_name)
    if not tpl:
        logger.warning("Unknown template: %s", template_name)
        return ""
    return _render(tpl, **kwargs)


def send_html_email(to_addr: str, subject: str, html_body: str, from_addr: str = None,
                    smtp_host: str = None, smtp_port: int = None,
                    smtp_user: str = None, smtp_pass: str = None) -> dict:
    from src.env import ENV
    smtp_host = smtp_host or ENV.SMTP_HOST
    smtp_port = smtp_port or ENV.SMTP_PORT
    smtp_user = smtp_user or ENV.SMTP_USER
    smtp_pass = smtp_pass or ENV.SMTP_PASS
    from_addr = from_addr or ENV.SMTP_FROM or smtp_user

    if not smtp_user or not smtp_pass:
        return {"success": False, "error": "SMTP not configured"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info("Email sent to %s: %s", to_addr, subject)
        return {"success": True}
    except Exception as e:
        logger.error("Failed to send email to %s: %s", to_addr, e)
        return {"success": False, "error": str(e)}
