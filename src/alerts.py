# src/alerts.py
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from src.db import get_connection
from src.env import ENV


def _get_smtp_config():
    return {
        "host":     ENV.SMTP_HOST,
        "port":     ENV.SMTP_PORT,
        "username": ENV.SMTP_USER,
        "password": ENV.SMTP_PASS,
        "from":     ENV.SMTP_FROM or ENV.SMTP_USER,
    }


def _init_alerts_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            email      TEXT NOT NULL,
            subject    TEXT NOT NULL,
            severity   TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            sent_at    TEXT NOT NULL,
            success    INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


def _log_alert(username, email, subject, severity, risk_score, success=True):
    _init_alerts_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO alert_log (username, email, subject, severity, risk_score, sent_at, success)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (username, email, subject, severity, risk_score,
         datetime.now().isoformat(), 1 if success else 0)
    )
    conn.commit()
    conn.close()


def _build_html(username, severity, risk_score, preview, keyword_hits,
                suspicious_urls, timestamp):
    color = "#ff4444" if severity == "CRITICAL" else "#ff8800"
    emoji = "🔴" if severity == "CRITICAL" else "🟠"

    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0d1117; color: #e2e8f0; margin: 0; padding: 0; }}
  .wrap {{ max-width: 580px; margin: 0 auto; padding: 40px 20px; }}
  .header {{ background: #0f172a; border: 1px solid #1e3a5f;
             border-radius: 16px 16px 0 0; padding: 32px;
             border-bottom: 3px solid {color}; text-align: center; }}
  .logo {{ font-size: 1.5rem; font-weight: 800; color: #60a5fa;
           letter-spacing: -0.02em; margin-bottom: 4px; }}
  .badge {{ display: inline-block; background: {color}22; color: {color};
            border: 1px solid {color}55; border-radius: 100px;
            padding: 6px 18px; font-size: 12px; font-weight: 700;
            letter-spacing: 0.08em; text-transform: uppercase;
            margin-top: 12px; }}
  .body {{ background: #0f172a; border: 1px solid #1e3a5f;
           border-top: none; padding: 32px; border-radius: 0 0 16px 16px; }}
  .score-row {{ display: flex; align-items: center; gap: 16px;
                background: #1a0a0a; border: 1px solid {color}44;
                border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; }}
  .score-num {{ font-size: 3rem; font-weight: 900; color: {color};
                line-height: 1; min-width: 80px; }}
  .score-label {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
  .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr;
                gap: 12px; margin-bottom: 24px; }}
  .meta-box {{ background: #111827; border: 1px solid #1e3a5f;
               border-radius: 10px; padding: 16px; }}
  .meta-val {{ font-size: 1.4rem; font-weight: 800; color: #e2e8f0; }}
  .meta-key {{ font-size: 11px; color: #475569; margin-top: 2px;
               text-transform: uppercase; letter-spacing: 0.08em; }}
  .preview {{ background: #111827; border: 1px solid #1e3a5f;
              border-left: 3px solid {color}; border-radius: 10px;
              padding: 16px 20px; font-family: monospace; font-size: 13px;
              color: #94a3b8; margin-bottom: 24px; line-height: 1.6; }}
  .actions {{ background: #111827; border: 1px solid #1e3a5f;
              border-radius: 10px; padding: 20px; margin-bottom: 24px; }}
  .actions-title {{ font-size: 13px; font-weight: 700; color: #60a5fa;
                    margin-bottom: 12px; }}
  .action-item {{ font-size: 13px; color: #94a3b8; padding: 4px 0; }}
  .footer {{ text-align: center; font-size: 11px; color: #334155;
             margin-top: 24px; line-height: 1.7; }}
  .ts {{ font-size: 11px; color: #334155; text-align: center;
         margin-top: 16px; font-family: monospace; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">🛡 PhishGuard AI</div>
    <div style="font-size:13px;color:#64748b;margin-top:4px">
      Threat Alert for <strong style="color:#94a3b8">{username}</strong>
    </div>
    <div class="badge">{emoji} {severity} THREAT DETECTED</div>
  </div>

  <div class="body">
    <div class="score-row">
      <div>
        <div class="score-num">{risk_score}</div>
        <div class="score-label">/ 100 Risk Score</div>
      </div>
      <div>
        <div style="font-size:1.1rem;font-weight:700;color:{color}">{severity}</div>
        <div style="font-size:13px;color:#64748b;margin-top:4px">
          Threat level classified as <strong>{severity.lower()}</strong> risk.
          Immediate review recommended.
        </div>
      </div>
    </div>

    <div class="meta-grid">
      <div class="meta-box">
        <div class="meta-val">{keyword_hits}</div>
        <div class="meta-key">Keyword Hits</div>
      </div>
      <div class="meta-box">
        <div class="meta-val">{suspicious_urls}</div>
        <div class="meta-key">Suspicious URLs</div>
      </div>
    </div>

    <div style="font-size:12px;color:#475569;margin-bottom:8px;
                text-transform:uppercase;letter-spacing:0.08em">
      Email Preview
    </div>
    <div class="preview">{preview[:300]}{'...' if len(preview) > 300 else ''}</div>

    <div class="actions">
      <div class="actions-title">⚡ Recommended Actions</div>
      {'<div class="action-item">→ Do NOT click any links in this email</div>' if suspicious_urls > 0 else ''}
      <div class="action-item">→ Do NOT reply or provide any credentials</div>
      <div class="action-item">→ Forward to your IT security team</div>
      <div class="action-item">→ Mark as phishing/spam in your email client</div>
      <div class="action-item">→ Log into PhishGuard for the full analysis report</div>
    </div>

    <div class="ts">
      Detected at {timestamp} · Automated alert by PhishGuard AI
    </div>
  </div>

  <div class="footer">
    You received this alert because threat notifications are enabled<br>
    on your PhishGuard account. Log in to manage alert settings.
  </div>
</div>
</body>
</html>
"""


def send_threat_alert(username: str, email: str, results: dict) -> bool:
    """
    Send a threat alert email. Called automatically after analysis
    when severity is CRITICAL or HIGH and the user has an email set.

    Returns True if sent successfully, False otherwise.
    """
    if not email:
        return False

    severity   = results.get("severity", "")
    risk_score = results.get("risk_score", 0)

    # Only alert for HIGH and CRITICAL
    if severity not in ("CRITICAL", "HIGH"):
        return False

    cfg = _get_smtp_config()
    if not cfg.get("username") or not cfg.get("password"):
        # SMTP not configured — silently skip
        return False

    keyword_hits   = results.get("total_keyword_hits", 0)
    suspicious_urls = results.get("suspicious_url_count", 0)
    preview        = results.get("email_preview", "")[:300]
    timestamp      = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    emoji          = "🔴" if severity == "CRITICAL" else "🟠"
    subject        = f"{emoji} PhishGuard Alert: {severity} threat detected (Score {risk_score}/100)"

    html_body = _build_html(
        username, severity, risk_score, preview,
        keyword_hits, suspicious_urls, timestamp
    )

    # Plain text fallback
    text_body = (
        f"PhishGuard AI — Threat Alert\n\n"
        f"User: {username}\n"
        f"Severity: {severity}\n"
        f"Risk Score: {risk_score}/100\n"
        f"Keyword Hits: {keyword_hits}\n"
        f"Suspicious URLs: {suspicious_urls}\n\n"
        f"Preview:\n{preview}\n\n"
        f"Detected at: {timestamp}\n\n"
        f"Log into PhishGuard for the full analysis."
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"PhishGuard AI <{cfg['from']}>"
    msg["To"]      = email

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(cfg["from"], [email], msg.as_string())
        _log_alert(username, email, subject, severity, risk_score, success=True)
        return True
    except Exception:
        _log_alert(username, email, subject, severity, risk_score, success=False)
        return False


def get_alert_log(username: str = None, limit: int = 50) -> list:
    """Get recent alert history. Pass username=None for all (admin view)."""
    _init_alerts_table()
    conn = get_connection()
    c = conn.cursor()
    if username:
        c.execute(
            """
            SELECT username, email, subject, severity, risk_score, sent_at, success
            FROM alert_log WHERE username = ?
            ORDER BY id DESC LIMIT ?
            """,
            (username, limit)
        )
    else:
        c.execute(
            """
            SELECT username, email, subject, severity, risk_score, sent_at, success
            FROM alert_log ORDER BY id DESC LIMIT ?
            """,
            (limit,)
        )
    rows = c.fetchall()
    conn.close()
    return rows
