import logging
import smtplib
import socket

from src.env import ENV

logger = logging.getLogger("smtp-validation")


def smtp_configured() -> bool:
    return bool(ENV.SMTP_HOST and ENV.SMTP_USER and (ENV.SMTP_PASS or ENV.SMTP_PASSWORD))


def smtp_config_status() -> dict:
    checks = {
        "SMTP_HOST": bool(ENV.SMTP_HOST),
        "SMTP_PORT": bool(ENV.SMTP_PORT),
        "SMTP_USER": bool(ENV.SMTP_USER),
        "SMTP_PASS": bool(ENV.SMTP_PASS or ENV.SMTP_PASSWORD),
        "SMTP_FROM": bool(ENV.SMTP_FROM or ENV.SMTP_USER),
        "APP_URL":   bool(ENV.APP_URL),
    }
    return {
        "configured": all(checks.values()),
        "checks": checks,
        "missing": [k for k, v in checks.items() if not v],
    }


def test_smtp_connection() -> dict:
    if not smtp_configured():
        return {"success": False, "error": "SMTP not configured (missing host, user, or password)"}
    try:
        server = smtplib.SMTP(ENV.SMTP_HOST, ENV.SMTP_PORT or 587, timeout=10)
        server.starttls()
        server.login(ENV.SMTP_USER, ENV.SMTP_PASS or ENV.SMTP_PASSWORD)
        server.quit()
        return {"success": True}
    except socket.gaierror:
        return {"success": False, "error": f"Cannot resolve hostname: {ENV.SMTP_HOST}"}
    except smtplib.SMTPAuthenticationError:
        return {"success": False, "error": "SMTP authentication failed — check username and password"}
    except smtplib.SMTPException as e:
        return {"success": False, "error": f"SMTP error: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
