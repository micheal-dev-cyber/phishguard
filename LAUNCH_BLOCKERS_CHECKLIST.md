# Launch Blockers Checklist

## CRITICAL — Must Fix Before Opening to Public

| # | Blocker | Severity | File | Fix | Minutes |
|---|---------|----------|------|-----|---------|
| 1 | **SMTP credentials missing** | CRITICAL | `.env` | Add `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`. Without these: email verification dead, password reset dead, welcome emails dead, magic link login dead. User can sign up but never receives verification or reset links. | 5 |
| 2 | **`APP_URL` not set** | CRITICAL | `.env` | Add `APP_URL=https://yourdomain.com`. All verification/reset/magic-link URLs fall back to `http://localhost:8501` — links from emails point to localhost. | 2 |
| 3 | **`PADDLE_ENVIRONMENT=sandbox` + live keys** | CRITICAL | `.env` line 10 | Change `PADDLE_ENVIRONMENT=sandbox` → `production`. Current config: sandbox environment with live (`pdl_live_*`) API keys. Checkout creates sandbox transactions that never finalize. | 1 |
| 4 | **Paddle webhook endpoint not externally reachable** | CRITICAL | `webhook.py` + infra | Paddle sends webhooks to `https://yourdomain.com/paddle-webhook`. The Flask webhook (port 5000) must be publicly accessible. Behind reverse proxy or not deployed → webhook events never arrive → subscriptions never activated. | 30 |
| 5 | **SMTP not set → email verification silently skipped** | CRITICAL | `src/auth.py` line 182 | When SMTP unconfigured, `st.info("SMTP not configured — email verification is disabled")`. User can log in directly without ever verifying email. No enforcement mechanism exists. | 0 (needs SMTP) |
| 6 | **`VIRUSTOTAL_API_KEY` not set** | HIGH | `.env` | Add `VIRUSTOTAL_API_KEY=<key>` or rename existing `VT_API_KEY` in `.env`. VT integration coded but falls back to "not configured" error on every URL check. | 1 |

## HIGH — Should Fix Before First Paid User

| # | Blocker | Severity | File | Fix | Minutes |
|---|---------|----------|------|-----|---------|
| 7 | **Paddle checkout `$29` plan has wrong feature set** | HIGH | `app.py` lines 565-600 | Plans claim "AI security reports" but AI requires OpenRouter (works) and VirusTotal (not configured). Sync plan descriptions with actual working features. | 10 |
| 8 | **Session timeout hardcoded 30 min, no warning** | HIGH | `app.py` line 453 | `1800` seconds hardcoded. User gets no warning before timeout — only a toast after. Mitigation: add 5-min warning or make configurable. | 15 |
| 9 | **No password strength meter or show/hide** | HIGH | `src/auth.py` lines 146-149 | Signup and reset forms have no visual feedback on password quality. First user may struggle to meet requirements. | 10 |
| 10 | **Onboarding wizard blocks all UI** | MODERATE | `app.py` lines 461-464 | `st.stop()` called after onboarding — user cannot skip or explore before completing. New user trapped until they complete setup. | 5 |
| 11 | **Pricing page shows features not yet working** | MODERATE | `src/auth.py` lines 860-889 | Need to verify each feature listed actually works end-to-end before charging. | 20 |

## LOW — Fix Within First Week

| # | Blocker | Severity | File | Fix | Minutes |
|---|---------|----------|------|-----|---------|
| 12 | **No analytics on signup source** | LOW | `src/auth.py` line 167 | `track_signup()` silently fails — no way to know if users came from Product Hunt, HN, or Reddit. | 30 |
| 13 | **No email delivery monitoring** | LOW | `src/email_test_backend.py` | Emails get stored in `email_log` with `delivered=0` when SMTP off. No alerting on delivery failures. | 15 |
| 14 | **`is_email_verified()` fails open** | LOW | `src/email_verify.py` line 73 | Returns `True` on any DB exception. Low risk since SMTP is the gate. | 5 |
| 15 | **Username/email cannot be changed after signup** | LOW | `src/auth.py` | No profile edit UI. User stuck with chosen username. | 20 |

## Summary
- **6 critical blockers** — all env var config (SMTP, APP_URL, PADDLE_ENVIRONMENT, VT key, webhook reachability)
- **4 high blockers** — UX sharp edges
- **3 low blockers** — polish items

**Estimated time to fix all critical: 43 minutes** (mostly env var configuration + webhook deployment).
