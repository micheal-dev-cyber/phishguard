# PhishGuard AI — Top 20 Blockers

> Each blocker is ranked by impact on the goal of: **first user → first active user → first retained user → first paying customer**.
> 
> Impact (1-10), Effort (hours), ROI = Impact / Effort * 100

---

## Tier 1 — CRITICAL PATH (Blockers that prevent ANY user)

### #1 — No SMTP Configuration
- **Impact**: 10 — Email verification, password reset, magic link, welcome emails, billing receipts all require SMTP. Zero transactional email works.
- **Code**: `src/email_templates.py:143` — sends `send_html_email` which returns `{"success": False, "error": "SMTP not configured"}` when SMTP_USER or SMTP_PASS is empty
- **Effort**: 1 hour (create Gmail app password, set env vars)
- **ROI**: 1000
- **Fix**: Set `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` env vars with a working Gmail app password

### #2 — No APP_URL Configured
- **Impact**: 10 — Verification links, password reset links, magic links all use `ENV.APP_URL` which defaults to empty string. Links point to `http://localhost:8501` or worse, `/?verify=TOKEN` with no base URL.
- **Code**: `src/auth.py:169` — `base_url = getattr(ENV, "APP_URL", "http://localhost:8501")`
- **Effort**: 10 minutes
- **ROI**: 6000
- **Fix**: Set `APP_URL` to production URL

### #3 — No AI Provider Configured
- **Impact**: 9 — AI features silently degrade. `ai_analyzer.py` falls back to weak heuristics. `jury_engine.py` skips LLM calls. Threat narratives, phishing simulations, AI copilot all return "No AI provider available" or weak fallback.
- **Code**: `src/providers.py:196-205` — `get_available_provider()` returns "none" when no key is set
- **Effort**: 1 hour (create Groq/OpenRouter free account, set key)
- **ROI**: 900
- **Fix**: Set `GROQ_API_KEY` (free tier, 30 req/min) or `OPENROUTER_API_KEY` (free tier)

### #4 — No Production Deployment
- **Impact**: 9 — The app exists only on localhost. No stranger can discover, access, or use it. No domain, no SSL (HF Spaces provides), no public URL.
- **Code**: N/A — deployment infrastructure
- **Effort**: 4 hours (deploy to HF Spaces or VPS)
- **ROI**: 225
- **Fix**: Deploy to HF Spaces with proper env config, or set up a VPS with Docker

### #5 — Password Reset Token Hash Mismatch (AUTHENTICATION BROKEN)
- **Impact**: 9 — The password reset flow has a critical bug. `password_reset.py:44` stores the token as `token_hash` (SHA-256). But `create_reset_token` receives `token_hash` and stores it in the `token` column. Meanwhile, `verify_reset_token` queries by `token = ?` with the hashed value. This should work **if** the column name is cosmetic. **Let me verify** by re-reading: line 36-49 shows `create_reset_token` generates a `token`, hashes it to `token_hash`, and inserts `token_hash` into the `token` column. Then `verify_reset_token` (line 52-70) hashes the incoming token and queries `WHERE token = ?` with the hash. So this is functionally correct despite confusing naming.
- **CORRECTION**: Reset flow IS actually correct. Remove this blocker. Replace with:
- **Fixed Issue**: `password_reset.py:44` stores the token hash but column is named `token` not `token_hash` — confusing but functional. However, `email_verify.py:40` stores token hash in a column properly named `token_hash`. Inconsistent naming but both work.

### #5 (REVISED) — Email Verification Never Sends
- **Impact**: 9 — Signup flow creates account then calls `send_verification_email()`. But SMTP is not configured → email never sends → user can never verify → user can never log in (login is blocked before verification).
- **Code**: `src/auth.py:161-178` — sends verification email, then redirects to login which blocks unverified users
- **Effort**: 1 hour (SMTP config)
- **ROI**: 900
- **Fix**: Configure SMTP (see Blocker #1)

---

## Tier 2 — ACTIVATION BLOCKERS (Prevent first scan → first "aha" moment)

### #6 — SPF/DKIM/DMARC Parser Orphaned
- **Impact**: 8 — `header_auth.py` has a fully functional email authentication parser. It can detect spoofing via SPF, DKIM, DMARC headers. **It is never called** from `detector.py:405` (`analyze_email`). The detection engine misses the single most important phishing signal.
- **Code**: `src/header_auth.py:89` — `analyze_auth_headers(text)` exists but is never called from `src/detector.py:455`
- **Effort**: 2 hours (import and integrate into detection pipeline)
- **ROI**: 400
- **Fix**: Add `from src.header_auth import analyze_auth_headers` to `detector.py` and call it in `analyze_email()`

### #7 — VirusTotal Not Configured
- **Impact**: 7 — URL reputation checking exists in code but `VIRUSTOTAL_API_KEY` is empty. All URL scans skip VT lookup. The landing page promises "Every URL cross-referenced against 90+ security vendors in real-time" — this is false.
- **Code**: `src/env.py:33` — `VIRUSTOTAL_API_KEY: str = ""`
- **Effort**: 1 hour (create free VT account, get API key)
- **ROI**: 700
- **Fix**: Set `VIRUSTOTAL_API_KEY`

### #8 — No Domain Age / WHOIS Lookup
- **Impact**: 6 — `src/osint.py` exists but has no WHOIS/domain age implementation. The OSINT engine is non-functional without paid API subscriptions (SecurityTrails, WhoisXML, etc.)
- **Code**: `src/osint.py` — exists but relies on external APIs not configured
- **Effort**: 8 hours (integrate whois library or free WHOIS API)
- **ROI**: 75
- **Fix**: Add `python-whois` library and implement domain age check in detection pipeline

### #9 — Fake Social Proof on Landing Page
- **Impact**: 7 — Hero page claims "10,000+ scans analyzed", "99% detection rate", "Trusted by security teams worldwide" with named fake testimonials. If a technical buyer discovers these are fabricated (there are 0 scans, 0 users), trust is irreversibly destroyed.
- **Code**: `src/auth.py:659-663` — hardcoded trust claims
- **Effort**: 30 minutes
- **ROI**: 1400
- **Fix**: Remove or replace with honest claims ("Beta — currently in active development")

### #10 — No Onboarding Flow
- **Impact**: 6 — After signup, user is dumped into the blank authenticated dashboard with no guidance, no tutorial, no sample data, no "first scan" prompt.
- **Code**: Missing — `src/ui_onboarding.py` exists but likely empty or minimal
- **Effort**: 8 hours (build welcome wizard with sample email, guided first scan)
- **ROI**: 75
- **Fix**: Build 3-step onboarding: (1) Welcome + value prop, (2) Guided demo scan, (3) First real scan

---

## Tier 3 — RETENTION BLOCKERS (Prevent day 2+ return)

### #11 — No Email Notification System Working
- **Impact**: 6 — `src/alerting.py` and `src/notifications.py` exist but can't send emails (no SMTP). Users won't return without alerts, digests, or re-engagement emails.
- **Effort**: Part of SMTP config (already counted)
- **ROI**: N/A (blocked by #1)

### #12 — Demo Results Too Limited
- **Impact**: 5 — Demo scan shows risk score, URL count, keyword hits but hides full analysis behind "Sign up for free" CTA. Since signup can't complete (no SMTP), user sees a teaser with no path to full value.
- **Code**: `src/auth.py:540-600` — `_show_demo_results()` limits visible data
- **Effort**: 2 hours (unlock more demo data, reduce friction)
- **ROI**: 250
- **Fix**: Show full analysis in demo (including AI narrative if available), gate only PDF export and history

### #13 — No Session Persistence
- **Impact**: 5 — Streamlit sessions are in-memory. User logs in → session stored in `st.session_state` → browser refresh or server restart = logged out. No persistent auth token/cookie.
- **Code**: Streamlit limitation by design
- **Effort**: 4 hours (implement session cookie via query params or st.experimental_auth)
- **ROI**: 125
- **Fix**: Store session token in URL query param or browser localStorage via st.markdown + JS

### #14 — No Scheduled Scanning / IMAP Integration Broken
- **Impact**: 4 — `workers/imap_worker.py` exists for automated inbox scanning. Not deployed. No recurring scan scheduling.
- **Code**: Workers not running — would need a separate process
- **Effort**: 8 hours (deploy IMAP worker separately)
- **ROI**: 50
- **Fix**: Deploy IMAP worker as separate service (or cron job)

---

## Tier 4 — MONETIZATION BLOCKERS (Prevent first payment)

### #15 — Paddle Billing Not Configured
- **Impact**: 10 — `paddle_billing.py:474` lines of integration code. None of it works. No API key, no price IDs, no webhook, no deployed webhook receiver. Zero billing capability.
- **Code**: `src/paddle_billing.py:41` — `is_configured()` returns False → `generate_checkout_url()` returns None
- **Effort**: 8 hours (create Paddle account, set up products, deploy webhook, test)
- **ROI**: 125
- **Fix**: Create Paddle account, configure products, deploy Flask webhook, test end-to-end

### #16 — Pricing Page Shows Unpurchasable Plans
- **Impact**: 5 — Pricing section shows 4 plans with prices ("$29/mo", "$99/mo"). "Start Free Trial" button leads to signup. No "Buy" or "Upgrade" button actually creates a Paddle checkout. User clicks pricing → can't buy.
- **Code**: `src/auth.py:863-888+` — static pricing HTML
- **Effort**: 4 hours (after Paddle is configured, wire buttons to `generate_checkout_url`)
- **ROI**: 125
- **Fix**: Replace static pricing with live Paddle checkout links

### #17 — No Usage Metering
- **Impact**: 3 — `database.py:389-456` has scan consumption code, but it's separate from the tenant-based plan limits in `tenants.py:318-329`. Two quota systems exist and may conflict.
- **Code**: Dual quota systems (`scan_consumption` table + `usage_log` table + `check_quota()` in tenants.py)
- **Effort**: 4 hours (unify to single quota system)
- **ROI**: 75
- **Fix**: Merge `check_quota()` and `check_scan_quota()` into one function

---

## Tier 5 — GROWTH BLOCKERS (Prevent scale)

### #18 — Analytics Data Empty
- **Impact**: 4 — `analytics.py` tracks events into `product_events` table. Zero events recorded (0 users). Cannot optimize what you cannot measure.
- **Effort**: N/A — blocked by having users
- **ROI**: N/A

### #19 — No SEO / Discoverability
- **Impact**: 3 — Streamlit apps are not indexed well by search engines. No SSR, no meta tags beyond basic, no blog, no content marketing.
- **Effort**: 16 hours (build marketing site separately)
- **ROI**: 19
- **Fix**: Create a separate landing page (Next.js or simple HTML) for SEO, link to app

### #20 — No Multi-Tenant Isolation
- **Impact**: 2 — Tenant data separation relies on `username` foreign keys. No true data isolation. One SQL query mistake = cross-tenant data leak.
- **Code**: All queries filter by `username` — correct practice but no RLS or schema-level isolation
- **Effort**: 16 hours (implement schema-per-tenant or row-level security)
- **ROI**: 12
- **Fix**: Not urgent at 0 users. Defer until >100 users.

---

## Ranked by ROI

| Rank | Blocker | Impact | Effort (h) | ROI | Tier |
|------|---------|--------|------------|-----|------|
| 1 | No APP_URL | 10 | 0.2 | 6000 | Critical |
| 2 | No SMTP | 10 | 1 | 1000 | Critical |
| 3 | No AI Provider | 9 | 1 | 900 | Critical |
| 4 | Email verify never sends | 9 | 1 | 900 | Critical |
| 5 | No VirusTotal key | 7 | 1 | 700 | Activation |
| 6 | No Production Deployment | 9 | 4 | 225 | Critical |
| 7 | Fake social proof | 7 | 0.5 | 1400 | Activation |
| 8 | SPF/DKIM/DMARC orphaned | 8 | 2 | 400 | Activation |
| 9 | Demo results too limited | 5 | 2 | 250 | Retention |
| 10 | Paddle not configured | 10 | 8 | 125 | Monetization |
| 11 | No session persistence | 5 | 4 | 125 | Retention |
| 12 | Pricing page unpurchasable | 5 | 4 | 125 | Monetization |
| 13 | No domain age / WHOIS | 6 | 8 | 75 | Activation |
| 14 | No onboarding flow | 6 | 8 | 75 | Activation |
| 15 | Dual quota systems | 3 | 4 | 75 | Monetization |
| 16 | IMAP worker not deployed | 4 | 8 | 50 | Retention |
| 17 | No SEO / discoverability | 3 | 16 | 19 | Growth |
| 18 | No multi-tenant isolation | 2 | 16 | 12 | Growth |
| 19 | Analytics data empty | 4 | 0 | — | Growth |
| 20 | No domain age service | 6 | 8 | 75 | Activation |

---

## Summary

**Fix these 5 things first** (total: ~6 hours) and the product goes from completely non-functional to minimally viable:

1. Set `APP_URL`, `SMTP_*`, `GROQ_API_KEY`, `VIRUSTOTAL_API_KEY` env vars (~1h)
2. Wire `header_auth.py` into `detector.py` (~2h)
3. Remove fake social proof (~0.5h)
4. Unlock demo results (~2h)
5. Deploy to HF Spaces with env config (~4h, independent)
