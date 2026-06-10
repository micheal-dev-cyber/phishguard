# PhishGuard AI — Execution Master Plan

## Phase 1: Reality Verification

### What blocks a stranger from using PhishGuard?

| # | Step | Blocker | File | Function | Fix | Effort | Impact |
|---|------|---------|------|----------|-----|--------|--------|
| 1 | Visit site | No public URL. `APP_URL` is empty string. | `src/env.py:44` | `EnvConfig` dataclass | Set `APP_URL` env var | 10 min | **CRITICAL** — user can't find the product |
| 2 | Create account | SMTP not configured. Verification email fails silently. | `src/env.py:45-49` | `SMTP_HOST/USER/PASS/FROM` all `""` | Set 4 SMTP env vars | 30 min | **CRITICAL** — registration dead-ends |
| 3 | Verify email | `APP_URL` empty → verification link is `http://localhost:8501/?verify=...` — broken | `src/auth.py:169` | `_signup_form()` | Set `APP_URL` | 10 min | **CRITICAL** — link points to localhost |
| 4 | Verify email | SMTP fails → `send_verification_email()` at `auth.py:171` prints "check your inbox" but email never arrives | `src/email_verify.py:86-91` | `send_verification_email()` → `send_html_email()` | Configure SMTP | 30 min | **CRITICAL** — user waits for email that never comes |
| 5 | Log in | Email not verified → `is_email_verified()` returns False → login blocked at `auth.py:291-292` | `src/auth.py:290-292` | `_login_form()` | Depends on SMTP fix | — | **CRITICAL** — user can never log in |
| 6 | Log in | Magic link also fails — SMTP not configured | `src/auth.py:222-240` | Magic link `send_email()` | Depends on SMTP fix | — | **CRITICAL** — all auth flows dead |
| 7 | Log in | Password reset also fails — SMTP not configured | `src/auth.py:370-387` | `_reset_form()` → `send_reset_email()` | Depends on SMTP fix | — | **CRITICAL** — can't recover account |
| 8 | Run scan | Demo mode works (no auth needed). **This is the only functional path.** | `src/auth.py:460-600` | `_demo_scan_page()` | — | 0 | **Already works** |
| 9 | Run scan | AI analysis returns fallback message — all 4 AI provider keys empty | `src/providers.py:40, 72, 100, 124` | `_groq_completion()` → `if not ENV.GROQ_API_KEY: return None` | Set `GROQ_API_KEY` | 10 min | **HIGH** — no AI threat narrative |
| 10 | Run scan | VirusTotal URL check disabled — key empty | `src/env.py:33` | `VIRUSTOTAL_API_KEY = ""` | Set `VIRUSTOTAL_API_KEY` | 10 min | **MEDIUM** — no URL reputation |
| 11 | Understand results | No onboarding flow — user dropped into dashboard with no guidance | `app.py:446-449` | `show_onboarding` flag never set after signup | Wire `show_onboarding=True` in `auth.py:294` | 30 min | **MEDIUM** — users don't understand value |
| 12 | Understand results | SPF/DKIM/DMARC parser (`header_auth.py`) never called from `detector.py:analyze_email()` | `src/detector.py:405-455` | `analyze_email()` ignores `analyze_auth_headers()` | Call `analyze_auth_headers()` in `analyze_email()` | 1 hr | **HIGH** — header analysis is weak |
| 13 | Return next day | Streamlit session state cleared on browser refresh. No "remember me" / persistent session. | `app.py:434-443` | Session timeout — 30 min inactivity cleans all keys | Add `st.query_params` or localStorage token | 4 hr | **MEDIUM** — user re-logs in every visit |
| 14 | Pay | `PADDLE_API_KEY` empty → `paddle_configured()` returns False | `src/paddle_billing.py:40-42` | `is_configured()` | Set `PADDLE_API_KEY` + `PADDLE_CLIENT_TOKEN` | 30 min | **CRITICAL** — $0 revenue |
| 15 | Pay | `PADDLE_PRICE_ID_STARTER` etc. all empty → `get_price_id()` returns None | `src/paddle_billing.py:45-46` | `get_price_id()` | Set 4 `PADDLE_PRICE_ID_*` env vars | 30 min | **CRITICAL** — no prices to charge |
| 16 | Trust product | Fake trust bar: "10,000+ scans", "99% detection rate", "90+ vendor correlation" — fabricated | `src/auth.py:659-663` | `_hero_page()` trust bar HTML | Remove fabricated claims | 15 min | **CRITICAL** — destroys credibility immediately |
| 17 | Trust product | Fake testimonials: "Sarah Chen, CISO, FinTech Corp" — doesn't exist | `src/auth.py:790-809` | `_hero_page()` testimonials HTML | Remove or replace with real beta users | 15 min | **CRITICAL** — lying to visitors |
| 18 | Trust product | "SOC 2 Compliant" claim on landing page — no evidence | `src/auth.py:831` | Trust items — "SOC 2 Compliant" | Remove or qualify | 10 min | **HIGH** — legal liability |
| 19 | Trust product | "Penetration Tested" claim — untested codebase | `src/auth.py:833` | Trust items — "Penetration Tested" | Remove | 10 min | **HIGH** — legal liability |
| 20 | Use product | Two user tables (`users` + `tenants`) — data inconsistency risk | `src/database.py:37-47`, `src/tenants.py:80+` | `init_db()` + `init_tenants()` | Unify to `tenants` | 3 hr | **MEDIUM** — technical debt |
| 21 | Use product | Two quota systems (`check_quota` + `check_scan_quota`) — conflicting limits | `src/tenants.py` (check_quota), `src/database.py` (check_scan_quota) | Redundant | Unify to `usage_log` | 2 hr | **LOW** — both return reasonable defaults |

### Blockers by Category

| Category | Count of CRITICAL | Count of HIGH | Count of MEDIUM |
|----------|-------------------|---------------|-----------------|
| **Auth flow** (signup → verify → login) | 6 | 0 | 0 |
| **Trust & credibility** | 2 | 3 | 0 |
| **Billing** (configure Paddle) | 2 | 0 | 0 |
| **Detection quality** | 0 | 2 | 1 |
| **Onboarding & retention** | 0 | 0 | 2 |
| **Technical debt** | 0 | 0 | 2 |

**The product has 10 CRITICAL blockers. 8 of them are env var configuration (~2 hours). 2 are code changes (remove fake claims, ~30 min).**

---

## Phase 3: Codebase Simplification

### Archive Immediately (zero impact on critical path)

These files cause no user-facing changes when removed. Move to `archive/` branch.

| File | LOC | Reason |
|------|-----|--------|
| `agents/*` (entire directory) | ~15,000 | 70+ agents, 0 data to process |
| `memory/*` (entire directory) | ~5,000 | 23 memory stores, no users |
| `phases/*` (entire directory) | ~3,000 | 79 pipeline phases, no data |
| `orchestrator/*` | ~2,000 | Agent orchestrator, no agents needed |
| `siem_webhook.py` | ~200 | No SIEM customer |
| `soar_gateway.py` | ~200 | No SOAR customer |
| `scim.py` | ~200 | No enterprise directory |
| `campaign_engine.py` | ~400 | No training customer |
| `honeypot_generator.py` | ~200 | No deployment |
| `aitm_detector.py` | ~300 | No active user base |
| `stix_exporter.py` | ~100 | No threat intel partners |
| `threat_intel_sharing.py` | ~200 | No sharing partners |
| `b2b_gateway.py` | ~200 | No B2B sales |
| `enterprise_api.py` | ~300 | No API consumers |
| `plugin_manager.py` | ~200 | No plugin ecosystem |
| `webhook_routing.py` | ~200 | No webhook consumers |
| `inbox_scanner.py` | ~200 | IMAP not deployed |
| `weekly_report.py` | ~150 | No weekly data |
| `workspace.py` | ~300 | No team customers |
| `custom_rules.py` | ~200 | No power users |
| `ip_allowlist.py` | ~200 | No enterprise tenant |
| `gdpr.py` | ~100 | No EU users |
| `mfa.py` | ~200 | No users |
| `ratelimit.py` | ~200 | No traffic |
| `retention.py` | ~200 | No data to retain |
| `ui_bulk_users.py` | ~150 | No bulk users |
| `ui_webhook_routing.py` | ~150 | No webhooks |
| `ui_plugins.py` | ~100 | No plugins |
| `ui_channels.py` | ~100 | No channels |
| `ui_soc_dashboard.py` | ~200 | No SOC team |
| `ui_scheduler.py` | ~150 | No scheduled tasks |
| `ui_founder_analytics.py` | ~200 | Merge into admin |
| `ui_performance.py` | ~100 | Premature |
| `ui_audit_log.py` | ~100 | No audit data |
| `ui_task_queue.py` | ~100 | No tasks |
| `ui_email_templates.py` | ~150 | No enterprise |
| `ui_domain_verify.py` | ~100 | No enterprise |
| **Total** | **~30,000** | |

### Disable Components (comment out or gate behind admin check)

| Component | File | Why |
|-----------|------|-----|
| SSO login button | `src/auth.py:329-335` | OAuth not configured, shows broken SSO UI |
| MFA form | `src/auth.py:400-436` | No users need MFA |
| Task queue worker | `app.py:371-401` | Starts worker thread for 0 tasks |
| Scheduler | `app.py:404-409` | Schedules recurring scans for 0 users |
| Inbox Scanner tab | `app.py:749-862` | Requires user to enter IMAP creds manually |
| Campaigns tab | `app.py:690-698` | No training/simulation customers |
| Training tab | `app.py:690-698` | No training customers |
| Developers tab | `app.py:690-698` | No API consumers |
| SOC view | `app.py:732` | No SOC team |

### Features to Hide (from non-admin users)

| UI Element | File | Hide From |
|------------|------|-----------|
| "Inbox Scanner" radio option | `app.py:730` | All non-admin |
| "Campaigns" tab | `app.py:690-698` | All non-admin |
| "Training" tab | `app.py:690-698` | All non-admin |
| "Developers" tab | `app.py:690-698` | All non-admin |

---

## Phase 6: Execution Backlog

### P0 — Do Immediately (within 48 hours)

| # | Task | Effort | Depends On | Business Impact |
|---|------|--------|------------|-----------------|
| P0.1 | Remove fake trust bar claims (`auth.py:659-663`) | 15 min | None | **Critical** — visitor trust restored |
| P0.2 | Remove fake testimonials (`auth.py:790-809`) | 15 min | None | **Critical** — credibility restored |
| P0.3 | Remove fake SOC 2 / Pen Tested claims (`auth.py:831-833`) | 10 min | None | **Critical** — legal liability removed |
| P0.4 | Set `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` env vars | 30 min | Gmail/email account | **Critical** — all auth flows unblocked |
| P0.5 | Set `APP_URL` env var (production URL) | 10 min | Deployment URL | **Critical** — verification links work |
| P0.6 | Set `GROQ_API_KEY` env var | 10 min | Groq account (free) | **High** — AI analysis enabled |
| P0.7 | Set `VIRUSTOTAL_API_KEY` env var | 10 min | VirusTotal account (free) | **Medium** — URL reputation |
| P0.8 | Deploy to public URL (HF Spaces / Railway / Fly.io) | 4 hr | P0.4-P0.7 | **Critical** — product is findable |
| P0.9 | Wire onboarding flag after first login (`auth.py:294` add `show_onboarding=True`) | 30 min | None | **Medium** — new users guided |

**P0 total: ~6 hours. Unblocks every critical auth path.**

### P1 — This Week

| # | Task | Effort | Depends On | Business Impact |
|---|------|--------|------------|-----------------|
| P1.1 | Wire `analyze_auth_headers()` into `detector.py:analyze_email()` | 1 hr | None | **High** — SPF/DKIM/DMARC detection enabled |
| P1.2 | Create free Paddle Sandbox account + configure price IDs | 2 hr | None | **Critical** — payment infrastructure ready |
| P1.3 | Set `PADDLE_API_KEY`, `PADDLE_CLIENT_TOKEN`, `PADDLE_PRICE_ID_*` env vars | 30 min | P1.2 | **Critical** — checkout flow functional |
| P1.4 | Test full signup → verify → login → scan flow end-to-end | 2 hr | P0.1-P0.9 | **Critical** — verify product works for real users |
| P1.5 | Add "Resend verification email" button to login page | 1 hr | P0.4 (SMTP) | **Medium** — users who lose email can retry |
| P1.6 | Create `/demo` public URL (deep-link to demo mode, no auth required) | 1 hr | None | **High** — shareable demo for social posts |
| P1.7 | Post on Hacker News "Show HN: I built a free phishing email analyzer" | 1 hr | P0.8 (deployed) | **High** — acquisition spike |
| P1.8 | Post on Reddit r/cybersecurity + r/blueteamsec + r/selfhosted | 1 hr | P0.8 (deployed) | **Medium** — targeted audience |

**P1 total: ~10 hours. Product is functional + first growth pushes.**

### P2 — Next Week

| # | Task | Effort | Depends On | Business Impact |
|---|------|--------|------------|-----------------|
| P2.1 | Launch on Product Hunt | 3 hr | P0.8 + P1.2-P1.3 | **High** — biggest launch channel |
| P2.2 | Add simple "How PhishGuard scored this email" explanation in results | 4 hr | None | **Medium** — users understand output value |
| P2.3 | Create 3 LinkedIn posts (launch story, tech deep-dive, threat landscape) | 2 hr | P0.8 | **Medium** — professional audience |
| P2.4 | Direct outreach: 20 SMB IT managers on LinkedIn (personalized message) | 3 hr | None | **Medium** — first conversations |
| P2.5 | Cold email: 50 local businesses in founder's network | 2 hr | P0.8 | **Medium** — personal network |
| P2.6 | Add persistent session ("remember me" checkbox on login, localStorage token) | 4 hr | None | **Medium** — retention improves |
| P2.7 | Unify `users` table → `tenants` table, drop `database.py:init_db()` user table | 3 hr | None | **Low** — data consistency |
| P2.8 | Unify quota: drop `check_scan_quota()`, keep `tenants.check_quota()` | 2 hr | None | **Low** — quota consistency |
| P2.9 | Create 1-pager benchmark: measure detection rate against known phishing dataset | 4 hr | None | **High** — credibility data for launch |

**P2 total: ~27 hours. Growth engine running + trust infrastructure built.**

### P3 — Later (after first 10 paying users)

| # | Task | Effort | Why Later |
|---|------|--------|-----------|
| P3.1 | Set `PADDLE_ENVIRONMENT=production` | 30 min | Wait until first paying user sandbox-test succeeds |
| P3.2 | Set `OPENROUTER_API_KEY` fallback | 10 min | Only needed if Groq rate limits |
| P3.3 | Wire Paddle webhook for production | 2 hr | Only needed if webhook never tested |
| P3.4 | Add team/workspace features | 6 hr | Only if a buyer asks for it |
| P3.5 | Archive AICOS system | 4 hr | No impact on users; wait until P2 items done |
| P3.6 | Archive enterprise features | 2 hr | No impact on users; wait until P2 items done |
| P3.7 | SSO configuration | 4 hr | Only if an enterprise buyer asks |
| P3.8 | Inbox Scanner IMAP | 4 hr | Only if users request it |
| P3.9 | API access for paying Business tier | 4 hr | Only if a Business subscriber asks |

**P3 total: ~28 hours. All optional, customer-driven features.**

### Summary

| Priority | Tasks | Total Effort | When |
|----------|-------|-------------|------|
| **P0** | 9 tasks | ~6 hours | Immediately |
| **P1** | 8 tasks | ~10 hours | This week |
| **P2** | 9 tasks | ~27 hours | Next week |
| **P3** | 9 tasks | ~28 hours | After first 10 paying users |
| **Total** | **35 tasks** | **~71 hours** | |
