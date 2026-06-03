# PhishGuard AI — Release Notes

**Project:** PhishGuard AI — Advanced Phishing Detection & Response Platform  
**Repository:** https://huggingface.co/spaces/Sabersouihi/phishguard-ai  
**Latest release:** Security audit session 3 — session management, email verification gate (2026-06-03)

---

## v0.9.2 — Security Audit Session 3 (2026-06-03)

### Security (Critical)
- **CRITICAL** — Predictable session IDs: `hashlib.sha256(username+time+ip)` replaced with `secrets.token_urlsafe(32)`
- **HIGH** — IP binding for sessions: `touch_session()` now persists the caller's IP address
- **HIGH** — Revoke sessions on password change: `set_password()` calls `revoke_all_sessions()`
- **HIGH** — Auto-login before email verification: signup no longer auto-authenticates; login checks `is_email_verified()` before granting access
- **HIGH** — Dead code removed: `verify_user_login()` and `register_premium_user()` used unsalted SHA-256 for passwords

### Bugfixes (Lint + CI)
- **F821** — Missing imports for `analyze_auth_headers` and `generate_ai_report` in `ui_analyzer.py` (runtime crashes)
- **F841** — Removed unused variables `username`, `mailbox` in app.py
- **E701/E702** — Split multi-statement lines in `ui_analyzer.py` (7 locations)
- **I001** — Auto-sorted imports across 9 files via Ruff

### Tests
- 8 new regression tests for session unpredictability, IP binding, password-change revocation, email verification flow
- Fixed `test_health_check_database` to patch the correct module

### Stats
- 10 files changed, +156/-120 lines
- 259 tests passing (251 existing + 8 new), 2 skipped (Redis unavailable)

---

## v0.9.1 — Centralized HTTP Client + Mixed Hashing Fix (2026-06-03)

### Architecture
- Created `src/http_client.py` — centralized HTTP client with retries (3 attempts, exponential backoff), configurable timeouts (default 30s), and connection pooling via `requests.Session()`
- All 22 external HTTP calls across 6 files migrated: `paddle_billing.py`, `threat_intel.py`, `osint.py`, `webhook_gateway.py`, `alerting.py`, `ui_webhook_tester.py`
- Retry on: 429, 500, 502, 503, 504 + connection errors. Backoff: 1s, 2s, 4s.

### Security (Mixed Hashing)
- **Critical** — Password reset no longer writes SHA-256 to bcrypt-verified column (`auth.py:1183`). Now uses `tenants.set_password()`.
- **Medium** — Email verification tokens no longer stored in plaintext. SHA-256 hashed before storage (`email_verify.py`).
- **Low** — Admin seed password hash: SHA-256 → bcrypt. SCIM provisioning password hash: SHA-256 → bcrypt (cosmetic — `users` table hash never verified).

### Stats
- 7 files changed, +165/-3 lines (net +162)
- All 251 tests passing (2 skipped: Redis unavailable)

---

## v0.9.0 — Daily Audit Hardening (2026-06-03)

### Security
- Fixed Python 3.10 syntax error (f-string `\'` escape → extracted variable)
- Removed hardcoded admin password `"phishguard2026"` — now env var + random fallback
- Added SQL injection protection in sender_profiler (column allowlist)
- Added SQL injection protection in SCIM PATCH (field allowlist)
- Replaced 33 bare `except: pass` with logged exceptions in email_parser
- Collapsed 10 try/except blocks into single loop in email_parser
- MD5 → SHA-256 for DOM checksums in url_sandbox
- `random` → `secrets` for referral code generation

### Quality
- Fixed `revoke_consent` undefined import in app.py
- Fixed `logger` undefined in header_auth.py
- Removed duplicate `init_db()` placeholder in database.py
- Renamed ambiguous `l` variables → `lb` in ui_design_system.py and app.py
- 392 auto-fixes applied via Ruff (unused imports, f-strings, sort ordering)
- 66 noqa directives for intentional patterns
- Ruff lint: all passing

### Tests
- Removed stale references to `tenants_mod.DB_PATH` in test_tenants.py
- Updated `tenants.DB_PATH` monkeypatch → `src.db.DB_PATH` in test_onboarding.py
- All 251 tests passing (2 skipped: Redis unavailable)

**Stats:** 104 files changed, +597/-538 lines

---

## v0.8.0 — Database Centralization (2026-05-31)

### Architecture
- Created `src/db.py` — single source of truth for DB management
- Removed 47 redundant `DB_PATH` definitions across 55 modules
- Replaced ~238 direct `sqlite3.connect()` calls with `get_connection()`
- All connections now consistently use `sqlite3.Row` + `PRAGMA foreign_keys=ON`

### Quality
- Context manager (`using_db()`) for automatic connection cleanup
- Single import pattern: `from src.db import get_connection`

**Stats:** 56 files changed, +346/-472 lines

---

## v0.7.0 — Security Audit Hardening (2026-05-31)

### Critical Fixes
- MFA secret no longer sent to external QR API (`api.qrserver.com`)
- SSRF vulnerability blocked — webhook tester validates URLs
- Password reset tokens now hashed with SHA-256 before storage
- postMessage origin validated (no wildcard `'*'`)

### High Fixes
- Timing attack protected — domain verification uses `hmac.compare_digest()`
- Broken user deletion query (`WHERE 1=0`) fixed to parameterized
- Infinite rerun loop in SOC dashboard replaced with meta refresh
- 19 files gained proper logging (was silent `except: pass`)
- `None.isdigit()` crash guarded
- IndexError on empty batch dict guarded with `next(iter(...), "text")`
- Webhook URL validation broadened to accept any HTTPS URL with warning
- Unclosed `<div>` in blur overlay properly scoped

**Stats:** 26 files changed

---

## v0.6.0 — Complete Product Restructuring (2026-05-31)

### Core Changes
- Plan consolidation: 4 duplicate plan definitions merged into single `PLANS` dict in `src/tenants.py`
- Enterprise price inconsistency fixed ($299 vs "Custom" → 0 with `custom: True`)
- Navigation: 23 tab labels shortened, sidebar guide with categories
- Dashboard: Security Score hero card, collapsible advanced tools (4 sub-tabs)
- Design system: 3 helpers (`feature_gate()`, `progress_bar()`, `metric_row()`)
- Onboarding: Reduced 6 → 5 steps, "Jump to Scan" and "Take Me to Scan" buttons
- Trust center, email templates, founder analytics, B2B gateway modules added
- 10+ new UI modules for enterprise workflows

### Cleanup
- Removed dead cached functions, stray `st.markdown("---")`, duplicate `import json`
- Git history cleaned: `git filter-branch` removed binary DB files from all 131 commits
- Force-pushed to GitHub and HuggingFace Spaces

---

## v0.5.0 — Landing Page & UX Overhaul (2026-05-31)

- Redesigned landing page, dashboard, auth UX with progressive disclosure
- Signup flow with empty states
- Professional design system implemented
- 11 critical/high bugs fixed

---

## v0.4.0 — Paddle Billing Integration (2026-05-29)

- Full Paddle subscription management (sandbox + production)
- Customer portal, invoice history, plan management
- Free-tier paywall with feature gating
- SOAR Gateway, WormGPT simulator, fingerprinting engine
- White-label reports for enterprise
- Paddle webhook route embedded in Streamlit (Tornado)
- Python 3.12 compat fix for f-string escapes
- Git history cleanup (removed temp files, backups)

---

## v0.3.0 — Enterprise Feature Expansion (2026-05-29)

- TOTP 2FA, OIDC/GitHub SSO, SSE notifications
- Scheduled scans, plugin system, granular webhook routing
- Activity timeline, brand impersonation detector
- Notification channels: Slack, Teams, Discord, PagerDuty
- SOC dashboard, white-label branding, domain verification
- Bulk CSV user management, RBAC permissions
- Health page + DB backup CLI
- 24 new test files (243 tests passing)

---

## v0.2.0 — Platform Maturity (2026-05-28/29)

- Modularized app.py (was monolithic)
- Theme toggle (dark/light), magic-link auth
- Task queue, SCIM provisioning, A/B testing framework
- Audit, performance, and monitor dashboards
- Email template editor, webhook tester
- Redis cache, data migration CLI
- API key bcrypt hashing, link checker
- CI lint pipeline + 7 new test modules
- Custom detection rules, campaigns UI, API docs
- IP allowlist, retention policies, session management
- Notification center, dashboard overhaul
- Password reset, audit log, email verification, MFA
- CI pipeline, admin lockout UI, API rate limiting
- JSON structured logging

---

## v0.1.0 — Initial MVP (2026-05-27/28)

- 12 enterprise-grade features: bcrypt+lockout, SSO OIDC, Graph API, PostgreSQL support
- Auto-incident response, SIEM integration, auto-training, weekly reports
- Onboarding wizard, PWA support
- 4 B2B monetization modules: cutoff paywall, consumption caps, white-label PDF, referral system
- Premium modules: domain monitoring, credits, training academy
- Email ingestion, alerting, feedback loop, compliance reports
- Docker support, OpenAPI docs
- Premium monetization: API keys, campaign engine, AitM detection, STIX export
- XSS/CORS/DB leak fixes (10 critical/high)
- Unified AI provider chain (Groq/OpenRouter/OpenAI/Anthropic)
- Header auth display, weekly digest
- env.py for secrets management, API proxy, pyproject.toml
- Docker HEALTHCHECK, pre-commit hooks, E2E tests
- HF Spaces deployment CI/CD, OCR/homograph detection
- Sender profiler, STIX intel sharing, URL sandbox
- Enterprise v3: extension upgrade, IMAP worker, FastAPI gateway
- Gamified leaderboard, Docker

---

## v0.0.1 — Initial Commit (2026-05-27)

- Basic Streamlit app with `set_page_config()` first
- HF Space metadata, landing page
- First deploy workflow to HuggingFace Spaces
- Initial phishing detection pipeline
