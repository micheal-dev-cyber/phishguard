# PhishGuard AI — Production Readiness Plan

> This is a deployment checklist. Not an architecture document. Every item is verified against the actual codebase.

---

## 1. SMTP — Email Delivery

**Status**: NOT CONFIGURED

### Required Variables
| Variable | Value | Source |
|----------|-------|--------|
| `SMTP_HOST` | `smtp.gmail.com` | `src/env.py:45` |
| `SMTP_PORT` | `587` | `src/env.py:46` |
| `SMTP_USER` | (your Gmail) | `src/env.py:47` |
| `SMTP_PASS` | (Gmail app password) | `src/env.py:48` |
| `SMTP_FROM` | (your Gmail) | `src/env.py:50` |

### Checklist
- [ ] Create Gmail app password (Google Account → Security → App Passwords)
- [ ] Set all 5 env vars in deployment environment
- [ ] Test: register a user — verify welcome email arrives
- [ ] Test: request password reset — verify reset email arrives
- [ ] Test: send magic link — verify it arrives
- [ ] **Risk**: Gmail rate-limit (500 emails/day for free accounts). For production, migrate to SendGrid/Mailgun/Resend (small cost)

### Code Paths That Send Email
- `src/auth.py:171` — verification email
- `src/auth.py:234` — magic link email
- `src/password_reset.py:82-87` — password reset email
- `src/email_verify.py:86-91` — verification email (via template)
- `src/email_verify.py:94-99` — welcome email
- `src/alerting.py` — alert emails (if called)

### Effort: 1 hour

---

## 2. AI Providers

**Status**: NOT CONFIGURED

### Options (all work with existing code)
| Provider | Cost | Rate Limit | Setup Time |
|----------|------|------------|------------|
| Groq | Free | 30 req/min | 5 min |
| OpenRouter | Free | Credits/day | 5 min |
| OpenAI | Paid (~$0.15/1M tokens) | 500 RPM | 5 min |
| Anthropic | Paid (~$3/M tokens) | 50 RPM | 5 min |

### Priority Chain (in `src/providers.py:150-155`)
1. Groq (free) ← set this first
2. OpenRouter (free)
3. OpenAI (paid, best quality)
4. Anthropic (paid, best quality)

### Checklist
- [ ] Create Groq account (groq.com) → API key → set `GROQ_API_KEY`
- [ ] Verify: `get_available_provider()` returns `"groq"`
- [ ] Test: `ai_analyzer.py:analyze_email()` returns LLM result not heuristic fallback
- [ ] Test: `jury_engine.py:evaluate_linguistic_jury()` uses LLM
- [ ] (Optional) Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` for higher quality

### Effort: 1 hour

---

## 3. Billing (Paddle)

**Status**: FULLY CODED, COMPLETELY UNTESTED

### Required Setup
1. Create Paddle Billing account (paddle.com)
2. Create products for each plan tier
3. Set environment variables:

| Variable | Value |
|----------|-------|
| `PADDLE_API_KEY` | From Paddle dashboard |
| `PADDLE_CLIENT_TOKEN` | From Paddle dashboard |
| `PADDLE_WEBHOOK_SECRET` | Generated in Paddle webhook settings |
| `PADDLE_PRICE_ID_STARTER` | Price ID from Paddle for Starter plan |
| `PADDLE_PRICE_ID_BUSINESS` | Price ID for Business plan |
| `PADDLE_PRICE_ID_CONSULTANT` | Price ID for Consultant plan |
| `PADDLE_PRICE_ID_ENTERPRISE` | Price ID for Enterprise plan |
| `PADDLE_ENVIRONMENT` | `sandbox` for testing, `production` for live |

### Checklist
- [ ] Create Paddle seller account
- [ ] Create 4 products matching pricing page
- [ ] Configure webhook endpoint (see below)
- [ ] Set all env vars
- [ ] Test `is_configured()` returns True
- [ ] Test `generate_checkout_url()` returns a valid URL
- [ ] Complete test purchase in sandbox
- [ ] Verify webhook receives `transaction.completed` event
- [ ] Verify `handle_webhook_event()` upgrades user plan in DB
- [ ] Test subscription management (pause, cancel, resume)
- [ ] Set `PADDLE_ENVIRONMENT=production` when ready

### Webhook Deployment

`webhook.py` is a Flask app that must be deployed separately from the Streamlit app (HF Spaces doesn't support persistent HTTP listeners).

**Options:**
1. **Render** (free tier): Deploy `webhook.py` as a web service
2. **Railway** (free tier): Same
3. **Fly.io** (free tier): Same
4. **AWS Lambda** via Zappa: More complex but cheapest at scale

Webhook URL format: `https://your-webhook-service.com/paddle-webhook`

### Effort: 8 hours

---

## 4. Authentication

**Status**: FUNCTIONALLY WORKING, MULTIPLE CONFIG ISSUES

### Verified Issues
- [ ] **Signup works**: Account creation, password hashing (bcrypt), basic validation all work
- [ ] **Email verification**: Sends via SMTP (blocked by #1)
- [ ] **Login**: Username/password, lockout after 5 attempts, MFA support all work
- [ ] **Password reset**: Token-based, hashed storage, works correctly (despite confusing column naming)
- [ ] **Magic link**: Works if SMTP configured
- [ ] **Session management**: `session_manager.py` creates/tracks/expires sessions

### Fixes Required
- [ ] Fix email verification flow — user should be able to login immediately with a "verify later" grace period
- [ ] Unify `users` table (database.py) and `tenants` table (tenants.py) — two user tables exist with different schemas
- [ ] Add session refresh/sliding expiration
- [ ] Test SSO flow (OAuth callback handler at `app.py:25-48`)
- [ ] Remove fake testimonials and trust claims

### Effort: 8 hours (unifying tables) + 2 hours (session fixes)

---

## 5. Database Migrations

**Status**: DUAL DATABASE LAYERS, NO PRODUCTION MIGRATION

### Current State
| Database | Location | Purpose | Status |
|----------|----------|---------|--------|
| SQLite `phishguard.db` | `data/phishguard.db` | All data | Active |
| PostgreSQL | External | Future state | Not connected |

### Schema Count: 40+ tables across `tenants.py.init_tenants()` and `database.py.init_db()`

### Migration Script
`src/migrate.py` exists and supports SQLite → PostgreSQL migration. Not yet tested.

### Checklist
- [ ] Set PostgreSQL env vars (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`)
- [ ] Run `python -m src.migrate to-postgres`
- [ ] Verify all 27 listed tables migrate successfully
- [ ] Test app with PostgreSQL backend
- [ ] Create rollback plan
- [ ] Document connection string for production

### Risk
SQLite is fine for single-user beta. For multi-user production, switch to PostgreSQL BEFORE first user signs up.

### Effort: 4 hours

---

## 6. Environment Variables

**Status**: PARTIALLY DOCUMENTED

### Complete Env Var Map

| Category | Variables | Required? | Set? |
|----------|-----------|-----------|------|
| **SMTP** | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | YES | No |
| **App** | `APP_URL` | YES | No |
| **AI** | `GROQ_API_KEY` or `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` | YES | No |
| **Threat Intel** | `VIRUSTOTAL_API_KEY` | Optional | No |
| **Billing** | `PADDLE_API_KEY`, `PADDLE_CLIENT_TOKEN`, `PADDLE_WEBHOOK_SECRET`, 4x `PADDLE_PRICE_ID_*` | For billing | No |
| **Admin** | `ADMIN_PASSWORD` | Optional | No |
| **PostgreSQL** | `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` | For PG | No |
| **SSO** | `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_AUTHORITY`, `OAUTH_REDIRECT_URI` | Optional | No |
| **Graph API** | `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET` | Optional | No |
| **SIEM** | `SIEM_SPLUNK_HEC_URL`, `SIEM_SPLUNK_HEC_TOKEN`, etc. | Optional | No |

### Checklist
- [ ] Document all 40+ env vars in `.env.example` (already done)
- [ ] Add validation on startup — log warnings for missing required vars
- [ ] Create deployment-specific `.env.production` template
- [ ] Verify `src/env.py:log_config_status()` reports accurately

### Effort: 2 hours

---

## 7. Backups

**Status**: CODE EXISTS, NO SCHEDULE

### Existing Code
`src/health.py` has:
- `run_backup()` — copies SQLite DB to `backups/` directory
- `list_backups()` — shows available backups
- `restore_backup()` — restores from backup

### Checklist
- [ ] Set up cron job: `python -m src.health backup` daily
- [ ] For HF Spaces: backups must be uploaded to external storage (S3, HF Dataset) — Spaces storage is ephemeral
- [ ] For PostgreSQL: use `pg_dump` via cron
- [ ] Test restore procedure
- [ ] Document recovery steps in incident response plan

### Effort: 2 hours

---

## 8. Monitoring

**Status**: CODE EXISTS, NOT DEPLOYED

### Existing Infrastructure
- `src/health.py`: System checks (DB, disk, task queue, Redis)
- `src/json_logger.py`: Structured logging
- `src/sse_notifier.py`: Server-sent events for real-time notifications (Streamlit compatible)

### Required Setup
- [ ] Deploy health endpoint (expose `/health` via webhook.py or separate health service)
- [ ] Set up uptime monitoring (UptimeRobot, BetterUptime — free tier)
- [ ] Set up error tracking: Sentry (free tier, `sentry-sdk`)
- [ ] Configure `LOG_LEVEL=INFO` (default)
- [ ] Set up application performance monitoring (optional: Prometheus + Grafana)

### Key Metrics to Track
- Scan latency (50th, 95th, 99th percentile)
- Detection pipeline pass/fail rate
- AI provider response time
- Paddle webhook processing time
- User signup → verification → first scan conversion
- Daily/weekly active users

### Effort: 4 hours

---

## 9. Logging

**Status**: WORKING, NEEDS CONFIGURATION

### Current State
- `src/json_logger.py`: JSON-structured logging module
- All major modules use `logging.getLogger(__name__)`
- No log aggregation or search

### Checklist
- [ ] Set `LOG_LEVEL=INFO` in production
- [ ] Configure log aggregation (optional: Axiom, Logtail, or ELK)
- [ ] Ensure no secrets/PII in logs
  - Risk: `src/env.py:153` exposes truncated API keys in logs
  - Risk: Email content logged in `save_analysis()`
- [ ] Add request ID to all log entries for tracing
- [ ] Add scan/event correlation IDs

### Effort: 2 hours

---

## 10. Security Hardening

**Status**: MULTIPLE GAPS

### Checklist
- [ ] **Remove fabricated social proof** — `src/auth.py:659-663` (hero page trust claims) and lines 790-809 (fake testimonials)
- [ ] **Hash password reset tokens** — `src/password_reset.py:44` — Actually already hashed (confirmed). Just rename `token` column to `token_hash` for clarity.
- [ ] **Unify user tables** — `users` (database.py) and `tenants` (tenants.py) are separate schemas with different columns. Pick one.
- [ ] **Rate limiting on API** — `src/ratelimit.py` exists. Wire it into API endpoints.
- [ ] **Add CSRF tokens** — Streamlit apps are somewhat protected but verify.
- [ ] **Set secure cookie flags** — HF Spaces handles this, verify for custom domains.
- [ ] **SQL injection** — All queries use parameterized statements. Verified clean.
- [ ] **Secrets exposure** — No secrets in source code. All read from env vars. Clean.

### Effort: 8 hours (unifying tables) + 4 hours (rate limiting) + 2 hours (social proof)

---

## Summary Checklist

| Category | Est. Hours | Done? |
|----------|-----------|-------|
| SMTP configuration | 1 | ☐ |
| AI provider configuration | 1 | ☐ |
| Billing (Paddle) + webhook | 8 | ☐ |
| Auth fixes (unify tables, session refresh) | 10 | ☐ |
| Database migration (SQLite → PG) | 4 | ☐ |
| Environment variables documentation | 2 | ☐ |
| Backup schedule | 2 | ☐ |
| Monitoring + uptime | 4 | ☐ |
| Logging configuration | 2 | ☐ |
| Security hardening | 14 | ☐ |
| **Total** | **48h** | |
