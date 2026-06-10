# PhishGuard AI — Next 14 Days Execution

> Strict execution roadmap. No new agents. No new memory stores. No infrastructure expansion. No speculative features.
> Only: product quality, onboarding, detection quality, deployment, first users, first revenue.

---

## Day 1 — SMTP + AI Provider Configuration (4h)

**Goal**: Make signup → verify → login pipeline actually work end-to-end.

### Tasks
- [ ] Create Gmail app password for SMTP (15 min)
- [ ] Set `SMTP_HOST=smpt.gmail.com`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_PORT=587` (15 min)
- [ ] Create Groq account → get API key → set `GROQ_API_KEY` (15 min)
- [ ] Set `APP_URL` to your deployment URL (5 min)
- [ ] **Test signup end-to-end**: register → receive email → verify → login → scan (30 min)
- [ ] Test password reset flow (15 min)
- [ ] Test magic link flow (15 min)
- [ ] Test welcome email (15 min)
- [ ] Fix: if verify email fails, don't silently succeed — show error to user (30 min)
- [ ] Fix: add "resend verification email" button to login page (30 min)
- [ ] Fix: verify immediately after signup without requiring re-login (45 min)

### Expected Outcome
- A stranger can: register → receive email → verify → login → scan
- First time in the project's history that the full auth pipeline works

### Files Changed
- `src/auth.py` — add resend button, fix post-signup flow
- `src/env.py` — verify config status detection
- `.env` — new values

---

## Day 2 — Remove Fake Claims + Wire SPF/DKIM/DMARC (5h)

**Goal**: Stop lying to users, start detecting real phishing signals.

### Tasks
- [ ] Remove fabricated trust bar claims from `src/auth.py:659-663` (15 min)
  - Replace with: "Beta — currently in active development"
- [ ] Remove fake testimonials from `src/auth.py:790-809` (15 min)
  - Replace with real pre-launch waitlist or remove section entirely
- [ ] Wire `header_auth.py:analyze_auth_headers()` into `detector.py:analyze_email()` (2h)
  - Import function
  - Call it on the email text
  - Merge results into the returned dict
  - Add to risk score calculation
- [ ] Test SPF/DKIM/DMARC detection with crafted test emails (1h)
  - Email with SPF=pass → should lower risk
  - Email with SPF=fail → should raise risk
  - Email with no auth headers → should note missing
- [ ] Fix `header_auth.py` to handle raw email text without actual SMTP headers (1h)
  - Most users paste emails from webmail that strip Authentication-Results
  - Add heuristic detection (display name spoofing, domain mismatch) as fallback
- [ ] Verify total risk score still calibrated 0-100 (15 min)

### Expected Outcome
- SPF/DKIM/DMARC detection live (was orphaned)
- No more fabricated social proof
- Auth header analysis contributes to risk score

### Files Changed
- `src/detector.py` — import and call `analyze_auth_headers()`
- `src/header_auth.py` — add heuristic fallback for stripped headers
- `src/auth.py` — remove fake claims

---

## Day 3 — VirusTotal URL Reputation + Demo Unlock (5h)

**Goal**: Real URL reputation + demo shows value to drive signups.

### Tasks
- [ ] Create VirusTotal account → get free API key → set `VIRUSTOTAL_API_KEY` (30 min)
- [ ] Find existing VT integration code in `src/threat_intel.py` or `src/url_intel.py` (30 min)
- [ ] Wire VT URL scanning into `detector.py:analyze_email()` (2h)
  - For each URL found, check VT reputation
  - If VT reports malicious → add risk score contribution
  - If VT not configured → skip gracefully
- [ ] Unlock full analysis in demo scan (1h)
  - Remove gate on AI narrative (if AI provider works)
  - Remove gate on OSINT results
  - Remove gate on PDF export download
  - Keep only: "Sign up to save history and get scheduled scans"
- [ ] Test VT integration with known malicious URLs (30 min)
- [ ] Test demo shows full results (30 min)

### Expected Outcome
- URL reputation via VirusTotal live
- Demo shows full value → users understand what they get by signing up
- Demo → signup conversion funnel starts working

### Files Changed
- `src/detector.py` — add VT URL checking
- `src/url_intel.py` or `src/threat_intel.py` — ensure VT function is callable
- `src/auth.py` — `_show_demo_results()` show more data

---

## Day 4 — Onboarding Flow + First Scan Wizard (6h)

**Goal**: New users don't get lost after signup.

### Tasks
- [ ] Build 3-step onboarding wizard in `src/ui_onboarding.py` (4h)
  - Step 1: "Welcome to PhishGuard" — value prop, what to expect
  - Step 2: "Scan your first email" — pre-filled example phishing email
  - Step 3: "Your results explained" — walk through risk score, severity, findings
- [ ] Add onboarding completion tracking (30 min) — don't show again
- [ ] Add "Quick Start" sample email pre-populated on main scan page (30 min)
- [ ] Add guided tour / tooltips on first visit (30 min)
- [ ] Test onboarding flow end-to-end (30 min)

### Expected Outcome
- New users complete onboarding → scan their first email within 90 seconds of signup
- First-scan conversion rate from 0% → baseline

### Files Changed
- `src/ui_onboarding.py` — full rewrite
- `src/ui_analyzer.py` — add pre-populated sample, onboarding entry point
- `app.py` — route to onboarding for new users

---

## Day 5 — Deployment to HF Spaces + Domain (4h)

**Goal**: Product is accessible at a public URL.

### Tasks
- [ ] Push code to HF Spaces repo (30 min)
- [ ] Configure all env vars in HF Spaces dashboard (30 min)
  - SMTP, GROQ_API_KEY, VIRUSTOTAL_API_KEY, APP_URL
- [ ] Verify app boots without errors (30 min)
- [ ] Set custom domain (optional — HF Spaces provides `*.hf.space`) (1h)
- [ ] Test full user flow on production URL (1h)
  - Register → verify → login → scan → see results
- [ ] Add basic uptime monitoring (UptimeRobot free tier) (30 min)

### Expected Outcome
- Product is live at a public URL
- Anyone can access, register, and use the product

### Files Changed
- `.github/workflows/deploy.yml` — verify config
- HF Spaces dashboard — env config

---

## Day 6 — Unified User Table + Quota System (5h)

**Goal**: Clean up the dual-database mess before real users arrive.

### Tasks
- [ ] Audit differences between `users` table (database.py) and `tenants` table (tenants.py) (1h)
  - `users`: username, password_hash, email, paddle_order_id, status, role, created_at
  - `tenants`: id, username, password_hash, email, plan, is_active, is_admin, created_at, notes, email_verified, mfa_enabled
- [ ] Migrate all existing data from `users` to `tenants` (1h)
- [ ] Move all queries in `database.py` to use `tenants` table (1h)
- [ ] Unify quota systems: `check_quota()` (tenants.py) and `check_scan_quota()` (database.py) (1h)
  - Use single `usage_log` table for tracking
  - Remove `scan_consumption` table
- [ ] Update all references across codebase (30 min)
- [ ] Test: register, scan, check quota (30 min)

### Expected Outcome
- Single user table, single quota system
- No data inconsistency risk

### Files Changed
- `src/tenants.py`, `src/database.py` — refactor
- `src/auth.py`, `src/ui_analyzer.py`, `src/ui_admin.py` — update references

---

## Day 7 — Paddle Billing Setup (8h)

**Goal**: Ability to accept payments.

### Tasks
- [ ] Create Paddle Billing account (30 min)
- [ ] Create 4 products matching pricing page: Trial (free), Starter ($29/mo), Business ($99/mo), Enterprise (custom) (1h)
- [ ] Note price IDs, set all 4 `PADDLE_PRICE_ID_*` env vars + `PADDLE_API_KEY`, `PADDLE_CLIENT_TOKEN`, `PADDLE_WEBHOOK_SECRET` (15 min)
- [ ] Deploy `webhook.py` (Flask app) to Render free tier or Railway (2h)
- [ ] Configure Paddle webhook URL → point to deployed webhook (30 min)
- [ ] Wire "Upgrade" buttons on pricing page → call `generate_checkout_url()` (1h)
- [ ] Test complete sandbox purchase: click buy → Paddle checkout → complete → webhook received → plan upgraded in DB (2h)
- [ ] Test subscription management: pause, cancel, resume (30 min)
- [ ] Test customer portal URL (15 min)

### Expected Outcome
- Users can pay for a subscription
- Billing pipeline works end-to-end
- Pricing page is functional, not decorative

### Files Changed
- `src/auth.py` — pricing section, wire upgrade buttons
- `src/paddle_billing.py` — verify config detection
- `webhook.py` — deploy to production

---

## Day 8 — Session Persistence + Auth Polish (4h)

**Goal**: Users don't get logged out on every page refresh.

### Tasks
- [ ] Implement persistent session cookie via Streamlit's `st.query_params` or `st.experimental_auth` (2h)
  - Store session token in URL or localStorage via JS injection
  - On page load, restore session from stored token
- [ ] Add "Remember me" checkbox on login form (1h)
  - When checked: 7-day session
  - When unchecked: current 30-min session
- [ ] Add sliding session expiration (30 min)
  - Reset TTL on each page view
- [ ] Fix: redirect to intended page after login (not always dashboard) (30 min)

### Expected Outcome
- Users stay logged in across browser refreshes
- Less friction for returning users

### Files Changed
- `src/session_manager.py` — add persistent sessions
- `src/auth.py` — login form, remember me

---

## Day 9 — Detection Quality Sprint (6h)

**Goal**: Improve detection beyond bare-minimum regex.

### Tasks
- [ ] Create test dataset of 20 known phishing emails + 20 legitimate emails (2h)
  - Use SpamAssassin public corpus or manually collect
- [ ] Run baseline benchmark: measure TPR, FPR, accuracy (1h)
- [ ] Fix top 3 false positives found in benchmark (1h)
- [ ] Add domain age check via `python-whois` (2h)
  - New domains (<30 days) → +15 risk
  - Old domains (>1 year) → -5 risk
  - WHOIS lookup failure → +5 risk (privacy protection)
- [ ] Test domain age with known examples (30 min)

### Expected Outcome
- First-ever accuracy benchmark for the detection engine
- Domain age adds real signal
- Known false positive rate

### Files Changed
- `src/detector.py` — add domain age check
- `requirements.txt` — add `python-whois`

---

## Day 10 — LLM Explanation Layer + Result UX (4h)

**Goal**: Detection results are understandable at a glance.

### Tasks
- [ ] Build `generate_threat_narrative()` that explains structured detection results in plain English (2h)
  - Input: the detection results dict
  - Output: 3-4 sentence explanation
  - Example: "This email fails SPF authentication, contains a link to a 2-day-old domain, and uses urgency language to trick you into clicking."
- [ ] Add "What to do next" recommendations based on severity (1h)
  - LOW: "No action needed"
  - MEDIUM: "Verify with sender via another channel"
  - HIGH: "Report to IT, don't click links"
  - CRITICAL: "Immediate threat — do not respond, report to security team"
- [ ] Redesign results page to be more visual and action-oriented (1h)

### Expected Outcome
- Non-technical users understand exactly what the analysis means and what to do

### Files Changed
- `src/ai_analyzer.py` — add narrative generation
- `src/ui_analyzer.py` — improved results display

---

## Day 11 — First User Recruitment + Manual Invites (4h)

**Goal**: Get the first 3-5 real users.

### Tasks
- [ ] Prepare invitation email template (30 min)
- [ ] Identify 10 target users/companies from personal network (1h)
- [ ] Send personalized invites with direct signup link (30 min)
- [ ] Offer: "Free lifetime Starter plan for early beta testers" (15 min)
- [ ] Set up user feedback channel (Slack/Discord) (30 min)
- [ ] Monitor signups in real-time (30 min)
- [ ] Follow up with anyone who signed up but didn't verify in 24h (30 min)
- [ ] Follow up with anyone who verified but didn't scan in 24h (15 min)

### Expected Outcome
- 3-5 real users registered and verified
- First scan volume from real users
- First feedback

### Files Changed
- None — this is a manual/outreach task

---

## Day 12 — Analytics + Funnel Optimization (4h)

**Goal**: Track every user step and identify drop-off.

### Tasks
- [ ] Verify all tracking events fire correctly (1h)
  - `track_signup`, `track_verification`, `track_login`, `track_first_scan`, `track_scan`
- [ ] Check `product_events` table has data from first users (30 min)
- [ ] Build a simple conversion funnel view in admin panel (1h)
- [ ] Fix any tracking gaps found (30 min)
- [ ] Analyze first real user data → identify biggest drop-off (1h)
- [ ] Fix top 1-2 funnel issues immediately (1h)

### Expected Outcome
- Data-driven understanding of user behavior
- First-ever conversion funnel with real data

### Files Changed
- `src/analytics.py` — verify all events
- `src/ui_analytics.py` or `src/ui_admin.py` — funnel view

---

## Day 13 — Bug Fixes + Polish (4h)

**Goal**: Clean up issues discovered from first real users.

### Tasks
- [ ] Review all logs from first users (1h)
- [ ] Fix any crashes, errors, or exceptions (1h)
- [ ] Fix any UX friction points reported (1h)
- [ ] Minor UI polish (spacing, loading states, error messages) (30 min)
- [ ] Send thank-you + feedback request to first users (30 min)

### Expected Outcome
- Clean logs, no critical errors
- Users report improved experience

### Files Changed
- Various — based on feedback

---

## Day 14 — Paddle Production Switch + First Revenue Attempt (4h)

**Goal**: First paying customer.

### Tasks
- [ ] Test sandbox billing end-to-end one more time (1h)
- [ ] Switch Paddle to production mode: `PADDLE_ENVIRONMENT=production` (15 min)
- [ ] Test production checkout with real card (your own) (30 min)
- [ ] Verify plan upgrade works in production (15 min)
- [ ] Verify webhook receives production events (15 min)
- [ ] Add "Upgrade" CTAs at key moments (scan results, dashboard, history) (1h)
- [ ] Offer first 10 beta users: "First month free with code BETA2026" (15 min)
- [ ] Monitor for any payment failures (15 min)
- [ ] One final end-to-end test: stranger flow (30 min)

### Expected Outcome
- Ability to accept real payments
- First paying customer within days

### Files Changed
- `.env` — `PADDLE_ENVIRONMENT=production`
- `src/auth.py` — add upgrade CTAs

---

## 14-Day Summary

| Day | Focus | Hours | Cumulative |
|-----|-------|-------|------------|
| 1 | SMTP + AI config | 4 | 4 |
| 2 | Remove fake claims + SPF/DKIM/DMARC | 5 | 9 |
| 3 | VirusTotal + demo unlock | 5 | 14 |
| 4 | Onboarding flow | 6 | 20 |
| 5 | Deploy to HF Spaces | 4 | 24 |
| 6 | Unify user tables + quota | 5 | 29 |
| 7 | Paddle billing setup | 8 | 37 |
| 8 | Session persistence + auth polish | 4 | 41 |
| 9 | Detection quality sprint | 6 | 47 |
| 10 | LLM explanation + result UX | 4 | 51 |
| 11 | First user recruitment | 4 | 55 |
| 12 | Analytics + funnel optimization | 4 | 59 |
| 13 | Bug fixes + polish | 4 | 63 |
| 14 | Paddle production + first revenue | 4 | 67 |

**Total: 67 hours across 14 days (~4.8h/day)**
