# PhishGuard AI — Complete Product Restructuring Analysis

> **Date:** 2026-05-31
> **Status:** Analysis complete, critical changes implemented, remaining items documented in roadmap
> **Tests:** 251 passed, 2 skipped (Redis)

---

## Part 1: Executive Summary

**Current state:** PhishGuard AI is a security SaaS with 109 Python files (17,912 LOC), 561 functions, 48+ DB tables, 23 navigation tabs, 5 pricing tiers, and 0 test coverage for the core database layer.

**Core problems:**
- No centralized data layer — `sqlite3.connect(DB_PATH)` duplicated in ~80 files
- 23 flat navigation tabs create choice paralysis
- 4 duplicate plan definitions with inconsistent pricing (enterprise = $299 vs "Custom")
- Free vs Trial confusion — two separate plans serving the same "get started" function
- 2 separate quota systems (tenants vs database modules) tracking scan usage independently
- Mixed auth hashing (bcrypt + SHA256) across the codebase
- Duplicate import patterns throughout app.py

**Target architecture:** Clerk (auth) → Supabase (DB) → Resend (email) → Trigger.dev (jobs) → Paddle (billing), implemented as provider-agnostic adapter layers over 3–6 months.

**Immediate changes made:** 6 critical bug fixes, plan consolidation into single source of truth, tab label simplification, dashboard redesign with Security Score hero card, design system enhancements (3 new helpers), onboarding optimized to 5 steps with jump-to-scan actions.

---

## Part 2: UX & Product Audit Findings

### Navigation Architecture (Phase 3)
- **23 tabs** for admin users, 18 for regular users — vastly exceeds Streamlit's horizontal tab capacity
- No hierarchical grouping — threat detection, account management, and admin tools are interleaved
- Tab labels use inconsistent formatting: some with emoji prefix, some without
- No active tab highlighting in sidebar navigation

### Plan & Pricing (Phase 4)
- **5 plans:** Free, Trial, Starter, Professional, Business, Consultant, Enterprise
- **4 duplicate definitions:** tenants.py, ui_founder_analytics.py, onboarding.py, b2b_gateway.py
- Free ($0) and Trial ($0) serve the same purpose — Trial is redundant
- Enterprise priced at $299 in one place, "Custom" in another
- Feature lists duplicated across b2b_gateway.py TIERS dict and tenants.py PLANS dict
- Hardcoded feature arrays in upgrade section of app.py

### Dashboard (Phase 5)
- Current dashboard has flat structure: checklist → quick actions → usage → stats → activity → SOC → threat log → weekly digest → export → compliance
- No security posture summary card at top
- Compliance reports mixed into main dashboard rather than in dedicated tab
- SOC analytics unnecessarily hidden behind expander on the dashboard
- No recommendations or feature discovery for new users

### Design System (Phase 6)
- Solid CSS token system in `ui_design_system.py` (32 dark tokens, 32 light tokens)
- Good component library: card(), stat_card(), badge(), section_title(), url_box(), empty_state()
- Missing: feature_gate() (now added), progress_bar() (now added), metric_row() (now added)
- Inconsistencies: some UI uses inline styles, some uses CSS classes

### Onboarding (Phase 7)
- 6-step wizard takes too long for power users
- No "skip to scan" option on early steps
- Good progress visualization with dots and progress bar
- Already well-polished with clean dark theme

### Code Quality (Phase 9)
- Critical: `quota_status` NameError in billing tab (FIXED)
- Critical: White-label check inconsistency (FIXED)
- Dead cached functions never called (REMOVED)
- Duplicate `import json as _json_stix` in PDF export (REMOVED)
- Empty `if` block at app.py line 33 (REMOVED)
- Stray `st.markdown("---")` after Full Analytics button (REMOVED)
- F-string SQL injection risks in ~20 modules (identified, not fixed — requires ORM layer)

---

## Part 3: Database & Schema Audit

### Current Schema
- ~48 database tables across tenants.db and analyses.db
- `tenants` table in tenants.db: primary user/plan/credential store
- `analyses` table in analyses.db: scan history
- Separate tables for: sessions, api_keys, audit_log, subscriptions, notifications, feedback, alerts, campaigns, workspaces, sso_tokens, custom_rules, ip_allowlist, retention_policy, etc.

### Issues
- No foreign key relationships enforced
- No migration system — schema is defined by CREATE TABLE IF NOT EXISTS in each module
- Two separate DB files (tenants.db, analyses.db) with no cross-DB joins
- `scan_quota` in database.py is a separate tracking system from `quotas` in tenants.py

### Migration Path
- Phase 1: Unified schema with Supabase (or SQLite migration system)
- Phase 2: Alembic-style migrations
- Phase 3: Foreign key enforcement
- Phase 4: Prepared statements to eliminate SQL injection risks

---

## Part 4: Navigation Restructure (Implemented)

### Changes Made
1. **Tab labels shortened:** "🔍 Analyze" → "🔍 Scan", "🧪 Training" → "🎓 Training", "⚡ Performance" → "⚡ Perf", "📖 API Docs" → "📖 API", "📡 SOC" → "📡 SOC", "📋 Timeline" → "📅 Timeline"
2. **Sidebar navigation guide added:** Groups tabs into Detection, Analysis, Security, Learning, Account, Admin categories with section headers, user info, and plan badge
3. **Dashboard tab content redesigned** as landing experience

### Category Groups
| Category | Tabs |
|---|---|
| Detection | Scan, Inbox |
| Analysis | Dashboard, Copilot, History |
| Security | Threat Intel, SOC, Timeline, Webhooks |
| Learning | Training, Leaderboard |
| Account | Billing, Settings, Team |
| Admin | Admin, Audit, Performance, M&A |

---

## Part 5: Plan Consolidation (Implemented)

### Current Plans (single source of truth in `src/tenants.py`)

| Plan | Price/Month | Price/Year | Scans | Key Features |
|---|---|---|---|---|
| Free | $0 | $0 | 5 | basic_scan, pdf_export |
| Trial | $0 | $0 | 50 | basic_scan, pdf_export, advanced_scan |
| Starter | $19 | $190 | 100 | basic_scan, pdf_export, advanced_scan |
| Professional | $49 | $490 | 500 | + team, api_access, batch_analysis |
| Business | $99 | $990 | 2000 | + sso, audit_log, custom_rules, white_label |
| Enterprise | Custom | Custom | ∞ | all features, sla, dedicated_support |
| Consultant | $149 | $1490 | 5000 | + white_label, client_reports, custom_branding |

### Recommended Restructure (Phase 2)
```
Trial → {14 days, 50 scans} → converts to Starter, Professional, or Business
Plans: Free (5 scans → upgrade gate) | Pro ($49) | Business ($99) | Enterprise (Custom)
Remove: Consultant (merge into Business + white_label add-on)
Remove: Starter (merge into Pro)
```

### Changes Made
- All 4 duplicate definitions consolidated into `src/tenants.py::PLANS`
- `ui_founder_analytics.py` now imports from PLANS for MRR calc
- `onboarding.py` references PLANS for Stripe `unit_amount`
- `b2b_gateway.py` TIERS sources features from PLANS
- `app.py` upgrade section references PLANS features

---

## Part 6: Dashboard Redesign (Implemented)

### New Layout
1. **Onboarding Checklist** — collapsed if complete, progress bar if <5/5
2. **Security Score Hero Card** — large score display (0–100) with color-coded health status (🟢 Healthy / 🟡 Moderate / 🔴 At Risk)
3. **Quick Actions Row** — 3 buttons: 🔍 Analyze, 📥 Inbox, 🤖 Copilot
4. **Usage Bar** — plan name + color-coded progress bar + used/limit count + upgrade link at ≥70%
5. **Metric Cards** — Total Scans, Avg Risk Score, Threats Found, Critical, Safe %
6. **Recent Threats Timeline** — color-coded severity with emoji, score, timestamp
7. **7-Day Summary** — weekly scan count, avg score, critical/high counts
8. **Advanced Tools** — collapsed expander with 4 sub-tabs: SOC Analytics, Threat Log, Export Data, Compliance Reports

---

## Part 7: Design System Enhancement (Implemented)

### New Helpers Added
- **`feature_gate(feature, plan, plans, upgrade_callback)`** — Renders upgrade CTA if plan lacks feature; identifies next tier that includes it
- **`progress_bar(pct, color, height)`** — Reusable gradient progress bar component
- **`metric_row(metrics)`** — Renders a row of stat cards from a list of (value, label, color) tuples

### CSS Refinements
- Alert/notification styling improvements for consistency

---

## Part 8: Onboarding Optimization (Implemented)

### Changes
- Reduced from 6 to 5 steps
- Step 1: "Welcome" — added "🚀 Jump to Scan" action button
- Step 3: "Your First Scan" — added "🔍 Take Me to Scan" direct link
- Steps 4+5 merged (Understanding Results + Export)
- Progress bar preserved with updated step count
- All existing functionality preserved

---

## Part 9: Code Cleanup (Implemented)

### Critical Bugs Fixed
1. `quota_status` NameError in billing tab — added `check_scan_quota` import and definition
2. White-label checks inconsistent — unified to `"white_label" in PLANS[plan]["features"]`
3. `_cached_stats()` and `_cached_daily_counts()` — dead code removed
4. Stray `st.markdown("---")` — removed
5. Duplicate `import json as _json_stix` — removed second occurrence
6. Empty `if` block at line 33 — removed

### Plan Deduplication
- 4 duplicate plan definitions consolidated into single `PLANS` dict
- Enterprise price inconsistency fixed ($299 vs "Custom" → 0)

---

## Part 10: Performance Assessment

### Current Performance
- Streamlit caching: `_cached_history(ttl=60)`, `_cached_threats(ttl=60)`, `_cached_all_analyses(ttl=60)`
- Lazy imports inside tab blocks (good — avoids loading all modules on startup)
- SQLite with no connection pooling

### Bottlenecks
- `sqlite3.connect(DB_PATH)` called on every rerun per module (~80 locations)
- No pagination on scan history queries
- Rate limiting uses simple token bucket
- Email sending blocks the request (should be async)

### Recommendations (Phase 2+)
- Connection pooling for SQLite
- Server-side pagination for history/queries
- Background task queue for email + report generation
- Redis caching for hot queries

---

## Part 11: Enterprise Readiness

### Current State
- ✅ SSO (OIDC via `src/sso.py`)
- ✅ SCIM provisioning (`src/scim.py`)
- ✅ Audit logging (`src/audit_log.py`)
- ✅ RBAC (`src/rbac.py`)
- ✅ GDPR tools (`src/gdpr.py`)
- ✅ Data retention policies (`src/retention.py`)
- ✅ IP allowlisting (`src/ip_allowlist.py`)
- ✅ Custom detection rules (`src/custom_rules.py`)
- ✅ SIEM webhook (`src/siem_webhook.py`)
- ✅ STIX threat intel export (`src/stix_exporter.py`)
- ✅ Monthly recurring webhook routes (`src/webhook_routing.py`)
- ✅ Workspace/team management (`src/workspace.py`)
- ⚠️ No SLA enforcement
- ⚠️ No dedicated support portal
- ⚠️ No status page
- ⚠️ Compliance reports generated but not auditable

### Gap Analysis
| Requirement | Status | Priority |
|---|---|---|
| SOC 2 Type II | Partial (reports exist, no audit trail) | High |
| GDPR compliance | Complete (export, delete, consent) | Complete |
| Single sign-on (OIDC) | Complete (generic OIDC + Google Workspace) | Complete |
| RBAC with custom roles | Complete (init_rbac, check_permission) | Complete |
| Audit log | Complete (CRUD + search + export) | Complete |
| Retention policies | Complete | Complete |
| White-label reports | Feature-gated, partially complete | Medium |
| SLA dashboard | Missing | Low |
| Status page | Missing | Low |

---

## Part 12: Roadmap

### Phase 1 (Weeks 1–2) — Foundation ✓ (Partially Complete)
- [x] Fix critical bugs (6 identified, 6 fixed)
- [x] Consolidate plan definitions into single source of truth
- [x] Remove dead code and fix inconsistencies
- [ ] Add proper error boundaries to all tab content
- [ ] Add comprehensive input validation

### Phase 2 (Weeks 3–4) — Navigation & UX ✓ (Partially Complete)
- [x] Simplify tab labels
- [x] Add sidebar navigation guide
- [x] Redesign dashboard as landing experience
- [x] Improve onboarding wizard
- [ ] Reduce tab count from 23 to ~10 (requires code restructuring)
- [ ] Add contextual upgrade prompts based on user behavior

### Phase 3 (Weeks 5–6) — Data Layer
- [ ] Centralize DB logic with ORM-like adapter
- [ ] Consolidate `tenants.db` and `analyses.db` into single schema
- [ ] Add migration system (Alembic or custom)
- [ ] Introduce prepared statements for all queries
- [ ] Add foreign key enforcement

### Phase 4 (Weeks 7–8) — Plans & Billing
- [ ] Eliminate Free vs Trial confusion
- [ ] Implement usage-based pricing notifications
- [ ] Add plan change proration
- [ ] Build plan comparison tool
- [ ] Implement trial expiration flow

### Phase 5 (Weeks 9–10) — Enterprise
- [ ] Add SLA enforcement dashboard
- [ ] Implement support ticket system
- [ ] Build admin panel for tenant management
- [ ] Add webhook-based event notifications
- [ ] Implement rate limit headers

### Phase 6 (Weeks 11–12) — Migration
- [ ] Clerk integration (auth layer)
- [ ] Supabase integration (DB + storage)
- [ ] Resend integration (email)
- [ ] Trigger.dev integration (background jobs)
- [ ] Paddle production checkout

---

## Part 13: Summary of Changes Made

| Category | File | Change |
|---|---|---|
| Bug Fix | app.py:32-33 | Removed empty `if` block |
| Bug Fix | app.py:219-232 | Removed dead `_cached_stats()`, `_cached_daily_counts()` |
| Bug Fix | app.py:1124,1467,1722 | Unified white-label check to use PLANS features |
| Bug Fix | app.py:2677 | Added `quota_status` definition to fix NameError |
| Bug Fix | app.py:1540 (old) | Removed stray `st.markdown("---")` |
| Bug Fix | app.py:1474 (old) | Removed duplicate `import json` |
| Plan | tenants.py | Enhanced PLANS with price_monthly, price_yearly, features, concurrent_sessions, rate_per_minute |
| Plan | ui_founder_analytics.py | Replaced PLAN_PRICES with PLANS import |
| Plan | onboarding.py | Replaced PLAN_PRICING with PLANS import |
| Plan | b2b_gateway.py | TIERS features now sourced from PLANS |
| Plan | app.py | Upgrade section references PLANS features |
| Nav | app.py:495-520 | Shortened tab labels, added sidebar navigation guide |
| Dashboard | app.py:1512-1745 | Redesigned with Security Score hero, collapsible advanced tools |
| Design | ui_design_system.py | Added feature_gate(), progress_bar(), metric_row() helpers |
| Onboarding | ui_onboarding.py | Reduced to 5 steps, added action buttons, improved flow |
| CSS | ui_design_system.py | Alert/notification styling refinements |

---

## Part 14: Test Results

```
251 passed, 2 skipped in ~40s
```

The 2 skipped tests are Redis-dependent (`test_redis_cache.py`) — expected when Redis is not running.
