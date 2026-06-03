# PhishGuard AI — Product Roadmap

**Last updated:** 2026-06-03 (Session 2)

> Scoring legend: 0–10 (10 = Production Ready)

| Dimension | Score | Notes |
|-----------|-------|-------|
| **Security** | 6.5 | 17 vulns fixed this session, 0 known unfixed issues. SQL injection surface reduced but ~20 modules still use f-string SQL (constant table names, low risk). Hardcoded secrets eliminated. Sqlite3 (file-based) needs Supabase migration for production. |
| **Reliability** | 6.0 | 251 tests passing. Centralized HTTP client with retries+timeouts on all 22 external calls. No schema migration system. Sqlite3 concurrency limited. No monitoring/alerting for app health. |
| **Performance** | 5.5 | Connection pooling via centralized Session reduces latency. Sqlite3 bottleneck. ~18,000 LOC single Streamlit process. No caching layer for AI calls. Async missing for I/O-bound tasks. |
| **Commercial Readiness** | 6.5 | Paddle billing integrated (sandbox). 3 pricing tiers defined. Feature gating implemented. B2B monetization modules (white-label, referrals, consumption caps). No Stripe option. No SLA/uptime guarantees. Missing usage analytics dashboard. |

**Overall: 6.3 / 10** — Reliability and performance improved via centralized HTTP client with retries/timeouts. Mixed hashing unified (bcrypt for all passwords). Email verification tokens now hashed. Architecture hardening still needed for production scale.

---

## Phase 1: Foundation Hardening (Weeks 1–2)

| Priority | Task | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| P0 | Supabase migration (sqlite3 → PostgreSQL) | 2 weeks | Reliability, Performance | ❌ |
| P0 | Schema migration system (Alembic) | 3 days | Reliability | ❌ |
| P0 | Replace remaining f-string SQL with parameterized queries | 2 days | Security | ⬜ |
| P1 | Unify bcrypt for all password hashing | 1 day | Security | ✅ |
| P1 | Add request timeouts to all external HTTP calls | 1 day | Reliability | ✅ |
| P1 | Centralize API client (requests session, retries, timeouts) | 2 days | Reliability | ✅ |

## Phase 2: Architecture Modernization (Weeks 3–4)

| Priority | Task | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| P0 | Provider-agnostic adapter: Auth (Clerk/OIDC) | 1 week | Architecture | ❌ |
| P0 | Provider-agnostic adapter: Email (Resend/SMTP) | 3 days | Architecture | ❌ |
| P1 | Provider-agnostic adapter: Queue (Trigger.dev/Celery) | 4 days | Architecture | ❌ |
| P1 | Provider-agnostic adapter: Billing (Paddle/Stripe) | 1 week | Architecture | ❌ |
| P1 | Provider-agnostic adapter: DB (Supabase/PostgreSQL) | 5 days | Architecture | ❌ |
| P2 | Split app.py into modular service files | 1 week | Maintainability | ⬜ |

## Phase 3: Navigation & UX Overhaul (Weeks 4–5)

| Priority | Task | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| P0 | Consolidate 23 tabs → ~10 with sub-navigation | 3 days | UX | ⬜ |
| P1 | Unify pricing: 3 clear tiers (Free/Pro/Business) | 2 days | UX, Sales | ⬜ |
| P1 | Mobile-responsive layout | 1 week | UX | ⬜ |
| P2 | Keyboard shortcuts power-user mode | 2 days | UX | ⬜ |
| P2 | Onboarding A/B test framework | 3 days | Growth | ⬜ |

## Phase 4: Data & Analytics (Weeks 5–6)

| Priority | Task | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| P1 | Usage analytics dashboard | 4 days | Commercial | ❌ |
| P1 | Real-time threat monitoring dashboard | 1 week | Product | ❌ |
| P2 | CSV/PDF export for all report types | 2 days | UX | ⬜ |
| P2 | Scheduled PDF report delivery (email) | 3 days | Commercial | ⬜ |
| P2 | Custom dashboard widgets/saved views | 1 week | UX | ⬜ |

## Phase 5: Testing & Quality (Ongoing)

| Priority | Task | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| P0 | Increase test coverage to 80%+ | Ongoing | Reliability | ⬜ |
| P1 | Integration tests for external APIs | 1 week | Reliability | ⬜ |
| P1 | E2E tests for critical user journeys | 1 week | Reliability | ⬜ |
| P1 | Load testing (target: 1000 concurrent users) | 3 days | Performance | ⬜ |
| P2 | Property-based testing for parsing modules | 2 days | Reliability | ⬜ |

## Phase 6: Production Readiness (Weeks 7–8)

| Priority | Task | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| P0 | Docker Compose production profile | 2 days | DevOps | ⬜ |
| P0 | CI/CD pipeline improvements (staging env) | 3 days | DevOps | ⬜ |
| P1 | Monitoring & alerting (health endpoint, Sentry) | 3 days | Reliability | ⬜ |
| P1 | Rate limiting per tenant | 2 days | Security | ⬜ |
| P1 | Audit log for all admin actions | 2 days | Compliance | ⬜ |
| P2 | Multi-region deployment guide | 2 days | DevOps | ⬜ |

## Phase 7: Growth & Monetization (Weeks 8–10)

| Priority | Task | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| P1 | Referral/invite system | 3 days | Growth | ⬜ |
| P1 | Public API with rate limits + API keys UI | 1 week | Commercial | ⬜ |
| P2 | Marketplace for detection rule packs | 1 week | Commercial | ⬜ |
| P2 | White-label mobile app (React Native) | 3 weeks | Commercial | ⬜ |
| P2 | Partner/ reseller portal | 2 weeks | Commercial | ⬜ |

---

## Done (Weeks 0–2)

| Task | Status | Date |
|------|--------|------|
| Security audit — 12 critical/high issues in app.py | ✅ | 2026-05-31 |
| Security audit — 17 additional issues across 50+ files | ✅ | 2026-06-03 |
| Database centralization (src/db.py, 56 files refactored) | ✅ | 2026-05-31 |
| Plan consolidation (single PLANS dict in src/tenants.py) | ✅ | 2026-05-31 |
| Navigation labels shortened (23 tabs) | ✅ | 2026-05-31 |
| Dashboard redesign (Score hero, collapsible tools) | ✅ | 2026-05-31 |
| Design system (3 helpers, CSS refinements) | ✅ | 2026-05-31 |
| Onboarding reduction (6→5 steps) | ✅ | 2026-05-31 |
| Git history cleanup (binary files removed from 131 commits) | ✅ | 2026-05-31 |
| Ruff lint passing (392 auto-fixes + 66 noqa) | ✅ | 2026-06-03 |
| All 251 tests passing | ✅ | 2026-06-03 |
| Mixed hashing unified (bcrypt for all passwords) | ✅ | 2026-06-03 |
| Centralized HTTP client (retries, timeouts, connection pooling) | ✅ | 2026-06-03 |
| Token hashing for email verification (plaintext → SHA-256) | ✅ | 2026-06-03 |
