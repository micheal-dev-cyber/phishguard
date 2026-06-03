# PhishGuard AI — Feature Requests & Candidates

**Last updated:** 2026-06-03 (Session 2)

---

## Core Product Gaps (Based on Codebase Analysis)

| # | Feature | Rationale | Effort | Priority |
|---|---------|-----------|--------|----------|
| 1 | **Supabase/PostgreSQL migration** | Sqlite3 is a hard ceiling for multi-tenant SaaS | 2 weeks | P0 |
| 2 | **Background job worker** | Long-running AI analysis blocks Streamlit UI | 1 week | P0 |
| 3 | **Public REST API** | API gateway exists but no public-facing API with docs | 1 week | P1 |
| 4 | **Usage analytics dashboard** | No way for founders to see MAU, scans, conversions | 1 week | P1 |
| 5 | **Real-time threat dashboard** | SOC dashboard exists but could show live global metrics | 1 week | P1 |
| 6 | **Mobile app (PWA/React Native)** | Web-only limits accessibility | 3 weeks | P2 |
| 7 | **Slack/Discord bot** | Inline phishing report checking | 2 weeks | P2 |
| 8 | **Browser extension** | Users want right-click "Report phishing" | 2 weeks | P2 |

## Existing Features to Improve

| # | Feature | Current State | Target | Effort |
|---|---------|---------------|--------|--------|
| 1 | **Onboarding** | 5 steps, functional | A/B testing, personalization | 3 days |
| 2 | **Pricing page** | Clear tiers but Free vs Trial confusing | 3 simple tiers + FAQ | 2 days |
| 3 | **Navigation** | 23 tabs, nested | ~10 tabs with sub-nav | 3 days |
| 4 | **Email templates** | Editable via UI | Drag-and-drop builder | 1 week |
| 5 | **Reports** | Generated on-demand | Scheduled + auto-email | 3 days |
| 6 | **Detection rules** | Custom rules supported | Marketplace for community rules | 1 week |

## Technical Enhancements

| # | Feature | Benefit | Effort | Priority |
|---|---------|---------|--------|----------|
| 1 | **Schema migration system (Alembic)** | Safe, versioned DB changes | 3 days | P0 |
| 2 | **Full type hints** | IDE support, fewer bugs | 1 week | P2 |
| 3 | **OpenAPI/Swagger docs** | API discoverability | 3 days | P2 |
| 4 | **Pre-commit hooks** | Catch issues before commit | 1 day | P1 |
| 5 | **Sentry/error monitoring** | Proactive error detection | 2 days | P1 |
| 6 | **Performance dashboard** | Track latency, error rates | 3 days | P2 |

## Monetization Candidates

| # | Feature | Model | Effort |
|---|---------|-------|--------|
| 1 | **Marketplace for detection rules** | Revenue share (30%) | 1 week |
| 2 | **White-label mobile app** | Enterprise upsell | 3 weeks |
| 3 | **API credits / usage-based billing** | Consumption pricing | 1 week |
| 4 | **Partner/reseller portal** | Channel sales | 2 weeks |
| 5 | **SLA guarantees** | Enterprise requirement | 3 days |

## User-Requested Features (Inferred from Code)

| # | Feature | Evidence | Effort |
|---|---------|----------|--------|
| 1 | **Bulk email analysis** | Existing single-email workflow; no bulk mode | 3 days |
| 2 | **Custom domain verification** | Domain verify module exists but half-implemented | 2 days |
| 3 | **Team/org management** | Tenant system exists but team features basic | 1 week |
| 4 | **Webhook integrations (custom)** | Webhook tester exists; no custom endpoint config UI | 3 days |
| 5 | **Saved search/filters** | Threat intel has search; no saved queries | 2 days |
