# PhishGuard AI — Technical Debt Register

**Last updated:** 2026-06-03 (Session 2)

---

## Architecture Debt

| Debt | Severity | Impact | Est. Effort | Notes |
|------|----------|--------|-------------|-------|
| Sqlite3 in production | HIGH | Reliability, Scale | 2 weeks | File-based DB unsuitable for multi-tenant. Must migrate to Supabase/PostgreSQL. |
| app.py monolithic (5,008 lines) | HIGH | Maintainability | 1 week | 1/3 of all source code in single file. 80+ functions, 5 pages. Needs modular split. |
| No schema migration system | HIGH | Reliability | 3 days | Every schema change is manual SQL. No rollback. No version tracking. |
| Streamlit import-order fragility | MEDIUM | Stability | 2 days | `import streamlit` before `set_page_config()` crashes app. 20+ files at risk. |
| Provider lock-in (no adapters) | MEDIUM | Flexibility | 3 weeks | Clerk, Resend, Paddle, Trigger.dev all directly coupled. Adapter layer needed. |
| No background job worker | MEDIUM | UX, Scale | 1 week | Long-running tasks (email parsing, AI analysis) block Streamlit event loop. Background worker exists but is thread-based, not distributed. |
| Duplicate env variable patterns | LOW | Maintainability | 1 day | Some use `os.getenv()`, some `st.secrets`, some `env.py`. Inconsistent. |

## Code Quality Debt

| Debt | Severity | Impact | Est. Effort | Notes |
|------|----------|--------|-------------|-------|
| F-string SQL in ~20 modules | MEDIUM | Security | 2 days | All constant table/column names (low injection risk) but non-idiomatic. |
| Mixed hashing (bcrypt + SHA-256) | MEDIUM | Consistency | 1 day | ✅ Fixed. All passwords use bcrypt, tokens use SHA-256. Email verification tokens no longer plaintext. |
| No type hints in many functions | MEDIUM | Maintainability | 1 week | Spotty coverage. Key functions untyped. |
| Inconsistent error handling patterns | MEDIUM | Reliability | 3 days | Some modules log, some raise, some return error dicts. No standard. |
| 66 noqa lint suppressions | LOW | Quality | 2 days | Mostly E402 (import order) and S608 (SQL). Should audit each. |
| Bare `except:` still in git history | LOW | Quality | N/A | All resolved in current HEAD. Historical only. |
| No pre-commit hooks configured | MEDIUM | Quality | 1 day | Would prevent unused imports, bad formatting, etc. |
| No centralized HTTP client | MEDIUM | Reliability | 2 days | ✅ Fixed. `src/http_client.py` provides retries, timeouts, connection pooling for all 22 external calls. |

## Testing Debt

| Debt | Severity | Impact | Est. Effort | Notes |
|------|----------|--------|-------------|-------|
| ~50% test coverage (estimate) | HIGH | Reliability | Ongoing | 251 tests exist but many modules untested. |
| No integration tests for external APIs | HIGH | Reliability | 1 week | AI providers, Paddle, SendGrid, etc. untested in CI. |
| No E2E tests | MEDIUM | Reliability | 1 week | Critical user journeys (signup → scan → pay) untested. |
| Tests rely on real DB files | MEDIUM | Reliability | 2 days | Tests create/modify `phishguard.db`. Not isolated. |
| No property-based tests | LOW | Quality | 2 days | Parsing modules (email, URL) good candidates. |
| No performance/load tests | MEDIUM | Reliability | 3 days | Unknown capacity limits. Sqlite3 concurrency untested. |

## Documentation Debt

| Debt | Severity | Impact | Est. Effort | Notes |
|------|----------|--------|-------------|-------|
| No API documentation for internal services | MEDIUM | Developer Experience | 2 days | Inter-module contracts undocumented. |
| No architecture decision records (ADRs) | MEDIUM | Maintainability | 2 days | Why certain decisions made — lost context. |
| Setup instructions incomplete | LOW | Developer Experience | 1 day | Missing Supabase, Redis setup steps. |

## Security Debt (Remaining)

| Debt | Severity | Impact | Est. Effort | Notes |
|------|----------|--------|-------------|-------|
| Rate limiting per tenant not implemented | MEDIUM | Security | 2 days | API keys have no rate limits. Brute force possible. |
| Audit log for admin actions | MEDIUM | Compliance | 2 days | No record of who changed what. |
| No IP allowlist enforcement for admin | LOW | Security | 1 day | Feature exists in code but not enforced. |
| Session management (revoke, expire) | MEDIUM | Security | 3 days | No way to force-logout all sessions. |
| No CSRF tokens for web forms | LOW | Security | 1 day | Streamlit handles most, but custom forms exist. |

## DevOps Debt

| Debt | Severity | Impact | Est. Effort | Notes |
|------|----------|--------|-------------|-------|
| Docker Compose lacks production profile | MEDIUM | DevOps | 2 days | Dev compose only. No prod-ready config. |
| No staging environment | MEDIUM | Reliability | 3 days | All changes deploy directly to HF Spaces. |
| No monitoring/alerting | HIGH | Reliability | 3 days | No Sentry, no health checks, no uptime monitoring. |
| CI pipeline runs on push only | MEDIUM | Quality | 1 day | Should run on PRs too. |
| No secrets scanning in CI | MEDIUM | Security | 1 day | Hardcoded secrets found manually. Should be automated. |
