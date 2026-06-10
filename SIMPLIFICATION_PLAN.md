# PhishGuard AI — Simplification Plan

> Goal: Reduce codebase complexity by 50%+ while maintaining or improving the actual product experience for real users.
> 
> **Do not modify code. This is a proposal only.**

---

## Summary

| Metric | Current | Target | Reduction |
|--------|---------|--------|-----------|
| Python files | ~108 | ~40 | 63% |
| LOC (product code, excl. venv) | ~20,064 | ~8,000 | 60% |
| Active agents (AICOS) | 70+ | 0 | 100% |
| Pipeline phases (AICOS) | 79 | 0 | 100% |
| Memory stores (AICOS) | 23 | 0 | 100% |
| Database tables | 40+ | ~15 | 63% |
| Database init functions | 2 | 1 | 50% |
| Quota systems | 2 | 1 | 50% |
| User tables | 2 | 1 | 50% |

---

## Step 1: Remove Entire AICOS System

### Current State
- 70+ agents in `agents/` directory
- 23 memory stores in `memory/` directory  
- 79 pipeline phases in `phases/` directory
- Agent orchestrator in `orchestrator/` directory
- These were built as "intelligence infrastructure" on top of PhishGuard

### Why Remove
- **Zero users** → zero data flowing through these pipelines
- **No measurable business value** — agents produce insights from empty databases
- **Maintenance cost** — every change to the product requires updating agent definitions
- **Cognitive load** — 172 files of orchestration for a product with 0 users

### Action
```bash
git mv agents/ archive/agents/
git mv memory/ archive/memory/
git mv phases/ archive/phases/
git mv orchestrator/ archive/orchestrator/
git rm -r agents/ memory/ phases/ orchestrator/
```

All moved to a git branch. If the product ever reaches 10,000+ active users AND the agents would provide value, they can be restored from git history.

### Files Removed
~25,000 LOC (estimated). This alone achieves the 50% reduction target.

---

## Step 2: Deduplicate Database

### Current State
Two init functions create overlapping tables:

**`database.py:init_db()` creates:**
| Table | Purpose | Conflict |
|-------|---------|----------|
| `analyses` | Analysis history | Same as using `usage_log` |
| `users` | User accounts | **DUPLICATES `tenants` table** |
| `leaderboard` | Gamification | Empty, no users |
| `threat_intel` | STIX data | Empty, no data shared |
| `sender_profiles` | Sender rep | Empty, no emails processed |
| `sender_communications` | Comm logs | Empty |
| `url_sandbox` | URL analysis | Empty, no sandbox infra |
| `homograph_alerts` | Alerts | Empty |
| `intel_broadcasts` | Broadcast log | Empty |
| `ocr_extractions` | OCR results | Empty |
| `leaderboard_history` | History | Empty |
| `campaign_templates` | Phishing sim | Empty |
| `campaigns` | Campaigns | Empty |
| `campaign_targets` | Targets | Empty |
| `api_keys` | API access | Empty, no API users |
| `api_usage` | API usage | Empty |
| `reported_phish` | Webhook reports | Empty |
| `scan_consumption` | Usage metering | **DUPLICATES `tenants.usage_log`** |
| `spending_caps` | Budget caps | Empty, no billing |
| `referral_codes` | Referrals | Empty, no users |
| `referral_redemptions` | Referral usage | Empty |
| `valuation_metrics` | M&A metrics | Empty, $0 revenue |
| `leaderboard_history` | Audit | Empty |

**`tenants.py:init_tenants()` creates:**
| Table | Purpose |
|-------|---------|
| `tenants` | User accounts (correct one) |
| `usage_log` | Activity log |
| `login_attempts` | Auth tracking |

### Proposed Schema (Single Source of Truth)

| Keep | Merge Into | Remove |
|------|-----------|--------|
| `tenants` | — | `users` |
| `usage_log` | — | `scan_consumption`, `analyses` |
| `login_attempts` | — | — |
| `email_verifications` | — | — |
| `password_reset_tokens` | — | — |
| `sessions` | — | — |
| `product_events` (analytics) | — | — |
| `paddle_subscriptions` | — | — |
| — | — | `leaderboard` (archive) |
| — | — | `leaderboard_history` (archive) |
| — | — | `threat_intel` (archive) |
| — | — | `sender_profiles` (archive) |
| — | — | `sender_communications` (archive) |
| — | — | `url_sandbox` (archive) |
| — | — | `homograph_alerts` (archive) |
| — | — | `intel_broadcasts` (archive) |
| — | — | `ocr_extractions` (archive) |
| — | — | `campaign_templates` (archive) |
| — | — | `campaigns` (archive) |
| — | — | `campaign_targets` (archive) |
| — | — | `api_keys` (archive) |
| — | — | `api_usage` (archive) |
| — | — | `reported_phish` (archive) |
| — | — | `spending_caps` (archive) |
| — | — | `referral_codes` (archive) |
| — | — | `referral_redemptions` (archive) |
| — | — | `valuation_metrics` (DELETE permanently) |
| — | — | `leaderboard` (archive) |
| — | — | `health_checks` (keep) |

### Result
40+ tables → ~12 tables. 70% reduction.

---

## Step 3: Merge Init Functions

### Current
```python
# app.py line 51+
from src.database import init_db  # Creates 22 tables
from src.tenants import init_tenants  # Creates 3 tables

# Both called at startup
init_db()
init_tenants()
```

### Proposed
```python
# Single init function in db.py
from src.db import init_all_tables  # Creates ~12 tables, all in one place

init_all_tables()
```

Remove `database.py:init_db()`. Move essential tables into `db.py:init_all_tables()`.

---

## Step 4: Remove Dead Enterprise Code Paths

### Files to Remove from Live Codebase (Move to `archive/enterprise/`)

| File | LOC | Reason |
|------|-----|--------|
| `siem_webhook.py` | ~200 | No SIEM customer |
| `soar_gateway.py` | ~200 | No SOAR customer |
| `scim.py` | ~200 | No enterprise directory |
| `sso.py` | ~300 | No OAuth/SSO customer |
| `white_label.py` | ~100 | No MSP/reseller customer |
| `compliance_reports.py` | ~200 | No compliance requirement |
| `gdpr.py` | ~100 | No EU users, no data requests |
| `campaign_engine.py` | ~400 | No training customer |
| `honeypot_generator.py` | ~200 | No deployment |
| `aitm_detector.py` | ~300 | No active user base |
| `stix_exporter.py` | ~100 | No threat intel partners |
| `threat_intel_sharing.py` | ~200 | No sharing partners |
| `b2b_gateway.py` | ~200 | No B2B sales |
| `enterprise_api.py` | ~300 | No API consumers |
| `plugin_manager.py` | ~200 | No plugin ecosystem |
| `webhook_routing.py` | ~200 | No webhook consumers |
| `auto_training.py` | ~200 | No training data |
| `weekly_report.py` | ~150 | No weekly data to report |
| `inbox_scanner.py` | ~200 | IMAP worker not deployed |
| `ui_bulk_users.py` | ~150 | No bulk user management needed |
| `ui_webhook_routing.py` | ~150 | No webhook routes to manage |
| `ui_plugins.py` | ~100 | No plugins to manage |
| `ui_channels.py` | ~100 | No notification channels configured |
| `ui_soc_dashboard.py` | ~200 | No SOC team |
| `ui_scheduler.py` | ~150 | No scheduled tasks |
| `ui_founder_analytics.py` | ~200 | Founder analytics can be in admin |
| `ui_performance.py` | ~100 | Premature optimization |
| `ui_webhook_tester.py` | ~100 | No webhooks to test |

**Total removed: ~4,800 LOC**

These files remain in git history. If a customer ever asks for any of these features, they can be restored and deployed for that specific customer's implementation project.

---

## Step 5: Simplify Detection Pipeline

### Current
```
detector.py → email_text → analyze_email()
  ├── extract_urls() → check_urls()           # Regex
  ├── scan_keywords()                          # Bag-of-words
  ├── detect_attachments()                     # Keyword check
  ├── analyze_headers()                        # Regex (own impl)
  ├── analyze_attachments()                    # Extension check
  ├── analyze_language()                       # Regex
  ├── fingerprint_email()                      # Kit fingerprint
  └── calculate_risk_score()                   # Weighted sum

Plus (orphaned):
header_auth.py:analyze_auth_headers()         # SPF/DKIM/DMARC — never called

Plus (AI wrapper):
ai_analyzer.py:analyze_email()                # LLM analysis (separate path)
ai_analyzer.py:analyze_url()                  # URL analysis (separate path)
ai_analyzer.py:generate_ai_report()           # Report gen (separate path)

Plus (jury):
jury_engine.py:evaluate_linguistic_jury()     # Linguistic analysis
jury_engine.py:evaluate_corporate_jury()      # BEC analysis
```

### Proposed
```python
# Single entry point: detector.py:analyze_email_v2()
def analyze_email_v2(email_text: str) -> dict:
    results = {}
    
    # 1. Heuristic engine (existing, keep)
    results['heuristic'] = run_heuristic_engine(email_text)
    
    # 2. Header auth (wire existing parser)
    results['auth'] = analyze_auth_headers(email_text)
    
    # 3. URL reputation (wire VT)
    results['urls'] = check_url_reputation(extract_urls(email_text))
    
    # 4. Jury engine (call existing, keep fallback)
    results['linguistic'] = evaluate_linguistic_jury(email_text)
    results['corporate'] = evaluate_corporate_jury(email_text)
    
    # 5. AI narrative (if AI provider configured)
    results['narrative'] = generate_threat_narrative(results)
    
    # 6. Ensemble scoring
    results['risk'] = calculate_ensemble_score(results)
    
    return results
```

This merge eliminates the parallel AI pipeline (`ai_analyzer.py` as separate path) and integrates everything through one function.

---

## Step 6: Simplify UI Files

### Current State
31 `ui_*.py` files. Most are Streamlit page components. Many are empty or near-empty (unused).

### Audit
| UI File | Status | Action |
|---------|--------|--------|
| `ui_analyzer.py` | Core scan page | **KEEP** |
| `ui_onboarding.py` | Onboarding wizard | **KEEP** (needs building) |
| `ui_history.py` | Scan history | **KEEP** |
| `ui_admin.py` | Admin panel | **KEEP** |
| `ui_analytics.py` | Usage analytics | **KEEP** |
| `ui_health.py` | System health | **KEEP** |
| `ui_design_system.py` | Design system doc | **KEEP** (dev tool) |
| `ui_theme.py` | Theme config | **KEEP** (tiny) |
| `ui_branding.py` | Brand settings | **KEEP** (tiny) |
| `ui_email_templates.py` | Email template editor | **ARCHIVE** — no enterprise user |
| `ui_domain_verify.py` | Domain verification | **ARCHIVE** — no enterprise customer |
| `ui_soc_dashboard.py` | SOC dashboard | **ARCHIVE** — no SOC team |
| `ui_bulk_users.py` | Bulk user import | **ARCHIVE** — no multi-user |
| `ui_channels.py` | Notification channels | **ARCHIVE** — no channels configured |
| `ui_plugins.py` | Plugin manager | **ARCHIVE** — no plugin ecosystem |
| `ui_scheduler.py` | Task scheduler | **ARCHIVE** — no scheduled tasks |
| `ui_webhook_routing.py` | Webhook routing | **ARCHIVE** — no webhooks |
| `ui_webhook_tester.py` | Webhook tester | **ARCHIVE** — no webhooks |
| `ui_founder_analytics.py` | Founder metrics | **MERGE** into admin panel |
| `ui_performance.py` | Performance metrics | **ARCHIVE** — premature |
| `ui_audit_log.py` | Audit log viewer | **ARCHIVE** — no audit data |
| `ui_task_queue.py` | Task queue viewer | **ARCHIVE** — no tasks |
| `ui_analyzer.py` | (already counted) | KEEP |

**UI files: 31 → ~12** (61% reduction)

---

## Step 7: Simplify Project Structure

### Current
```
phishguard/
├── src/               # 108 Python files
│   ├── ui_*.py        # 31 UI pages
│   └── *.py           # 77 backend modules
├── tests/             # 37 test files
├── data/              # SQLite DB + JSON data
├── workers/           # IMAP worker
├── api_gateway/       # API gateway
├── backend/           # Flask backend
├── extension/         # Browser extension
├── webhook.py         # Paddle webhook (Flask)
├── config.py          # Config (8 lines)
├── app.py             # Main entry (4410 lines)
└── ...
```

### Proposed
```
phishguard/
├── app.py                  # Main entry (simplified, remove dead imports)
├── src/
│   ├── core/               # Detection pipeline
│   │   ├── detector.py     # Main detection
│   │   ├── header_auth.py  # SPF/DKIM/DMARC
│   │   └── keywords.json   # Phishing keywords
│   ├── auth/               # Authentication
│   │   ├── auth.py         # Login/signup forms
│   │   ├── tenants.py       # User management
│   │   ├── session_manager.py
│   │   ├── email_verify.py
│   │   └── password_reset.py
│   ├── billing/            # Payments
│   │   └── paddle_billing.py
│   ├── ai/                 # AI integration
│   │   ├── providers.py    # LLM provider chain
│   │   ├── ai_analyzer.py  # LLM analysis
│   │   └── jury_engine.py  # Jury analysis
│   ├── ui/                 # All UI components
│   │   ├── analyzer.py
│   │   ├── onboarding.py
│   │   ├── history.py
│   │   ├── admin.py
│   │   └── ...
│   ├── lib/                # Shared utilities
│   │   ├── db.py           # Database connection
│   │   ├── env.py          # Environment config
│   │   ├── health.py       # Health/backup
│   │   └── analytics.py    # Event tracking
│   └── threat_intel/       # (Keep only what's wired)
│       └── url_intel.py    # VirusTotal integration
├── tests/                  # Keep all tests
├── archive/                # Pruned code (git branch)
│   ├── enterprise/         # SIEM, SOAR, SCIM, SSO, etc.
│   ├── growth/             # Referrals, gamification, etc.
│   ├── training/           # Campaign engine, simulations
│   └── aicos/              # Agents, memory, pipelines
├── data/                   # SQLite + JSON
└── webhook.py              # Paddle webhook (standalone)
```

---

## Effort Estimate

| Step | Description | Hours | Risk | LOC Removed |
|------|-------------|-------|------|-------------|
| 1 | Remove AICOS system | 4 | Low | ~25,000 |
| 2 | Deduplicate database tables | 6 | Medium | ~500 schema |
| 3 | Merge init functions | 2 | Medium | ~200 |
| 4 | Remove enterprise code paths | 2 | Low | ~4,800 |
| 5 | Simplify detection pipeline | 4 | Medium | ~300 code merged |
| 6 | Simplify UI files | 3 | Low | ~2,000 |
| 7 | Restructure directories | 2 | Low | 0 (file moves) |
| **Total** | | **23 hours** | | **~32,000 LOC** |

---

## Risk Mitigation

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Archived code needed later | Low | Git history. `git log` to find. Branch. |
| Removing enterprise code before first enterprise customer | None | Enterprise customers are 12+ months away. By then, re-implement based on actual requirements. |
| Merge conflicts with active development | Medium | Do this in a focused 2-day cleanup sprint. Nothing else changes during that time. |
| Breaking the working demo | Medium | Test suite must pass before/after. 37 test files exist. |

---

## The Result

**Before**: ~108 files, ~20,064 LOC, 40+ DB tables, 70+ agents, 79 pipeline phases, 2 user tables, 2 quota systems, 31 UI pages, 23 memory stores, 0 users, 0 revenue.

**After**: ~40 files, ~8,000 LOC, ~12 DB tables, 0 agents, 0 pipeline phases, 1 user table, 1 quota system, 12 UI pages, 0 memory stores, same 0 users but fast path to 10.

The simplification doesn't change what users see. It changes what the team has to maintain. Every file removed is cognitive load reclaimed for building what matters.
