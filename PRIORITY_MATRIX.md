# PhishGuard AI — Priority Matrix

> Brutal audit of every significant feature/component. Columns: Impact (1-10), Effort (hours), Risk (1-10), Revenue Impact, User Impact, Verdict.

---

## Core Product Features

| Feature | Files | Impact | Effort | Risk | Revenue Impact | User Impact | Verdict | Rationale |
|---------|-------|--------|--------|------|----------------|-------------|---------|-----------|
| **Heuristic detection engine** | `detector.py` (455 LOC) | 9 | 0 | 1 | High | High | **KEEP** | Only thing that works today. Core value prop. |
| **Demo scan (no account)** | `auth.py:460-600` | 8 | 2 (unlock) | 1 | Medium | High | **KEEP** | Top-of-funnel. Show value before signup. |
| **Signup form** | `auth.py:108-192` | 10 | 0 | 1 | High | High | **KEEP** | User acquisition. Already works. |
| **Email verification** | `email_verify.py` (99 LOC) | 10 | 0 | 1 | High | High | **KEEP** | Works. Just needs SMTP. |
| **Login (username/password)** | `auth.py:195-326` | 10 | 0 | 1 | High | High | **KEEP** | Works. Core auth. |
| **Magic link login** | `auth.py:218-242`, `magic_link.py` | 7 | 0 | 1 | Medium | High | **KEEP** | Reduces password friction. |
| **Password reset** | `password_reset.py` (87 LOC) | 8 | 0 | 1 | Medium | High | **KEEP** | Required for retention. |
| **Session management** | `session_manager.py` (106 LOC) | 7 | 4 (fix) | 2 | Medium | High | **KEEP** | Needs remember-me + refresh. |
| **Plan/quota enforcement** | `tenants.py:318-329` | 7 | 2 (fix) | 2 | High | Medium | **KEEP** | Revenue gating. But currently duplicate with `scan_consumption`. |
| **Header auth (SPF/DKIM/DMARC)** | `header_auth.py` (198 LOC) | 8 | 2 | 1 | Medium | High | **KEEP** | Orphaned. Wire into detector. |
| **VirusTotal integration** | `threat_intel.py` / `url_intel.py` | 7 | 2 | 1 | Medium | High | **KEEP** | Configure key + wire into pipeline. |
| **Domain age / WHOIS** | Not implemented | 6 | 8 | 2 | Low | High | **KEEP** (deferred) | High effort, but strong signal. Schedule post-revenue. |
| **AI analysis (LLM)** | `ai_analyzer.py` (371 LOC) | 8 | 1 | 1 | High | High | **KEEP** | Configure Groq key = works immediately. |
| **AI threat narrative** | `ai_analyzer.py:354-371` | 7 | 3 | 1 | Medium | High | **KEEP** | Biggest UX win for result page. |
| **Jury engine (linguistic/BEC)** | `jury_engine.py` (338 LOC) | 5 | 0 | 1 | Low | Medium | **KEEP** | Falls back to heuristics. Fine as-is. |
| **PDF report export** | `report_generator.py` | 4 | 0 | 1 | Low | Medium | **KEEP** | Low effort to keep. Users expect it. |
| **Usage dashboard** | `ui_analytics.py` | 3 | 0 | 1 | Low | Medium | **KEEP** | Already built. Minimal maintenance. |

---

## Enterprise Features — DELETE or ARCHIVE

| Feature | Files | Impact | Effort | Risk | Revenue Impact | User Impact | Verdict | Rationale |
|---------|-------|--------|--------|------|----------------|-------------|---------|-----------|
| **STIX 2.1 threat intel sharing** | `stix_exporter.py` | 0 | 0 | 1 | None | None | **ARCHIVE** | Requires threat intel partners. Zero users. Zero data to share. No business impact until 10K+ users. |
| **SIEM webhook integration** | `siem_webhook.py` | 0 | 0 | 2 | None | None | **ARCHIVE** | No SIEM customer exists. Splunk/Elastic/QRadar integrations require enterprise sales cycle. Premature. |
| **SOAR gateway** | `soar_gateway.py` | 0 | 0 | 2 | None | None | **ARCHIVE** | Same as SIEM. No SOAR customer. |
| **SCIM provisioning** | `scim.py` | 0 | 0 | 1 | None | None | **ARCHIVE** | Enterprise directory sync. No enterprise directory customer. |
| **SSO/OAuth** | `sso.py` | 0 | 0 | 1 | None | None | **ARCHIVE** | No enterprise customer. Google OAuth login is a nice-to-have but not blocking. |
| **White labeling** | `white_label.py` | 0 | 0 | 1 | None | None | **ARCHIVE** | No enterprise/MSP customer. |
| **Compliance reports** | `compliance_reports.py` | 0 | 0 | 1 | None | None | **ARCHIVE** | No compliance requirements from users. |
| **GDPR tools** | `gdpr.py` | 0 | 0 | 1 | None | None | **ARCHIVE** | No EU users. No GDPR requests. |
| **Campaign engine (phishing sim)** | `campaign_engine.py` | 0 | 0 | 2 | None | None | **ARCHIVE** | Training feature for enterprise. No customer to train. Adds UI complexity. |
| **Honeypot generator** | `honeypot_generator.py` | 0 | 0 | 2 | None | None | **ARCHIVE** | Advanced deception tech. No deployment to protect. |
| **AITM detector** | `aitm_detector.py` | 0 | 0 | 2 | None | None | **ARCHIVE** | Adversary-in-the-Middle detection. Extremely niche. Zero users need this. |
| **Brand impersonation detector** | `brand_impersonation.py` | 1 | 0 | 1 | Low | Low | **KEEP** (lite) | Actually useful. Already integrated-ish. Keep but don't expand. |
| **Phishing DNA fingerprinting** | `phishing_dna.py` | 1 | 0 | 1 | Low | Low | **KEEP** (lite) | Runs on every scan. Low overhead. Keep as-is. |
| **URL sandbox** | `url_sandbox.py` | 4 | 0 | 2 | Low | Low-Med | **KEEP** (lite) | Good for detection. But requires headless browser. Don't deploy yet. |
| **Attachment scanner** | `attachment_scanner.py` | 3 | 0 | 1 | Low | Medium | **KEEP** (lite) | Useful signal. Keep regex portion. Don't expand. |
| **Homograph detector** | `ocr_homograph.py` | 2 | 0 | 1 | Low | Low | **KEEP** (lite) | Low maintenance. Keep as regex. |

---

## AICOS System — AGGRESSIVE PRUNE

| Feature | Files | Impact | Effort | Risk | Revenue Impact | User Impact | Verdict | Rationale |
|---------|-------|--------|--------|------|----------------|-------------|---------|-----------|
| **70+ agents** | AICOS agents/ | 0 | 0 | 3 | None | None | **ARCHIVE** | Zero users. Agents built on empty data produce no value. Every hour maintaining them is stolen from user acquisition. |
| **23 memory stores** | AICOS memory/ | 0 | 0 | 3 | None | None | **ARCHIVE** | Memory without users = empty databases. No behavioral data to learn from. |
| **79 pipeline phases** | AICOS phases/ | 0 | 0 | 3 | None | None | **ARCHIVE** | Pipeline orchestration for a product with no pipeline throughput. Premature optimization at scale. |
| **Agent orchestration** | AICOS orchestrator/ | 0 | 0 | 3 | None | None | **ARCHIVE** | Scheduling agents to do nothing productive. |
| **Auto-training pipeline** | `auto_training.py` | 0 | 0 | 2 | None | None | **ARCHIVE** | Training requires data. Data requires users. Users don't exist. |
| **Weekly report generation** | `weekly_report.py` | 0 | 0 | 1 | None | None | **ARCHIVE** | Reports for zero users. |

---

## Admin / Internal Features — RETAIN

| Feature | Files | Impact | Effort | Risk | Revenue Impact | User Impact | Verdict |
|---------|-------|--------|--------|------|----------------|-------------|---------|
| **Admin panel** | `ui_admin.py` | 5 | 0 | 1 | Medium | None | **KEEP** |
| **Health checks** | `health.py` | 6 | 0 | 1 | Low | None | **KEEP** |
| **Backup system** | `health.py:143-167` | 7 | 0 | 1 | Low | None | **KEEP** |
| **Analytics tracking** | `analytics.py` (271 LOC) | 8 | 0 | 1 | High | None | **KEEP** |
| **Event tracking** | `analytics.py:46-75` | 8 | 0 | 1 | High | None | **KEEP** |
| **Rate limiting** | `ratelimit.py` | 6 | 0 | 1 | Low | Low | **KEEP** |
| **IP allowlist** | `ip_allowlist.py` | 1 | 0 | 1 | None | None | **KEEP** (tiny file) |

---

## Duplicate / Conflicting Code — ELIMINATE

| Feature | Files | Impact | Effort | Risk | Revenue Impact | User Impact | Verdict |
|---------|-------|--------|--------|------|----------------|-------------|---------|
| **`users` table** | `database.py:38-47` | 7 | 3 | 2 | Medium | Medium | **DELETE** | Duplicates `tenants` table. Different columns. Will cause bugs. |
| **`scan_consumption` table** | `database.py:313-323` | 7 | 2 | 2 | Medium | Medium | **DELETE** | Duplicates `tenants.usage_log`. Two quota systems will conflict. |
| **`spending_caps` table** | `database.py:326-334` | 3 | 1 | 1 | Low | None | **ARCHIVE** | No billing active. Premature. |
| **`referral_codes` / `referral_redemptions`** | `database.py:337-358` | 3 | 1 | 1 | Low | None | **ARCHIVE** | No users to refer. Dead code until growth stage. |
| **`valuation_metrics`** | `database.py:361-381` | 0 | 1 | 1 | None | None | **DELETE** | M&A valuation telemetry for a product with $0 revenue. Delusional. |

---

## UX / Marketing Features — PRIORITIZE

| Feature | Files | Impact | Effort | Risk | Revenue Impact | User Impact | Verdict |
|---------|-------|--------|--------|------|----------------|-------------|---------|
| **Landing page (hero)** | `auth.py:603-663` | 8 | 0 | 1 | High | High | **KEEP** | But remove fake claims immediately. |
| **Pricing section** | `auth.py:851-888` | 8 | 4 | 2 | High | High | **KEEP** | Wire to functional Paddle checkout. |
| **Testimonials** | `auth.py:790-809` | -3 | 0.5 | 10 | Negative | Negative | **DELETE** | Fabricated. Trust poison. Remove now. |
| **Trust bar** | `auth.py:654-663` | -3 | 0.5 | 10 | Negative | Negative | **DELETE** | "99% detection rate" with zero evidence. Libel risk. |
| **Demo mode** | `auth.py:460-600` | 8 | 2 | 1 | High | High | **KEEP** (improve) | Unlock all results. Gate only PDF save. |
| **Onboarding** | Missing | 7 | 6 | 1 | Medium | High | **BUILD** | First-scan activation is critical. |
| **Trust pages** | `auth.py:77-92` | 2 | 0 | 1 | Low | Low | **KEEP** | Low effort. Provides legitimacy. |

---

## Summary: What to Cut

| Delete/Archive | LOC | Reason |
|----------------|-----|--------|
| AICOS agents (70+) | ~10,000+ | Zero users. Zero data. Pre-revenue complexity. |
| AICOS memory stores (23) | ~5,000+ | Empty databases serving no one. |
| AICOS pipeline phases (79) | ~8,000+ | Orchestration overhead for no throughput. |
| SIEM integration | ~500 | No SIEM customer. |
| SOAR gateway | ~400 | No SOAR customer. |
| SCIM provisioning | ~300 | No enterprise directory. |
| STIX exporter | ~200 | No threat intel partners. |
| Campaign engine | ~800 | No training customers. |
| Honeypot generator | ~400 | No deployment. |
| AITM detector | ~600 | Niche. Premature. |
| Compliance reports | ~300 | No compliance need. |
| GDPR tools | ~200 | No EU users. |
| White labeling | ~200 | No enterprise customer. |
| `valuation_metrics` table | ~60 lines of schema | M&A prep for $0 revenue. |
| `referral_codes` tables | ~50 lines | No users. |
| `spending_caps` table | ~30 lines | No billing. |
| `users` table | ~20 lines | Duplicate of `tenants`. |
| `scan_consumption` table | ~30 lines | Duplicate of `usage_log`. |
| Fake testimonials + trust bar | ~30 lines | Trust poison. |
| **Total removed** | **~28,000 LOC** | |

**Keep ~10,000 LOC** — the actual product.
