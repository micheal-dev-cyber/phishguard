# PhishGuard AI — Archive Backlog

> Features that create zero business value today. Do not touch until the product has 100+ paying users and someone specifically requests them.

---

## Enterprise Integrations — NO ENTERPRISE CUSTOMERS EXIST

| Feature | LOC | If Someone Asks | Effort to Reactivate |
|---------|-----|-----------------|----------------------|
| SIEM webhooks (Splunk, Elastic, QRadar) | ~500 | "We need to send alerts to our SIEM" | 2h (code exists) |
| SOAR gateway | ~400 | "We need to trigger playbooks" | 1h (code exists) |
| SCIM provisioning | ~300 | "We need directory sync" | 1h (code exists) |
| SSO/OAuth | ~300 | "We need SAML/SSO" | 1h (code exists) |
| White labeling | ~200 | "We need white-label resale" | 1h (code exists) |
| Microsoft Graph API | ~200 | "Scan our Exchange inbox" | 2h (code exists) |

## Threat Intelligence — NO THREAT INTEL PARTNERS EXIST

| Feature | LOC | If Someone Asks | Effort |
|---------|-----|-----------------|--------|
| STIX 2.1 export | ~200 | "Share intel with our ISAC" | 1h |
| Threat intel sharing | ~300 | "Join a threat sharing group" | 2h |
| MISP integration | ~200 | "Sync with our MISP" | 2h |

## Security Awareness — NO TRAINING CUSTOMERS EXIST

| Feature | LOC | If Someone Asks | Effort |
|---------|-----|-----------------|--------|
| Campaign engine (phishing sim) | ~800 | "Run a phishing simulation" | 1h |
| Honeypot generator | ~400 | "Deploy a honeypot" | 1h |
| Auto-training pipeline | ~300 | "Auto-train users" | 1h |

## Advanced Detection — USERS DON'T NEED THIS YET

| Feature | LOC | If Someone Asks | Effort |
|---------|-----|-----------------|--------|
| AITM detector | ~600 | "Detect evilginx attacks" | 1h |
| URL sandbox (headless browser) | ~400 | "Render phishing pages" | 4h (needs infra) |
| OCR/homograph deep scan | ~300 | "Detect homograph attacks" | 1h |
| Perplexity AI analyzer | ~150 | "Use Perplexity for analysis" | 1h |

## Billing / Growth — NO USERS TO BILL OR GROW

| Feature | LOC | If Someone Asks | Effort |
|---------|-----|-----------------|--------|
| `spending_caps` table | ~30 | "Set a monthly budget" | 0.5h |
| `referral_codes` tables | ~50 | "Refer a friend" | 0.5h |
| `valuation_metrics` table | ~60 | "M&A diligence dashboard" | Never. Delete this. |
| Leaderboard/gamification | ~400 | "Compete with my team" | 1h |

## AICOS System — DELETE / MOVE TO BRANCH

| Component | LOC | Status | Action |
|-----------|-----|--------|--------|
| 70+ agents | ~10,000 | Zero users, zero data | Move to `archive/` branch |
| 23 memory stores | ~5,000 | Empty databases | Move to `archive/` branch |
| 79 pipeline phases | ~8,000 | Orchestration overhead | Move to `archive/` branch |
| Agent orchestrator | ~2,000 | Nothing to orchestrate | Move to `archive/` branch |

**Total archived: ~28,000 LOC**
**Remaining active codebase: ~10,000 LOC**
**Reduction: ~74%**

---

## When to Unarchive

| Trigger | Feature |
|---------|---------|
| 10+ paying business users | Team access, API, custom rules |
| 1 enterprise customer (50+ seats) | SSO, SCIM, SIEM, white-label, compliance |
| 100+ active users/month | Campaign engine, auto-training, gamification |
| Security researcher community | STIX, threat intel sharing, MISP |
| AICOS agents proposed for user-facing feature | Individual agent, on merit |

**If none of these triggers exist, the archived code stays archived.**
