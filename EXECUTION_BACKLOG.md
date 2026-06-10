# PhishGuard AI — Execution Backlog

> **ICE Score = Impact × Confidence × Ease** (each 1-10)
> Only work that directly helps Acquisition, Activation, Retention, or Revenue.

---

## Tier 0 — DO TOMORROW (ICE > 500)

| # | Item | Impact | Confidence | Ease | ICE | Type | Why Now |
|---|------|--------|------------|------|-----|------|---------|
| 1 | **Set SMTP env vars** | 10 | 10 | 10 | 1000 | Acquisition / Activation | Unlocks entire signup pipeline. Minute-for-minute highest ROI in the entire codebase. |
| 2 | **Set Groq API key** | 9 | 10 | 10 | 900 | Activation | AI features switch from "broken fallback" to "working." Free tier exists. |
| 3 | **Set APP_URL** | 10 | 10 | 10 | 1000 | Acquisition | Verification/reset/magic links work. Currently point to localhost. |
| 4 | **Remove fake trust claims + testimonials** | 7 | 10 | 10 | 700 | Trust / Retention | Prevents immediate trust destruction when first technical user arrives. |
| 5 | **Deploy to public URL** | 10 | 10 | 8 | 800 | Acquisition | Product exists on the internet for the first time. |

**Total effort**: ~4 hours | **Business impact**: Product goes from non-functional to minimally viable.

---

## Tier 1 — THIS WEEK (ICE 400-500)

| # | Item | Impact | Confidence | Ease | ICE | Type |
|---|------|--------|------------|------|-----|------|
| 6 | **Wire header_auth.py into detector.py** | 8 | 9 | 8 | 576 | Activation (detection quality) |
| 7 | **Configure VirusTotal API key** | 7 | 8 | 9 | 504 | Activation (URL reputation) |
| 8 | **Unlock full demo results** | 6 | 8 | 9 | 432 | Acquisition (demo→signup conversion) |
| 9 | **Add "resend verification" button** | 8 | 9 | 6 | 432 | Activation (recover lost signups) |
| 10 | **Set VIRUSTOTAL_API_KEY** | 7 | 9 | 9 | 567 | Activation |

**Total effort**: ~8 hours

---

## Tier 2 — NEXT WEEK (ICE 300-400)

| # | Item | Impact | Confidence | Ease | ICE | Type |
|---|------|--------|------------|------|-----|------|
| 11 | **Configure Paddle billing (create account, products, webhook)** | 10 | 9 | 5 | 450 | Revenue |
| 12 | **Wire pricing page → generate_checkout_url()** | 8 | 9 | 6 | 432 | Revenue |
| 13 | **Build 3-step onboarding wizard** | 7 | 8 | 5 | 280 | Activation |
| 14 | **Add persistent session ("remember me")** | 5 | 8 | 7 | 280 | Retention |
| 15 | **Build generate_threat_narrative()** | 7 | 7 | 5 | 245 | Activation (result understanding) |

**Total effort**: ~20 hours

---

## Tier 3 — THIS MONTH (ICE 200-300)

| # | Item | Impact | Confidence | Ease | ICE | Type |
|---|------|--------|------------|------|-----|------|
| 16 | **Domain age check via whois** | 6 | 7 | 4 | 168 | Activation (detection quality) |
| 17 | **Unify user tables (users + tenants → tenants)** | 7 | 9 | 2 | 126 | Reliability |
| 18 | **Unify quota systems (usage_log > scan_consumption)** | 7 | 9 | 3 | 189 | Reliability |
| 19 | **First user outreach (invite 10-20 people)** | 7 | 6 | 6 | 252 | Acquisition |
| 20 | **Create benchmark dataset (20 phishing + 20 legit)** | 6 | 7 | 5 | 210 | Trust (prove detection accuracy) |

**Total effort**: ~22 hours

---

## Tier 4 — WHEN YOU HAVE PAYING CUSTOMERS (ICE < 200)

| # | Item | ICE | Defer Until |
|---|------|-----|-------------|
| 21 | IMAP/auto-scan worker | 160 | 10+ active users |
| 22 | Team/collaboration features | 120 | 1+ paying business customer |
| 23 | API access | 100 | User requests it |
| 24 | Custom rules | 80 | User requests it |
| 25 | Browser extension | 60 | 50+ active users |

---

## ICE Score Summary

```
Tier 0 (ICE > 500):  5 items, ~4 hours → MAKES PRODUCT WORK
Tier 1 (ICE 400-500): 5 items, ~8 hours → MAKES PRODUCT GOOD
Tier 2 (ICE 300-400): 5 items, ~20 hours → ADDS REVENUE
Tier 3 (ICE 200-300): 5 items, ~22 hours → ADDS USERS
Tier 4 (ICE < 200):   5 items, deferred → ADDS SCALE
```

**Total to get to first paying customer: ~54 hours of focused work.**
