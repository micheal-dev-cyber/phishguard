# PhishGuard AI — First Revenue Playbook

## Revenue Principle

**You cannot charge someone for a product they cannot use.**

Before ANY pricing: auth flow must work, SMTP must send email, AI must analyze, demo must be shareable. These are prerequisites, not features.

---

## What's Required Before Charging

1. **Auth flow end-to-end** — signup → verification email arrives → login works
2. **Public deployment URL** — product is at a real internet address
3. **AI analysis works** — at minimum Groq API key configured
4. **Fake claims removed** — trust bar, testimonials, SOC 2, pen test
5. **Paddle sandbox configured** — API key, client token, price IDs set
6. **Checkout wired** — "Subscribe" buttons generate real Paddle checkout URLs
7. **Paddle webhook receives events** — transactions.completed updates user plan in DB

**These 7 items are the billing-critical path. They require:**
- 4 env var groups (SMTP, APP_URL, GROQ, Paddle)
- 3 code changes (fake claims removal, wire checkout, test webhook)
- 1 deployment

**Total: ~12 hours of work before you can accept a credit card.**

---

## Pricing Tiers

### Free Plan ($0/mo) — "Try before you buy"

| Feature | Value |
|---------|-------|
| Monthly analyses | 10 |
| Detection engines | Heuristic + header analysis |
| URL scanning | Regex-based detection |
| Risk scoring | 0-100 score + severity |
| PDF export | Yes |
| Demo access | Unlimited |
| Support | Community (GitHub Issues) |

**Purpose:** Acquisition. Remove every friction to trying the product. No credit card required. No time limit (usage-capped, not time-capped).

**Why 10 scans/month:** Enough to evaluate the product over 2-3 weeks (test 3 real emails). Forces upgrade when the user sees value.

### Starter Plan ($29/mo) — "Individual security pro"

| Feature | Value |
|---------|-------|
| Monthly analyses | 100 |
| Detection engines | Everything in Free + SPF/DKIM/DMARC |
| URL scanning | VirusTotal (90+ vendors) |
| AI threat narrative | Full Groq/LLM analysis |
| OSINT investigation | Domain WHOIS, geolocation, registrar |
| AI security report | Generated PDF with AI narrative |
| Email support | 24h response |
| | |
| **Scarcity:** 100 scans/mo | Upgrade to Business if you need more |

**Expected conversion rate from Free:** 2-5% of activated users → Starter within 30 days.

**$29 price justification:** Cheaper than 1 hour of IT consulting. Equivalent to 1 coffee/day for security protection. Below the "think about it" threshold for most professionals.

### Business Plan ($99/mo) — "SMB team"

| Feature | Value |
|---------|-------|
| Monthly analyses | 500 |
| Everything in Starter | Yes |
| Priority support | 4h response |
| Team seats | 3 users included |
| API access | REST API for automation |
| Bulk export | CSV/JSON for SIEM ingestion |

**Expected conversion rate from Starter:** 10-15% of Starter users → Business within 90 days.

**$99 price justification:** For a team of 3, that's $33/user/month. Priced below per-user tools. The 500-scan cap means ~165 scans/user/month for a 3-person team.

### Enterprise (Custom pricing) — "Don't offer yet"

**Don't list Enterprise prices. Don't build Enterprise features.**
Redirect Enterprise inquiries to a "Contact us" flow. When someone asks, have a conversation. Don't guess what they need.

**Why:** Enterprise pricing requires negotiation, contracts, procurement, and custom features. At 0 users, you have zero credibility for any of these. First get 50 Starter subscribers, then think about Enterprise.

---

## Billing Architecture

```
User clicks "Subscribe — Starter" in app.py:604
    │
    ▼
app.py:608 → generate_checkout_url(username, "starter", success_url)
    │
    ▼
paddle_billing.py:49 → POST /transactions with price_id + custom_data
    │
    ▼
Paddle returns checkout URL (hosted payment page)
    │
    ▼
User completes payment on Paddle.com
    │
    ├─ User redirected back to success_url
    │  └─ app.py:529-538 → verify_transaction() → update_tenant(plan="starter")
    │
    └─ Paddle sends webhook to /webhook
       └─ app.py:291-320 → handle_webhook_event() → update_tenant(plan="starter")
```

**Already coded.** The entire flow from `app.py:604` (button) → `paddle_billing.py:49` (checkout URL) → `app.py:529` (return handler) → `paddle_billing.py:330` (webhook) exists and is wired. The only missing piece is the env vars.

## Revenue Projections (First 90 Days)

### Pessimistic

| Metric | Month 1 | Month 2 | Month 3 |
|--------|---------|---------|---------|
| Signups | 40 | 60 | 80 |
| Activated users | 25 | 40 | 55 |
| Free users | 25 | 38 | 49 |
| Starter conversions | 0 | 2 | 4 |
| Business conversions | 0 | 0 | 1 |
| MRR | $0 | $58 | $174 |

### Realistic

| Metric | Month 1 | Month 2 | Month 3 |
|--------|---------|---------|---------|
| Signups | 80 | 120 | 200 |
| Activated users | 50 | 80 | 130 |
| Free users | 48 | 73 | 115 |
| Starter conversions | 2 | 5 | 10 |
| Business conversions | 0 | 2 | 5 |
| MRR | $58 | $343 | $785 |

### Optimistic (Product Hunt front page + HN front page + viral Reddit)

| Metric | Month 1 | Month 2 | Month 3 |
|--------|---------|---------|---------|
| Signups | 200 | 400 | 800 |
| Activated users | 130 | 260 | 520 |
| Free users | 123 | 237 | 456 |
| Starter conversions | 5 | 15 | 35 |
| Business conversions | 2 | 8 | 29 |
| MRR | $343 | $1,227 | $3,886 |

**Target:** $1,000 MRR by Month 3 (realistic case).

## Churn Prevention

### Before Churn Happens

1. **Usage-based upgrade prompt:** When user hits 70%+ of scan quota, show a subtle "You're running low on scans — upgrade to Starter for 100 scans/mo" in the dashboard (`app.py:968-969` — already coded).

2. **Email notification at 80% usage:** Not possible until SMTP is configured. Once it is, `usage_log` query → email when approaching limit.

3. **In-app value reinforcement:** After each scan, show "We found X suspicious indicators — this would have been missed by basic email filtering." Reinforce the value of the analysis itself.

### When Churn Happens

1. **Downgrade from Starter → Free:** Not a churn — they're still in the product. Send an email: "Your Starter plan was downgraded. You still have 10 free scans/month. Need more? Restart Starter below."

2. **Cancel from Free:** 0 usage for 30 days → email: "Haven't seen you in a while. Got a suspicious email? Paste it here → [demo link]"

3. **Cancel from Starter:** Request reason in Paddle cancellation survey. Email 3 days later: "Sorry to see you go. Here's one thing you might have missed: [feature]. Back anytime."

## Pricing Page Content (for app.py pricing section)

Replace current pricing bloat (`auth.py:863-888`) with:

**Free** — $0 — 10 scans/mo — Risk scoring, URL detection, PDF export
**Starter** — $29/mo — 100 scans — VirusTotal, AI narrative, OSINT, SPF/DKIM/DMARC
**Business** — $99/mo — 500 scans — Team seats (3), API access, priority support
**Enterprise** — Custom — For organizations needing custom deployment, SSO, and SLA

Remove the Consultant tier ($149/mo) — it confuses the pricing ladder. 4 tiers is too many for 0 users. 3 tiers (Free + Starter + Business) is the standard SaaS model.

## Action Items

| # | What | Who | When |
|---|------|-----|------|
| 1 | Create Paddle Sandbox account | Founder | Day 1 |
| 2 | Create 3 price IDs in Paddle (Free=$0, Starter=$29/mo, Business=$99/mo) | Founder | Day 1 |
| 3 | Set all Paddle env vars in deployment | Founder | Day 1 |
| 4 | Run sandbox transaction end-to-end: click Subscribe → enter test card → verify plan upgrade in DB | Founder | Day 1 |
| 5 | Replace pricing UI in `auth.py:863-888` (remove Consultant tier, simplify tiers) | Dev | Day 2 |
| 6 | Test downgrade flow: cancel subscription → verify user returns to Free | Founder | Day 2 |
| 7 | Switch Paddle to production after first successful sandbox transaction | Founder | Day 30 (or when first real user reaches 10 scans) |
