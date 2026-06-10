# PhishGuard AI — First 100 Users Roadmap

## Target: 100 users in 30 days

---

## Pre-Launch Checklist (Day 0-2)

Before any growth channel goes live, the product must not lie to or break for visitors.

- [ ] Fake claims removed from landing page (trust bar, testimonials, SOC 2, pen test)
- [ ] SMTP configured → full auth flow works
- [ ] APP_URL set → verification/magic/reset links work
- [ ] GROQ_API_KEY set → AI analysis live
- [ ] VIRUSTOTAL_API_KEY set → URL reputation live
- [ ] Public deployment URL live
- [ ] `/demo` deep-link works (shareable demo, no auth required)
- [ ] Onboarding wizard triggers on first login
- [ ] Paddle sandbox configured (billing testable in staging)

**If any of these are broken, every acquisition dollar is wasted.**
**Effort: ~12 hours. Must be done before Day 3.**

---

## Channel 1: Hacker News (Day 3)

### Target: "Show HN" — launch story

**Title:** Show HN: I built a free phishing email analyzer — paste any email, get a risk score in 2 seconds

**Strategy:**
- Post at 8:00 AM ET on Tuesday (highest HN engagement)
- First comment: direct link to `/demo` (no signup required)
- Lead with the pain: "Every SMB gets phishing emails. Most tools cost $50+/mo. I made a free one that works in 2 seconds."
- Embed the demo link naturally: "Try it here — no account needed → phishguard.ai/demo"

**Expected conversion:**
- HN front page = ~5,000-15,000 views
- Demo click-through rate: ~10% = 500-1,500 demo visits
- Demo → Signup: ~3% = 15-45 signups
- Signup → Activated (1 scan): ~60% = 9-27 activated users

**Actual benchmark (realistic):** 10-30 signups from a modest Show HN post

## Channel 2: Reddit (Day 3-10)

### Subreddits

| Subreddit | Subs | Post Type | Title Angle | Expected Signups |
|-----------|------|-----------|-------------|------------------|
| r/cybersecurity | 1.5M | Tool sharing | "I built a free phishing analyzer. Here's how it works (and what it catches)" | 5-15 |
| r/blueteamsec | 200K | Technical deep-dive | "We needed a free phishing analysis tool. So I built one — open source, API-first, SPF/DKIM/DMARC parser included" | 3-8 |
| r/selfhosted | 400K | Self-hosted tool | "Self-hosted phishing email analyzer — paste any email, get risk score + header analysis (SPF/DKIM/DMARC)" | 5-10 |
| r/SaaS | 500K | Founder story | "How I built a phishing analyzer as a solo founder — and why I'm giving it away for free" | 2-5 |
| r/startups | 2M | Launch story | "Zero to launch: building a security SaaS as a solo dev" | 3-8 |

**Total Reddit expected signups: 18-46**

### Reddit Strategy
- Post in technical subreddits first (r/blueteamsec, r/cybersecurity)
- Never post links without value. Each post should teach something: "Here's how SPF/DKIM/DMARC parsing works in Python"
- Link to public demo in the post body
- Engage every comment (answer questions within 1 hour)
- Cross-post only where relevant (don't spam)

## Channel 3: Product Hunt (Day 5)

### Strategy

| Element | Detail |
|---------|--------|
| Launch day | Tuesday (best PH day) |
| Time | 12:01 AM PT (auto-scheduled) |
| Category | Security / Productivity |
| Maker comment | Lead with: "Phishing is the #1 attack vector for SMBs. Most tools are enterprise-priced. I built one that's free." |
| First 10 supporters | DM 10 security colleagues/friends to upvote in first hour |
| Product URL | Direct to `/demo` (no signup gate) |
| Tagline | "Free phishing email analyzer — paste any email, get risk score + AI analysis in 2 seconds" |

**Expected conversion:**
- 100-300 upvotes (early-stage product)
- ~1,000-3,000 visits from PH
- Demo → Signup: ~2% = 20-60 signups
- Actual benchmark (realistic): 10-25 signups from PH

## Channel 4: LinkedIn (Day 5-30)

### Content Plan (3x/week)

| Post | Angle | Target |
|------|-------|--------|
| 1 | Launch story: "I built a free phishing analyzer as a solo founder" | Founders, SMB owners |
| 2 | Technical: "How SPF/DKIM/DMARC works (with real Python code)" | Security engineers |
| 3 | Threat landscape: "5 phishing trends in 2026 that SMBs need to know" | IT managers |
| 4 | Customer story: "How [Company] caught a spear-phishing attempt" | Case study |
| 5 | Product update: "New feature announcement" | Existing users |
| 6 | Educational: "How to spot a phishing email in 30 seconds" | General audience |

**Direct outreach: 100 SMB IT managers**
- Search: "IT Manager", "Security Engineer", "IT Director" at companies with 20-500 employees
- Personalized connection request: "Hey [Name], I built a free phishing analysis tool — thought your team might find it useful. Happy to share early access."
- No hard sell. Just value + free tool.
- After connecting: send the `/demo` link
- Expected: 25-35% connection rate, 10-15% try the demo, 2-3 signups

**Total LinkedIn expected signups: 10-20**

## Channel 5: Direct Outreach (Day 7-30)

### Cold Email
- Build list of 200 SMB IT leaders (LinkedIn Sales Navigator or manual search)
- Send from personal email (not Mailchimp — keep it manual)
- Template:
  ```
  Subject: Free phishing analysis tool for [Company]

  Hi [Name],

  I built PhishGuard — a free tool that analyzes phishing emails in 2 seconds.

  No setup, no cost. Just paste the email and get a risk score, header analysis (SPF/DKIM/DMARC), and AI threat narrative.

  Try it here (no account needed): [demo link]

  Would love your feedback.

  Best,
  [Your name]
  ```

**Expected conversion:**
- 200 emails sent
- Open rate: ~50% = 100 opens
- Click rate: ~10% = 20 demo visits
- Demo → Signup: ~5% = 10 signups
- Total: 10 signups per batch

### Community
- Post in 5 security communities/forums: Security Stack Exchange, BleepingComputer, Wilders Security, Spiceworks, SANS ISC
- Each post: answer a question + mention the tool as a resource
- Expected: 1-2 signups per community = 5-10 total

## Conversion Funnel

```
Visit (demo page)
│
├─ Run demo scan (60% of visits)
│  └─ See results (100%)
│     ├─ Sign up for full access (3-5%)
│     └─ Leave (95-97%)
│
├─ Try example email (15% of visits)
│  └─ Same as above
│
└─ Leave immediately (25% of visits)
```

### Funnel by Channel

| Channel | Visits | Demo Runs | Signups | Activated (1 scan) |
|---------|--------|-----------|---------|-------------------|
| Hacker News | 500-1,500 | 300-900 | 9-27 | 5-16 |
| Reddit (5 posts) | 2,000-5,000 | 1,200-3,000 | 18-46 | 11-28 |
| Product Hunt | 1,000-3,000 | 600-1,800 | 10-25 | 6-15 |
| LinkedIn | 300-500 | 180-300 | 10-20 | 6-12 |
| Direct outreach | 200-400 | 120-240 | 15-25 | 9-15 |
| **Total** | **4,000-10,400** | **2,400-6,240** | **62-163** | **37-86** |

**Realistic target:** 50-80 activated users in first 30 days.
**Stretch target:** 100 activated users in first 30 days.

## Activation (getting from signup → first scan)

The single most important metric is **activated users** (signed up + ran ≥1 scan).

To maximize activation:

1. Onboarding wizard (`app.py:446-449`) fires immediately after first login
2. Onboarding wizard loads the example phishing email into the scan box
3. User just clicks "Analyze" — zero friction to first value
4. After first scan, show: "Want to try with a real email you received? Paste it above."

## KPIs

| KPI | Target (30 days) | Measured By |
|-----|------------------|-------------|
| Website visits | 5,000 | Server logs / Plausible |
| Demo scans run | 2,500 | `analytics.track_event('demo_scan')` |
| Signups | 100 | `analytics.track_signup()` |
| Activated users (≥1 scan) | 60 | `analytics.track_event('first_scan')` |
| Day 7 retained | 20 | Login within 7 days of signup |
| Paid conversions | 2 | Paddle subscription created |
| MRR | $58-198 | Paddle revenue |
| NPS (if measured) | ≥30 | Survey after 7 days |

## What NOT to Do

- Do NOT post on LinkedIn with "I'm thrilled to announce" — nobody cares about your launch announcement
- Do NOT build a waitlist — 0 users means 0 demand, a waitlist is theater
- Do NOT ask for feedback before people try the product — 99% of "would you use this?" answers are wrong
- Do NOT try to sell "Enterprise" — it's a free demo tool until proven otherwise
- Do NOT email every tech blog for coverage — it's a 2-year-old codebase with 0 users, journalists don't care
