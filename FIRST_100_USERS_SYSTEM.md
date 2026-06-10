# PhishGuard AI — First 100 Users System

> No paid ads. No growth team. No content calendar with 50 blog posts.
> 
> Minimum viable growth engine: **product quality + founder-led sales + 3 channels.**

---

## The Product Angle: "Free Phishing Email Analyzer"

The single highest-leverage growth move is repositioning from "AI-powered security platform" to:

> **"Paste any suspicious email. Instantly know if it's phishing. Free. No account required."**

This changes everything:
- No signup friction → anyone can try it
- Viral sharing → "I got a phishing email, let me check it"
- Embeddable → widget on any security blog
- Linkable → `phishguard.ai/analyze?email=...`

### Landing Page Redesign (Current is Wrong)

**Current**: Hero → Features → Testimonials (fake) → Pricing → Signup
**Should be**: Hero → **INSTANT DEMO** → Signup (optional) → Features → Pricing

The hero should be the demo scan, not marketing copy. Show results first. Ask for signup later.

---

## Channel 1: Hacker News "Show HN" (Launch Day)

### Preparation (Week 1-2)
- [ ] Product live at public URL with working demo (no signup needed)
- [ ] Remove all fake claims — replace with honest "beta" messaging
- [ ] Write a detailed technical blog post: "How I built a phishing detector in 30 days"
- [ ] Prepare demo video (30 seconds, screen recording)
- [ ] Make the free demo actually impressive (full analysis, not gated)

### The Post
- Title: "Show HN: PhishGuard – Paste any email, instantly know if it's phishing"
- First comment: Technical deep-dive about regex engine, SPF/DKIM/DMARC parsing, challenges
- Be ready to answer questions for 24 hours
- Have a "Launch HN" version if you have YC connections

### Expected Outcome
- 500-2000 visitors
- 30-100 signups (if demo impresses)
- 5-10 engaged users who provide feedback

### Required Product State
- Demo works without account
- Signup works (SMTP configured)
- AI analysis works (Groq key configured)
- Detection catches the example phish you post
- No fake claims on site

---

## Channel 2: Reddit (r/cybersecurity, r/sysadmin, r/blueteamsec)

### Strategy
Don't post links. Post value.

- **r/cybersecurity**: "I built a free phishing email analyzer. Here's the technical breakdown of how it detects spoofed domains." → Link in comments
- **r/sysadmin**: "PSA: You can check suspicious emails by pasting them into this free tool" → Link in comments
- **r/blueteamsec**: Technical post about SPF/DKIM/DMARC parsing challenges

### Weekly Actions
- [ ] 1 Reddit post per week in a relevant subreddit
- [ ] Never link directly — always provide value first
- [ ] Respond to every comment within 2 hours
- [ ] Track traffic from each post

### Expected Outcome
- 200-1000 visitors per post
- 10-50 signups per good post
- Quality feedback from security professionals

---

## Channel 3: Founder-Led LinkedIn

### Strategy
No company page. Personal profile only.

Post 3x/week:
- Mon: Technical insight (phishing technique breakdown)
- Wed: Product update (new feature, improvement)
- Fri: Personal/reflection (building in public)

### Sample Posts
- "Most phishing detection tools cost $1000+/mo. I built one that runs on regex and gives you the answer in 2 seconds. Here's how it works."
- "Just detected my first real phishing email with my own tool. The SPF check caught it — the sender domain wasn't authorized to send for the domain it claimed to be from."
- "I spent 6 months building a phishing detector. 0 users. 0 revenue. Here's what I learned about building in public."

### Daily Actions
- [ ] Engage with 10 security-related posts/day
- [ ] Respond to every comment within 1 hour
- [ ] DM 3 potential users/day with personalized message
- [ ] Share any user wins or testimonials (real ones)

### Expected Outcome
- 50-200 profile visitors/day
- 5-20 signups/week
- 1-3 qualified conversations/week

---

## Channel 4: Cold Email Outreach (IT Managers)

### Target List
- IT managers at SMBs (50-500 employees)
- Managed service providers (MSPs) 
- School IT departments
- Nonprofit tech leads

### Message Template
```
Subject: Free phishing detection tool (no signup, no upsell)

Hi [Name],

I built a phishing email analyzer that's free to use — no account, no credit card, no upsell.

Your team can paste any suspicious email and get an instant analysis: risk score, URL reputation, SPF/DKIM/DMARC check, and recommended actions.

It's not a replacement for your existing security stack. It's a quick sanity check when someone forwards you a suspicious email.

Would love for you to try it: [URL]

Feedback welcome,
[Your name]
```

### Weekly Actions
- [ ] Send 20 cold emails/week
- [ ] Follow up with non-responders after 5 days
- [ ] Track open rate, click rate, signup rate
- [ ] Iterate on messaging based on responses

### Expected Outcome
- 30% open rate
- 10% click rate
- 2% signup rate
- 1-2 qualified conversations per 100 emails

---

## Channel 5: Product Hunt Launch

### Preparation (Week 3-4)
- [ ] Product has been live for 2+ weeks with real usage
- [ ] Have at least 10 real users with positive feedback
- [ ] Prepare launch assets: tagline, logo, demo GIF, description
- [ ] Recruit 3-5 people to leave genuine reviews on launch day
- [ ] Prepare for maker commentary (respond to every comment)

### Launch Day
- Schedule: Tuesday or Wednesday morning (EST)
- Title: "PhishGuard – Free AI phishing email analyzer"
- Tagline: "Paste any email. Instantly know if it's phishing."
- First comment: Founder story + technical details
- Engage with every comment for 24 hours

### Expected Outcome
- 1000-5000 visitors
- 50-200 signups
- 100-500 upvotes

---

## KPIs: First 100 Users

### Acquisition Metrics
| Metric | Target | Timeline |
|--------|--------|----------|
| Unique visitors | 5,000 | 30 days |
| Demo scans | 1,000 | 30 days |
| Signups | 200 | 30 days |
| Signup rate (from visitor) | 4% | — |
| Signup rate (from demo) | 20% | — |

### Activation Metrics
| Metric | Target | Timeline |
|--------|--------|----------|
| Email verified | 180 (90% of signups) | Within 24h |
| First scan completed | 100 (50% of signups) | Within 7 days |
| Time to first scan | < 2 minutes | — |
| Onboarding completion | 80% of verified users | — |

### Retention Metrics
| Metric | Target | Timeline |
|--------|--------|----------|
| Day 1 return rate | 30% | — |
| Day 7 return rate | 15% | — |
| Day 30 return rate | 10% | — |
| Scans per active user | 5+/month | Month 2+ |

### Revenue Metrics
| Metric | Target | Timeline |
|--------|--------|----------|
| Upgrade clicks | 10% of active users | — |
| Trial → paid conversion | 5% | — |
| First $1 revenue | < 60 days | — |
| First $100 MRR | < 90 days | — |

### Funnel Targets (100 users)
```
10,000 visitors (via all channels)
  → 1,000 demo scans (10% conversion)
    → 200 signups (20% of demo users)
      → 180 verified (90%)
        → 100 first scans (55% of verified)
          → 30 day-1 returnees (30%)
            → 10 day-7 returnees (33% of D1)
              → 5 paying customers (5% of active)
```

---

## Weekly Growth Cadence

| Day | Growth Activity | Time |
|-----|----------------|------|
| Monday | LinkedIn post + 10 engagements | 30 min |
| Tuesday | Cold email 10 prospects | 30 min |
| Wednesday | Reddit post + respond to comments | 30 min |
| Thursday | LinkedIn post + DM 3 prospects | 30 min |
| Friday | Follow up on cold emails + weekly metrics review | 30 min |
| Saturday | Content prep for next week | 30 min |
| Sunday | Rest | — |

**Total growth time: ~3.5 hours/week**

---

## What NOT to Do

- ❌ SEO blog strategy (6-month payback period, zero users today)
- ❌ Paid ads (burn cash you don't have for users who won't convert)
- ❌ Social media automation (engagement requires authenticity)
- ❌ Content calendar with 50 articles (write zero articles before launch)
- ❌ Product Hunt pre-launch page (focus on making the product work first)
- ❌ Building a community (communities require critical mass)
- ❌ Agency partnerships (too early, no track record)

---

## The 30-Day Launch Sprint

| Day | Product Work | Growth Work |
|-----|-------------|-------------|
| 1-3 | SMTP, AI key, deploy, fix fake claims | — |
| 4-7 | Wire header auth, unlock demo, VT key | Prepare HN post |
| 8-10 | Onboarding, session persistence | Cold email 20 prospects |
| 11-14 | Paddle setup, pricing CTA | LinkedIn posts (3x) |
| 15-17 | Narrative engine, result UX | Reddit posts (2x) |
| 18-21 | Bug fixes from first users | Product Hunt prep |
| 22-24 | Polish, benchmark | Cold email follow-ups |
| 25-27 | Stability improvements | Product Hunt launch |
| 28-30 | Fix what broke | Analyze all data, iterate |

**After 30 days**: Goal is 10-20 active users and clear signal on whether the product solves a real problem. If yes → double down. If no → pivot fast.
