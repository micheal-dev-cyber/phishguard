# Day 0 Launch Playbook

## Pre-Flight Checklist (T-24h)
- [ ] All 6 critical blockers resolved (see LAUNCH_BLOCKERS_CHECKLIST.md)
- [ ] `PADDLE_ENVIRONMENT=production` confirmed
- [ ] Paddle webhook URL configured in Paddle dashboard
- [ ] SMTP credentials verified — send test email
- [ ] `APP_URL` set to production domain
- [ ] `VIRUSTOTAL_API_KEY` set
- [ ] Full test suite passes: `python -m pytest tests/ -q`
- [ ] End-to-end payment test with real card (refund immediately)
- [ ] Backup database: `python src/backup.py`
- [ ] Smoke test: signup → scan → PDF → upgrade (sandbox mode)

---

## Hour 0: Deployment
**Action**: Push to production
```
git push production main
ssh server "cd /opt/phishguard && git pull && pip install -r requirements.txt && python src/migrate.py"
ssh server "sudo systemctl restart phishguard-webhook phishguard-app"
```

**Verify**:
- [ ] `curl https://yourdomain.com/health` returns `{"status":"ok"}`
- [ ] Streamlit app loads without errors
- [ ] Webhook endpoint responds: `curl -X POST https://yourdomain.com/paddle-webhook -H "Content-Type: application/json" -d '{}'`
- [ ] SMTP test: send a real welcome email to yourself

---

## Hour 0-1: Product Hunt Launch
**Action**: Submit to Product Hunt

**Prep needed before**:
- [ ] 3 screenshots uploaded (results page, PDF report, dashboard)
- [ ] Short demo GIF ready (optional but recommended)
- [ ] Maker comment drafted: "Hi PH! We built PhishGuard because most phishing tools are either free-but-limited or enterprise-expensive. Paste any email, get an instant analysis. Would love your feedback!"

**Monitoring**:
- [ ] Check signup rate every 15 min
- [ ] Check scan completion rate
- [ ] Watch for error spikes in logs
- [ ] Reply to every comment within 30 min

---

## Hour 1-2: Hacker News Post
**Action**: Submit "Show HN: PhishGuard – Paste any email, instantly detect phishing"

**Title**: `Show HN: PhishGuard – Paste any email, instantly detect phishing`
**URL**: `https://yourdomain.com`

**Prep needed before**:
- [ ] Write comment explaining how detection works technically
- [ ] Be ready for tough technical questions about detection methodology
- [ ] Have benchmark results ready to share

**Monitoring**:
- [ ] Check HN thread every 10 min
- [ ] Flag any technical inaccuracies in comments and correct them
- [ ] Don't defend fake claims — we removed them all, be transparent

---

## Hour 2-4: Reddit Posts
**Action**: Post to relevant subreddits

**r/cybersecurity**:
- Title: "Built an open-source phishing email analyzer — paste any email, get a risk score"
- Content: Technical overview of detection engine, invite feedback
- Do NOT link directly (Reddit shadowbans product links) — use text post

**r/SaaS**:
- Title: "Launched my first SaaS — feedback on landing page welcome"
- Focus on business lessons, not product

**Monitoring**:
- [ ] Check threads every 30 min
- [ ] Be transparent about being a new product
- [ ] Offer to answer technical questions

---

## Hour 2-4: LinkedIn Post
**Action**: Publish company announcement

**Prep needed before**:
- [ ] Company LinkedIn page created
- [ ] Team members (if any) reshare post
- [ ] Post content: problem → solution → CTA

**Post draft**:
```
🛡️ We just launched PhishGuard — a phishing email analyzer that anyone can use.

Paste a suspicious email. Get a risk score, threat breakdown, and PDF report in seconds.

Built for teams that need inbox protection but don't have a dedicated security budget.

Try it free → https://yourdomain.com

#cybersecurity #phishing #infosec #saas
```

---

## Hour 6: First Check-In
**Metrics to review**:
- [ ] Signups: count
- [ ] Scans completed: count
- [ ] Activation rate (% who scanned within 1 hour of signup)
- [ ] Error rate (target < 0.1%)
- [ ] Server CPU/memory (should be idle)

**If any metric is red**:
- Signups = 0 → check landing page, CTA, deployment URL
- Scans = 0 → check detector.py, OpenRouter key
- Error rate > 1% → check logs, rollback if needed
- Server > 80% CPU → scale up

---

## Hour 12: Second Check-In
**Metrics to review**:
- [ ] Total signups (target: 10-50 from PH/HN/Reddit combined)
- [ ] Activation rate (target: > 50%)
- [ ] Any paid conversions (target: 1 if pricing is live)
- [ ] Support emails received
- [ ] Top referring source (PH vs HN vs Reddit vs LinkedIn vs direct)

**If activation rate < 50%**:
- Onboarding is confusing → add more guidance
- Demo not working → fix anonymous demo flow
- Too many steps → consider removing email requirement from signup

---

## Hour 18: Third Check-In
**Metrics to review**:
- [ ] Signups since launch
- [ ] Retention: users who scanned > 1 email
- [ ] Any bugs reported
- [ ] Server cost so far

**Actions**:
- [ ] Reply to all remaining comments on PH and HN
- [ ] Share early metrics on LinkedIn (if positive)
- [ ] Prepare bug fix deploy if needed

---

## Hour 24: Launch Retro
**Metrics**:
- [ ] Total signups: _____
- [ ] Active users (scanned > 1 email): _____
- [ ] Paid conversions: _____
- [ ] Revenue: _____
- [ ] Top channel: _____
- [ ] Critical bugs found: _____
- [ ] Server cost: _____

**Go/No-Go for second day**:
- If > 50 signups → keep pushing, post follow-up content
- If 10-50 signups → standard day 2 — engage with users who signed up
- If < 10 signups → something fundamentally broken — investigate landing page, pricing, value prop

**Post-launch checklist**:
- [ ] Thank everyone who commented/signed up
- [ ] Publish first changelog with launch stats (transparent)
- [ ] Plan week 1: fix bugs, help first users, get first testimonial
- [ ] Start collecting feedback for v2

---

## Quick Reference: Key Commands

```bash
# Check logs
journalctl -u phishguard-app --since "1 hour ago"
journalctl -u phishguard-webhook --since "1 hour ago"

# Check database
sqlite3 data/phishguard.db "SELECT COUNT(*) FROM tenants;"
sqlite3 data/phishguard.db "SELECT plan, COUNT(*) FROM tenants GROUP BY plan;"
sqlite3 data/phishguard.db "SELECT COUNT(*) FROM analysis_history;"

# Quick rollback if needed
git revert HEAD --no-commit
sudo systemctl restart phishguard-app

# Backup
python src/backup.py
```
