# Production Launch Checklist

## Pre-Launch (1 week before)

### Billing & Pricing
- [ ] Paddle sandbox checkout tested end-to-end with test card
- [ ] `PADDLE_ENVIRONMENT=production` set (not sandbox)
- [ ] Live price IDs verified against Paddle dashboard
- [ ] Webhook URL configured in Paddle dashboard → `https://phishguard.ai/paddle-webhook`
- [ ] Webhook secret key stored in `.env`
- [ ] Free tier limits confirmed (scans/day, users, storage)
- [ ] Refund policy drafted and linked in billing UI

### Email Delivery
- [ ] SMTP provider configured (SendGrid / Mailgun / SES)
- [ ] DKIM/SPF set up for sending domain
- [ ] Transactional email templates reviewed
- [ ] Welcome email triggered on new signup (tested)
- [ ] Password reset flow tested end-to-end
- [ ] Magic link login tested

### Detection Engine
- [ ] VirusTotal API key active (enhances URL/domain checks)
- [ ] OpenRouter API key active (AI analysis)
- [ ] Detection benchmark tests pass (12/12)
- [ ] False positive rate acceptable on benchmark suite (legit ≤ 25 score)
- [ ] Phishing kit signatures loaded

### Infrastructure
- [ ] `APP_URL` set to production domain
- [ ] HTTPS enabled (Cloudflare / Let's Encrypt)
- [ ] Database backups configured (daily)
- [ ] Logging configured (JSON logs → stdout)
- [ ] Monitoring endpoint (`/health`) checked externally
- [ ] Rate limits configured (analysis: 15/min per user)

### Security
- [ ] Admin password changed from default
- [ ] `.env` file permissions locked (400)
- [ ] No secrets in git history (check with `git secrets`)
- [ ] Session timeout configured
- [ ] SSO/MFA tested if enabled

## Launch Day

### Go / No-Go
- [ ] All pre-launch items checked
- [ ] Last 312+ tests pass
- [ ] Canaries deployed (internal users test)
- [ ] Rollback plan documented
- [ ] Support contact ready

### Launch Sequence
1. Push code to production
2. Run `python src/migrate.py`
3. Start `webhook.py` (Flask)
4. Start Streamlit `app.py`
5. Verify `/health` OK
6. Run smoke test: scan, signup, upgrade
7. Open public access

### First 24 Hours Monitoring
- [ ] Error rate (target < 0.1%)
- [ ] Signup rate
- [ ] Scan completion rate
- [ ] Paddle webhook success rate
- [ ] Email delivery rate
- [ ] API response time (target < 2s per scan)

## Post-Launch (first 30 days)
- [ ] Collect user feedback on detection accuracy
- [ ] Review false positive reports
- [ ] Monitor Paddle revenue dashboard
- [ ] Track activation rate (% of signups who scan)
- [ ] Track conversion rate (% free → paid)
- [ ] Review server costs vs. budget
- [ ] Publish first changelog/update

## Rollback Plan
```bash
# If critical issues found:
git revert HEAD --no-commit
streamlit stop
python webhook.py  # restart without webhook if needed
# Or: revert PADDLE_ENVIRONMENT=sandbox to disable live billing
```
