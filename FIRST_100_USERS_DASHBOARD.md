# First 100 Users Dashboard

## How to Track

All data lives in `data/phishguard.db`. Query directly or via the app's analytics.

### Key SQL Queries

```sql
-- Total users
SELECT COUNT(*) FROM tenants;

-- Users by plan
SELECT plan, COUNT(*) FROM tenants GROUP BY plan;

-- Active today (scanned in last 24h)
SELECT COUNT(DISTINCT tenant_id) FROM analysis_history
WHERE analyzed_at > datetime('now', '-1 day');

-- Total scans
SELECT COUNT(*) FROM analysis_history;

-- Scans per user (top 10)
SELECT tenant_id, COUNT(*) as scans FROM analysis_history
GROUP BY tenant_id ORDER BY scans DESC LIMIT 10;

-- Conversion funnel
SELECT
  (SELECT COUNT(*) FROM tenants) as signed_up,
  (SELECT COUNT(DISTINCT tenant_id) FROM analysis_history) as scanned,
  (SELECT COUNT(*) FROM tenants WHERE plan IN ('starter', 'business')) as paid;

-- Revenue
SELECT plan, COUNT(*) as users, COUNT(*) * CASE plan
  WHEN 'starter' THEN 29 WHEN 'business' THEN 99 ELSE 0
  END as monthly_revenue
FROM tenants WHERE plan IN ('starter', 'business')
GROUP BY plan;
```

## Milestone Checklist

### First 10 Users
- [ ] Verify signup flow works
- [ ] Verify first scan completes
- [ ] No Paddle webhook errors
- [ ] Welcome email received
- [ ] Activation rate > 50% (% who scan in first session)

### First 25 Users
- [ ] Check false positive rate < 5%
- [ ] Average scan time < 3 seconds
- [ ] No support requests for broken features
- [ ] Outbound email delivery 100%

### First 50 Users
- [ ] At least 1 paid conversion
- [ ] Daily active users > 10%
- [ ] Paddle revenue > $0
- [ ] No critical bugs reported

### First 100 Users
- [ ] Paid conversion rate > 3%
- [ ] Churn rate < 10% (if month-over-month)
- [ ] Average scans/user > 5
- [ ] MRR > $50
- [ ] Server cost < $100/mo

## Metrics Dashboard

For a quick Python check:
```python
import sqlite3, json
db = sqlite3.connect("data/phishguard.db")
c = db.execute("SELECT plan, COUNT(*) FROM tenants GROUP BY plan")
print("Users by plan:", dict(c.fetchall()))
c = db.execute("SELECT COUNT(*) FROM analysis_history")
print("Total scans:", c.fetchone()[0])
c = db.execute("SELECT COUNT(DISTINCT tenant_id) FROM analysis_history")
print("Users who scanned:", c.fetchone()[0])
```

## What to Watch
1. **Activation rate** — users who scan within 24h of signup. If < 40%, improve onboarding
2. **Scan-to-upgrade time** — average days between first scan and paid plan. Target < 7 days
3. **Detection accuracy** — if users report false positives > 5%, tune thresholds
4. **Email delivery** — if welcome/reset emails bounce, check SMTP config
5. **Server cost per user** — target < $2/user/month
