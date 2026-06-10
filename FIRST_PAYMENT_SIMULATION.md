# First Payment Simulation

## Scenario
User has completed their free trial, wants to upgrade to Starter ($29/mo). This document traces every code path involved.

## Step 1: Pricing Page
**Path**: Sidebar → Billing tab or "Upgrade" button
**Code**: `app.py` lines 560-653

**What user sees**:
- Two plans: Starter ($29/mo) and Business ($99/mo)
- Each shows feature list
- "Subscribe" / "Upgrade" button per plan

**Status**: ✅ Works. Consultant/enterprise already removed.

## Step 2: Paddle Checkout
**Path**: Click "Subscribe" → Paddle.js overlay opens
**Code**: `app.py` lines 588-630

**What happens**:
1. `generate_checkout_url(plan)` called (src/paddle_billing.py)
2. Paddle client-side JS opens checkout overlay
3. User fills payment info → Paddle processes
4. On success: Paddle redirects to `?checkout=completed&transaction_id=...`

**Status**: ⚠️ BLOCKED
**Blockers**:
1. **`PADDLE_ENVIRONMENT=sandbox`** (`.env` line 10) — checkout uses sandbox API, transaction never finalizes with live keys
2. **No `PADDLE_WEBHOOK_SECRET` in `.env`** — Wait, it IS there at line 6. Secret is configured. ✅
3. **Client token is live, environment is sandbox** — Paddle rejects mixed-mode configs. Must set `PADDLE_ENVIRONMENT=production`.

## Step 3: Paddle Webhook
**Path**: Paddle → POST → `https://yourdomain.com/paddle-webhook`
**Code**: `webhook.py` (Flask) + `app.py` lines 285-328 (Tornado handler)

**What should happen**:
1. Paddle sends `transaction.completed` webhook
2. Server verifies `Paddle-Signature` header using `PADDLE_WEBHOOK_SECRET`
3. Event parsed → `handle_webhook_event()` called
4. User's plan upgraded in database: `tenants` table `plan` = "starter" or "business"

**Status**: ❌ CRITICAL BLOCKER
**Blockers**:
1. **Two webhook handlers exist**: `webhook.py` (Flask standalone) AND `app.py` lines 285-328 (Tornado handler mounted on Streamlit). This creates ambiguity about which is active.
2. **No public URL**: Webhook endpoint is `localhost:5000` or embedded in Streamlit. Paddle cannot reach `localhost`.
3. **No webhook URL configured in Paddle dashboard** — this is an external setup step.

## Step 4: Subscription Activation
**Path**: Webhook received → plan upgraded → user sees new features
**Code**: `src/paddle_billing.py` → `handle_webhook_event()`

**What should happen**:
1. `handle_webhook_event(event_body, webhook_secret)` verifies and parses
2. For `transaction.completed`: extracts `custom_data.user_id`, calls `activate_plan(user_id, plan)`
3. For `subscription.cancelled`: calls `downgrade_to_trial(user_id)`
4. User now has "starter" or "business" plan → more scans, VT access, AI reports

**Status**: ⚠️ CODED BUT UNTESTABLE
**Blockers**:
- Cannot test without live Paddle → real payment → real webhook → callback to public URL
- Unit tests pass (41 billing tests) but no end-to-end test possible without deployment

## Step 5: Post-Upgrade Enforcement
**Path**: User accesses premium features after upgrade
**Code**: `app.py` + plan checks throughout

**What should happen**:
- `user_tier` = "starter" → 100 scans/month, VT integration enabled
- `user_tier` = "business" → 500 scans/month, team access

**Status**: ⚠️ PARTIAL
**Issues**:
- VT integration disabled by `VIRUSTOTAL_API_KEY` not set → Starter plan promises VT but it doesn't work
- Quota system works (enforced per scan)
- Team access ("3 seats") — not verifiable without multiple users

## Complete Dependency Map

```
User clicks "Subscribe"
  └─> PADDLE_ENVIRONMENT = sandbox → ❌ MUST be "production"
  └─> PADDLE_API_KEY = pdl_live_... → configured ✓
  └─> PADDLE_CLIENT_TOKEN = ct_live_... → configured ✓
  └─> PADDLE_PRICE_ID_STARTER = pri_... → configured ✓
  └─> Paddle.js opens checkout overlay
        └─> User enters payment info → Paddle processes
              └─> Paddle sends webhook to /paddle-webhook
                    └─> webhook.py OR app.py handler receives it
                          └─> PADDLE_WEBHOOK_SECRET verifies signature → configured ✓
                          └─> Server must be publicly reachable → ❌
                          └─> handle_webhook_event() runs
                                └─> activate_plan() updates DB
                                      └─> User tier changes → features unlocked
```

## What Must Happen Before First Payment
1. [ ] Set `PADDLE_ENVIRONMENT=production`
2. [ ] Deploy `webhook.py` on a publicly reachable server
3. [ ] Configure Paddle dashboard webhook URL → `https://yourdomain.com/paddle-webhook`
4. [ ] Test checkout end-to-end with a real card (refund immediately)
5. [ ] Verify subscription.cancelled webhook triggers downgrade
6. [ ] Verify plan enforcement after upgrade (VT, quota, AI reports)
