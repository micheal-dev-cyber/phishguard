# Billing Migration Report

## Summary

Replaced Paddle as the primary billing provider with Gumroad while maintaining full backward compatibility. The migration introduces a provider-agnostic billing abstraction layer that makes future provider swaps (Stripe, LemonSqueezy) trivial.

## What Changed

### New Files Created

| File | Lines | Purpose |
|---|---|---|
| `src/billing/__init__.py` | 1 | Package marker |
| `src/billing/provider.py` | 51 | Abstract `BillingProvider` interface |
| `src/billing/gumroad.py` | 231 | Gumroad API implementation |
| `src/billing/service.py` | 522 | Orchestration + webhook dispatch + local state |
| `src/billing/models.py` | 68 | Shared data models |
| `src/billing/config.py` | 83 | PlanConfig — single source of truth for pricing |
| `src/billing/migrations.py` | 108 | Idempotent DB migration for new tables |
| `src/billing/paddle_compat.py` | 43 | Backward-compat stubs |
| `src/billing/webhook_handler.py` | 62 | ASGI webhook endpoint |
| `src/plan_service.py` | 74 | Centralized feature gating |
| `src/events.py` | 28 | Event bus for AICOS integration |
| `tests/test_billing_provider.py` | 83 | Provider interface + config tests |
| `tests/test_gumroad_provider.py` | 175 | Gumroad provider unit tests |
| `tests/test_webhooks.py` | 280 | Webhook handler + ASGI endpoint tests |
| `tests/test_plan_service.py` | 92 | PlanService feature gating tests |
| `tests/test_subscription_lifecycle.py` | 178 | End-to-end lifecycle tests |

### Modified Files

| File | Changes |
|---|---|
| `src/env.py` | Added 6 GUMROAD_* env vars + `gumroad_configured` flag |
| `src/tenants.py` | No changes (pricing already in PLANS dict) |
| `app.py` | Added Gumroad + BillingService imports, upgraded upgrade section with monthly/yearly toggle, updated billing tab with Gumroad-aware subscription display + cancellation |

### Database

Two new tables added (no changes to existing Paddle tables):

- **`billing_subscriptions`** — local subscription state per user
- **`webhook_events`** — webhook audit trail

Both created idempotently via `src/billing/migrations.py`.

## Test Coverage

93 tests across 5 test files covering:
- Plan configuration and pricing
- Provider interface compliance
- Gumroad checkout URL generation (all plan/cycle combinations)
- Purchase verification (success, failure, edge cases)
- Webhook signature validation (valid, invalid, missing secret)
- All webhook event types (sale.created, sale.updated, subscription.*, refund.*)
- Full subscription lifecycle (create, verify, cancel, expire, refund)
- Feature gating and quota enforcement
- ASGI webhook endpoint (GET 405, POST no-config 503, valid POST 200)
- Error handling (invalid JSON, missing data, unknown products)

All tests pass.

## Rollback Plan

To revert to Paddle-only billing:
1. Set `GUMROAD_ACCESS_TOKEN` and `GUMROAD_WEBHOOK_SECRET` to empty
2. Ensure `PADDLE_API_KEY` and `PADDLE_CLIENT_TOKEN` are set
3. The app falls back to Paddle automatically — no code changes needed
4. The new billing tables can be left in place (they are unused when Gumroad is not configured)

## Future Provider Addition (e.g., Stripe)

To add Stripe:
1. Create `src/billing/stripe.py` implementing `BillingProvider`
2. Add Stripe env vars to `src/env.py`
3. Add `stripe_configured()` check similar to `gumroad_configured()`
4. Instantiate `BillingService(StripeProvider())` when Stripe is configured
5. No changes needed in `service.py`, `config.py`, `models.py`, or any UI code

## Migration Notes

- Existing Paddle users are unaffected — their subscriptions continue to work
- New users go through Gumroad checkout automatically if Gumroad is configured
- The `paddle_compat.py` layer ensures any lingering Paddle calls don't break
- The upgrade/billing UI shows "Active" status for both Paddle and Gumroad subscriptions
