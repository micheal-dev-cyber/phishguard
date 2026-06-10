# Billing Architecture

## Overview

PhishGuard's billing system uses a **provider-agnostic abstraction layer**. The `BillingProvider` ABC defines the interface; each payment backend (Gumroad, Paddle, Stripe, LemonSqueezy) implements it. The `BillingService` orchestrates provider calls, local state management, analytics, and the event bus — the rest of the app calls `BillingService` exclusively.

```

┌─────────────────────────────┐
│      app.py / auth.py      │
│   (UI — Streamlit views)    │
└──────────┬──────────────────┘
           │ BillingService
┌──────────▼──────────────────┐
│      BillingService         │
│  - checkout creation        │
│  - purchase verification    │
│  - subscription CRUD        │
│  - webhook dispatch         │
│  - analytics + events       │
└──────────┬──────────────────┘
           │ BillingProvider (ABC)
     ┌─────┼─────┬─────┐
     │     │     │     │
┌────▼┐ ┌─▼──┐ ┌▼───┐ ┌▼────────┐
│Gum‑ │ │Pad‑│ │St‑ │ │LemonSq  │
│road │ │dle │ │ripe│ │eezy     │
└─────┘ └────┘ └────┘ └─────────┘
```

## Key Design Decisions

### 1. Provider Interface (`src/billing/provider.py`)
Every provider implements:
- `create_checkout_url()` — generate a checkout link
- `verify_purchase()` — validate a completed sale
- `get_subscription()` — fetch remote subscription state
- `cancel_subscription()` — cancel via the provider
- `update_subscription_plan()` — plan change (providers without API support return False)
- `verify_webhook_signature()` — validate incoming webhooks

### 2. BillingService (`src/billing/service.py`)
- Single entry point for the entire app — UI, API, webhooks all go through here
- Creates checkout URLs, verifies purchases, processes webhooks
- Persists subscriptions to `billing_subscriptions` table
- Emits events via `src/events.py` for AICOS integration
- Tracks billing events via `src/analytics.py`

### 3. PlanConfig (`src/billing/config.py`)
- Single source of truth for pricing
- Reads analyses_per_month and features from `src/tenants.py:PLANS`
- All price values consumed from config — never hardcoded in UI

### 4. Backward Compatibility
- Existing Paddle code remains untouched
- `src/billing/paddle_compat.py` routes old Paddle calls through BillingService if Paddle is not configured
- `app.py` imports both old Paddle functions (with fallbacks) and new Gumroad imports

### 5. Webhook Processing
- Gumroad sends webhooks to `/webhooks/gumroad`
- HMAC-SHA256 signature verification using `GUMROAD_WEBHOOK_SECRET`
- Events persisted to `webhook_events` table for audit trail
- Unhandled event types are logged and ignored (not rejected)

## Key Files

| File | Purpose |
|---|---|
| `src/billing/provider.py` | Abstract base class for all billing providers |
| `src/billing/gumroad.py` | Gumroad-specific implementation |
| `src/billing/service.py` | Orchestration layer |
| `src/billing/config.py` | Plan pricing and configuration |
| `src/billing/models.py` | Shared data models |
| `src/billing/migrations.py` | DB migration for billing tables |
| `src/billing/webhook_handler.py` | ASGI webhook endpoint |
| `src/billing/paddle_compat.py` | Backward-compat stubs |
| `src/plan_service.py` | Feature gating and quota enforcement |
| `src/events.py` | Event bus for AICOS integration |
