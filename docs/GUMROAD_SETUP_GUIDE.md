# Gumroad Setup Guide

## Prerequisites

1. A Gumroad account with creator access
2. Products created in Gumroad for each plan/cycle combination

## Step 1: Create Products in Gumroad

Create one product per plan × billing cycle pair:

| Product Name | Permalink (example) |
|---|---|
| Starter Monthly | `phishguard-starter-monthly` |
| Starter Yearly | `phishguard-starter-yearly` |
| Business Monthly | `phishguard-business-monthly` |
| Business Yearly | `phishguard-business-yearly` |

**Important settings per product:**
- Set as a **subscription** (recurring billing)
- Choose monthly or yearly recurrence to match the product
- Set the correct price ($29/mo, $290/yr, $99/mo, $990/yr)
- Enable **License Keys** (required for purchase verification)
- Enable custom checkout fields if you want to pass username data

## Step 2: Configure Environment Variables

Set these in your `.env` file or production environment:

```bash
# Tokens & Secrets
GUMROAD_ACCESS_TOKEN=your_gumroad_access_token
GUMROAD_WEBHOOK_SECRET=your_webhook_signing_secret

# Product Permalinks (from Gumroad product edit page URL)
GUMROAD_STARTER_MONTHLY_PERMALINK=phishguard-starter-monthly
GUMROAD_STARTER_YEARLY_PERMALINK=phishguard-starter-yearly
GUMROAD_BUSINESS_MONTHLY_PERMALINK=phishguard-business-monthly
GUMROAD_BUSINESS_YEARLY_PERMALINK=phishguard-business-yearly
```

### Where to find these values

- **Access Token**: Gumroad Dashboard → Settings → Advanced → API → Access Token
- **Webhook Secret**: Generated when you create a webhook in Gumroad Dashboard → Settings → Webhooks
- **Permalinks**: Found in the product edit URL: `https://app.gumroad.com/products/<PERMALINK>/edit`

## Step 3: Set Up Webhooks

1. Go to Gumroad Dashboard → Settings → Webhooks → Add Webhook
2. URL: `https://your-domain.com/webhooks/gumroad`
3. Events to subscribe to:
   - `sale.created`
   - `sale.updated`
   - `subscription.created`
   - `subscription.cancelled`
   - `subscription.ended`
   - `subscription.updated`
   - `refund.created`
4. Copy the signing secret and set it as `GUMROAD_WEBHOOK_SECRET`

## Step 4: Verify Configuration

The app checks `GUMROAD_ACCESS_TOKEN` and `GUMROAD_WEBHOOK_SECRET` to determine if Gumroad is configured. If both are non-empty, `gumroad_configured()` returns `True` and the upgrade/billing UI switches to Gumroad mode.

## Step 5: Checkout Flow

1. User selects plan + billing cycle in the upgrade section
2. App creates a Gumroad checkout URL: `https://app.gumroad.com/checkout/{permalink}?custom={username}`
3. User completes payment on Gumroad
4. Gumroad sends `sale.created` webhook to `/webhooks/gumroad`
5. Webhook handler verifies HMAC-SHA256 signature
6. BillingService activates the user's plan, creates local subscription record
7. User is redirected back to the app with plan active

## Limitations

- **No plan change API**: Gumroad does not support server-side subscription plan changes. Users must cancel and re-subscribe.
- **No customer portal**: Gumroad does not offer a white-label customer portal. Users manage billing on gumroad.com.
- **No invoice API**: Invoice history is not accessible via API. Users can view invoices on gumroad.com.
- **No pause/resume**: Gumroad subscriptions cannot be paused via API.
