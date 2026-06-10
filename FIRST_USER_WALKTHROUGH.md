# First User Walkthrough

## Scenario
Complete stranger arrives at PhishGuard. Has never used the product. Wants to test it.

## Step 1: Landing Page
**Path**: `/` (Streamlit app)
**What they see**: Hero with "Paste any email. Instantly know if it's a phishing attack." Two primary CTAs: "Start Free Trial" and "Try Demo — No Account Needed". Below: demo text area with example email pre-loaded.

**Status**: ✅ Works. Demo preview runs without account.
**Issues**:
- "Instantly know" is aspirational — actual scan takes 1-3 seconds
- Demo text area pre-populated with truncated email (200 chars + "...")

## Step 2: Try Demo (No Account)
**Path**: Click "Try Demo" button
**What happens**: Sets `session_state["show_demo"] = True`, reruns. Since user is not logged in, `check_password()` still shows landing page but sets the flag.

**Status**: ⚠️ BROKEN. The "Run Demo" flow on the landing page sets `show_demo = True` (auth.py line 757) but the actual analysis is only rendered in `app.py` tab system which requires authentication (app.py line 330: `if not check_password(): st.stop()`). Unauthenticated users see the landing page regardless.

**Blocker**: Demo without account doesn't work for an anonymous user.

## Step 3: Sign Up
**Path**: Click "Start Free Trial" → Signup form appears
**What they see**: Username, email, password, confirm password fields.

**Status**: ✅ Works.
**Details**:
- Username: 3+ chars, alphanumeric + hyphens/underscores only
- Email: must contain @ and .
- Password: 8+ chars, must match confirm
- On success: toast "Account created!" → redirected to login

## Step 4: Email Verification
**Path**: After signup, user told "Verification email sent!"
**What happens if SMTP configured**: Email sent with verify link → user clicks → verified.
**What happens if SMTP NOT configured (current state)**: Shows "SMTP not configured — email verification is disabled. You can log in directly." → user can log in immediately without verifying.

**Status**: ✅ Works (by design — skips verification when SMTP off).
**Issues**:
- No email actually sent — user doesn't notice, but they never get a welcome email
- No "resend verification" on first visit to login page (only appears after failed login attempt)

## Step 5: Log In
**Path**: Enter username + password → click Log In
**What happens**: Session created, `st.rerun()` → enters main app.

**Status**: ✅ Works.
**Issues**:
- "Forgot password?" link shown even though SMTP is not configured (opens reset flow that errors out)
- No SSO option shown (configured or not)

## Step 6: First Scan
**Path**: Main app → Scan tab → paste email → "Analyze Email" button
**What they see**: Text area, "Load Example" button, analyze button.

**Status**: ✅ Works.
**Details**:
- Quick Start banner shown on first visit (Phase 4)
- "Load Example Phishing Email" button pre-fills a phishing sample
- Analysis completes in 1-3 seconds
- Results shown below: risk score, severity, keyword breakdown, URL list

## Step 7: Results Page
**Path**: After scan, scroll down
**What they see**: Risk score gauge, severity badge, keyword matches, URL analysis, header analysis, attachment analysis, language analysis.

**Status**: ✅ Works.
**Issues**:
- If user pasted plain text without real email headers: auth headers show "missing" (SPF/DKIM/DMARC all fail → risk contribution +40)
- First-scan guidance is shown (good)
- Multiple scores (risk_score, composite_score, jury_score) can confuse — user sees potentially different severity ratings

## Step 8: PDF Download
**Path**: Scroll to "Export & AI Analysis" → "Download PDF Report"
**What happens**: PDF generated in-memory, download triggered.

**Status**: ✅ Works (if AI report available).
**Issues**:
- AI Security Report requires OpenRouter API key (configured ✓)
- Without AI report, PDF has basic data only
- CTAs to upgrade shown if user is on free tier

## Step 9: Upgrade Flow
**Path**: Click "Upgrade" in sidebar or navigate to Billing tab
**What happens**: Shows plan comparison → Starter $29/mo or Business $99/mo → Paddle checkout.

**Status**: ⚠️ PADDLE_ENVIRONMENT=sandbox with live keys. Checkout will submit but transaction stays in sandbox. Webhook never arrives → plan never activated.

**Issues**:
- If PADDLE_ENVIRONMENT fixed to production → checkout works
- Webhook must be publicly reachable for subscription activation
- No Stripe fallback

## Summary

| Step | Status | Blocker |
|------|--------|---------|
| 1. Landing Page | ✅ | None |
| 2. Demo (no account) | ❌ | Doesn't work for anonymous users |
| 3. Sign Up | ✅ | None |
| 4. Email Verification | ⚠️ | SMTP not configured → skipped silently |
| 5. Log In | ✅ | None |
| 6. First Scan | ✅ | None |
| 7. Results Page | ✅ | Score confusion (multiple scores) |
| 8. PDF Download | ✅ | None |
| 9. Upgrade Flow | ❌ | PADDLE_ENVIRONMENT mismatch + webhook not reachable |
