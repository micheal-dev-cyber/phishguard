# PhishGuard AI — First Customer Readiness

> Can a stranger discover, register, use, trust, upgrade, and pay for PhishGuard AI today?
> 
> **Overall Score: 15/100**

---

## 1. Discovery — Can a stranger find the product?

**Score: 2/10**

| Factor | Status |
|--------|--------|
| Public URL | No — only runs on localhost. HF Spaces deployment exists but URL is unknown |
| SEO visibility | Zero — Streamlit apps are not indexed well. No meta tags, no SSR, no blog |
| Social proof | Fake — landing page claims "Trusted by security teams worldwide" with fabricated testimonials |
| App store presence | None |
| Word of mouth | Impossible — zero users |

**Evidence**: The app has no production deployment. `.github/workflows/deploy.yml` exists but the target URL is not public. The app runs on `http://localhost:8501` by default.

**To reach 5/10**: Deploy to HF Spaces, remove fake social proof, create a basic landing page.

---

## 2. Registration — Can a stranger create an account?

**Score: 5/10**

| Factor | Status |
|--------|--------|
| Signup form exists | Yes — beautiful dark-theme form with validation |
| Username available | Yes — checks uniqueness |
| Email required | Yes |
| Password validation | Yes — min 8 chars, confirmation match |
| Password strength | Basic — min length only |
| Password hashing | Yes — bcrypt with salt |
| Terms/privacy | Linked to static trust pages |
| CAPTCHA | No |
| Email verification triggered | Yes — but email never sends (no SMTP) |

**Evidence**: `src/auth.py:108-192` — `_signup_form()` creates account via `create_tenant()`, then calls `send_verification_email()`. Since SMTP is not configured, the email fails silently (error is logged, not shown to user). User sees "Account created!" success message but verification email never arrives.

**To reach 10/10**: Configure SMTP, add CAPTCHA, add rate limiting per IP.

---

## 3. Email Verification — Can a stranger verify their email?

**Score: 1/10**

| Factor | Status |
|--------|--------|
| Verification email sent | No — SMTP not configured |
| Verification link works | Untestable — no email received |
| Token expiration | Yes — 24 hour TTL in code |
| Token security | Yes — SHA-256 hashed |
| Welcome email | No — same SMTP issue |

**Evidence**: `src/email_verify.py:48-70` — `verify_email_token()` hashes the token, checks expiry, marks verified. Code is correct. But the verification link never reaches the user.

**To reach 10/10**: Configure SMTP. That's it. The code is ready.

---

## 4. Login — Can a stranger log in?

**Score: 6/10**

| Factor | Status |
|--------|--------|
| Username/password login | Yes |
| Magic link login | Yes |
| SSO login | Yes — coded, needs OAuth provider config |
| Account lockout | Yes — 5 attempts in 15 minutes |
| MFA support | Yes — TOTP via authenticator app |
| Session management | Yes — session creation, tracking, revocation |
| Passwordless option | Yes — magic link |
| "Remember me" | No — always 30 min session TTL |

**Evidence**: `src/auth.py:195-326` — `_login_form()` handles username/password, magic link, and SSO. `verify_tenant()` checks lockout, verifies bcrypt password, tracks login attempts. `session_manager.py` creates and tracks sessions.

**To reach 10/10**: Configure SMTP (for magic link), add "remember me" with 7-day session, add persistent auth cookies.

---

## 5. Run a Scan — Can a stranger analyze an email?

**Score: 7/10**

| Factor | Status |
|--------|--------|
| Demo scan (no account) | Yes — works with regex engine |
| Authenticated scan | Yes — same pipeline |
| Paste email to analyze | Yes |
| Upload EML file | Not in code |
| Upload MSG file | Not in code |
| Upload screenshot | Yes — `ai_analyzer.py:326-349` OCR via GPT-4o vision |

**Evidence**: `src/auth.py:460-600` — Demo scan takes email text, runs `analyze_email()`, shows results. Detection pipeline is purely regex-based (no API calls). Works instantly, offline.

**To reach 10/10**: Show full analysis in demo (not gated). Add EML/MSG file upload. Wire VirusTotal. Wire header auth parser.

---

## 6. Understand the Result — Can a stranger interpret the output?

**Score: 4/10**

| Factor | Status |
|--------|--------|
| Risk score (0-100) | Yes — clear gauge |
| Severity label | Yes — CRITICAL/HIGH/MEDIUM/LOW with colors |
| URL analysis | Yes — list of suspicious URLs with flags |
| Keyword breakdown | Yes — category + hit count |
| Header analysis | Yes — but uses own regex, not SPF/DKIM/DMARC |
| AI narrative | Gated behind signup — and requires AI provider key anyway |
| PDF report | Gated behind signup |
| Recommended actions | Basic — only in AI narrative (not available) |

**Evidence**: `src/auth.py:540-600` — Demo shows limited results. Full analysis (AI narrative, PDF, OSINT) is gated behind signup. Since signup doesn't work, user never sees the full picture.

**To reach 10/10**: Show complete analysis in demo. Include SPF/DKIM/DMARC results. Provide clear "what to do next" actions based on findings.

---

## 7. Trust the Result — Can a stranger believe the analysis?

**Score: 2/10**

| Factor | Status |
|--------|--------|
| Detection accuracy known | No — never benchmarked |
| False positive rate known | No — never measured |
| Vendor cross-reference visible | Not — VirusTotal not configured |
| Claims on landing page | Fake — "99% detection rate" with zero evidence |
| Testimonials | Fabricated — named quotes from people who don't exist |
| Transparency about limitations | No — "Trusted by security teams worldwide" is displayed |
| Independent audit | None |

**Evidence**: `src/auth.py:659-663` — `"◈ 99% detection rate"` is hardcoded HTML. `src/auth.py:790-809` — three named testimonials with full names, titles, and company names. None of these people exist. No scans have been analyzed. No detection rate has been calculated.

**To reach 10/10**: Remove all fake claims. Replace with honest messaging ("Beta — currently in active development"). Run a benchmark against a public phishing dataset (e.g., SpamAssassin corpus). Publish results.

---

## 8. Upgrade — Can a stranger upgrade their plan?

**Score: 0/10**

| Factor | Status |
|--------|--------|
| Upgrade button exists | No — pricing page is static HTML |
| Checkout URL generated | No — `generate_checkout_url()` returns None |
| Plan comparison visible | Yes — static pricing grid |
| Feature gating works | In code — `check_quota()` blocks over-limit scans |
| Self-serve upgrade flow | None |

**Evidence**: `src/paddle_billing.py:49-75` — `generate_checkout_url()` checks `cfg["api_key"]` (empty) and returns `None`. `src/auth.py:851-888+` — pricing section is static HTML with no functional buy/upgrade buttons.

**To reach 10/10**: Configure Paddle, wire pricing buttons to `generate_checkout_url()`, test end-to-end.

---

## 9. Pay — Can a stranger complete a payment?

**Score: 0/10**

| Factor | Status |
|--------|--------|
| Paddle checkout works | No |
| Paddle webhook processes payment | No — webhook not deployed |
| Payment success email sent | No — SMTP not configured |
| Plan upgraded after payment | No |
| Invoice generated | No |
| Receipt available | No |
| Subscription management | No — all Paddle API calls fail with no key |

**Evidence**: Every function in `paddle_billing.py` that makes an API call first checks `cfg["api_key"]` and returns `None`/`False` if empty. Since no Paddle API key is configured, zero payment functions work.

**To reach 10/10**: Configure Paddle end-to-end. See Production Readiness Plan section 3.

---

## 10. Stay Active — Will a stranger return?

**Score: 2/10**

| Factor | Status |
|--------|--------|
| First scan satisfaction | Minimal — limited demo results |
| Onboarding flow | None |
| Email notifications | None — no SMTP |
| Scheduled/recurring scans | None — IMAP worker not deployed |
| Team/collaboration features | Coded but non-functional |
| Dashboard with history | Exists but empty |
| Gamification/leaderboard | Exists but empty |
| Re-engagement emails | Templates exist but no SMTP |
| Mobile app | None |

**Evidence**: `src/ui_onboarding.py` exists but the user flow after signup is "login → blank dashboard → ???". No guided first scan, no welcome wizard, no sample data.

**To reach 10/10**: Build onboarding wizard, configure SMTP for re-engagement, deploy IMAP worker for auto-scanning, seed leaderboard with sample data during beta.

---

## Final Score: **15/100**

| Dimension | Score | Why |
|-----------|-------|-----|
| Discovery | 2/10 | No public deployment, no SEO |
| Registration | 5/10 | Form works, email never sends |
| Email Verification | 1/10 | Code correct, SMTP missing |
| Login | 6/10 | Username/password + magic link work (locally) |
| Run a Scan | 7/10 | Demo works, regex-only, no file upload |
| Understand Result | 4/10 | Limited demo, AI narrative gated |
| Trust Result | 2/10 | Fake claims, no benchmark, no transparency |
| Upgrade | 0/10 | No functional upgrade path |
| Pay | 0/10 | Zero billing capability |
| Stay Active | 2/10 | No onboarding, no notifications, empty dashboard |
| **Total** | **15/100** | |
