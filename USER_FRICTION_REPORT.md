# PhishGuard AI — User Friction Report

> Role-playing as 4 personas attempting to discover, evaluate, and purchase PhishGuard.

---

## Persona 1: SMB Owner (50 employees, no dedicated security team)

### Journey

| Step | What Happens | Friction | Severity |
|------|-------------|----------|----------|
| 1. Heard about PhishGuard | Word of mouth / ad / article | **Can't find it.** Google returns nothing. No production URL exists. | **CRITICAL** |
| 2. Find the URL | Ask founder for link | **CRITICAL** | **CRITICAL** |
| 3. Visit landing page | "Trusted by security teams worldwide" — who? Shows "10,000+ scans" — not possible for a pre-launch product | **Trust destroyed immediately.** Any technical buyer will see through this in 3 seconds. | **CRITICAL** |
| 4. Read testimonials | "Sarah Chen, CISO, FinTech Corp" — doesn't exist. "Marcus Rivera, Security Engineer, CloudScale" — doesn't exist. | **Trust destroyed again.** If I catch one lie, I assume everything is a lie. | **CRITICAL** |
| 5. Try demo | Paste an email, get a risk score | Actually works. **Original friction: LOW** | LOW |
| 6. See demo results | Shows limited data. "Sign up for the full analysis." | **Why can't I see the full value before committing?** I'm being pressured to sign up without knowing what I'm getting. | **HIGH** |
| 7. Click "Create Free Account" | Signup form appears. Looks professional. | **Original friction: LOW** | LOW |
| 8. Fill in signup form | Username, email, password, confirm password. Good validation. | LOW | LOW |
| 9. Submit signup | "Account created! Check your email to verify." | **Email never arrives.** SMTP not configured. | **CRITICAL** |
| 10. Wait for email | Nothing. Check spam. Nothing. | **Dead end.** Can't proceed. Cannot log in (blocked before verification). | **CRITICAL** |
| 11. Try to log in anyway | "Please verify your email before logging in." | **CRITICAL** | **CRITICAL** |
| 12. Click "Forgot password" | Enter email. "If that email is in our system, a reset link is on its way." | **No email arrives either.** | **CRITICAL** |
| 13. Try magic link | Enter email. "Magic link on its way!" | **No email arrives.** | **CRITICAL** |
| 14. Give up | Close tab. Never return. | | |

**Verdict for SMB Owner**: Product is completely non-functional. **Cannot use at all.**

---

## Persona 2: Solo Founder / Freelancer

### Journey

| Step | What Happens | Friction | Severity |
|------|-------------|----------|----------|
| 1-5 | Same as SMB Owner | Same | CRITICAL |
| 6. See pricing | Free trial, $29/mo starter, $99/mo business | **Looks reasonable.** But: | LOW |
| 7. Click "Start Free Trial" on pricing | Goes to signup form | OK | LOW |
| 8. Signup | Same email issue | CRITICAL | CRITICAL |
| 9. Eventually get access (hypothetical) | Dashboard is empty. No data. No scans. No history. | **"What do I do now?"** No onboarding, no tutorial, no sample data. | **HIGH** |
| 10. Try to scan an email | Scanner UI appears. Paste box is there. | LOW — UI is functional | LOW |
| 11. See scan results | Risk score, severity, URL count, keyword count. | **What does this mean for me?** No explanation, no recommended action, no context. | **MEDIUM** |
| 12. Want to upgrade | Click pricing page. | **"Buy" buttons don't work.** They're static HTML. No Paddle configured. | **CRITICAL** |
| 13. Want to set up recurring scans | IMAP worker not deployed. | Can't automate. | LOW (expected for free tier) |
| 14. Return next day | Logged out. Session expired. | **Re-enter credentials.** Repeat every visit. | MEDIUM |

**Verdict for Solo Founder**: Product function is there but rough. **Cannot pay even if they want to.**

---

## Persona 3: IT Manager (200-person company)

### Journey

| Step | What Happens | Friction | Severity |
|------|-------------|----------|----------|
| 1-5 | Same as above | Same | CRITICAL |
| 6. Evaluate for team use | Look for SSO, team management, admin controls. | **SSO exists in code.** Not configured. No OAuth provider set up. **Cannot evaluate.** | HIGH |
| 7. Check security | Look for SOC reports, penetration tests, security whitepapers. | **Nothing.** Landing page claims SOC 2 compliance and penetration testing — no evidence. | **CRITICAL** |
| 8. Check compliance | GDPR, data handling, SLAs | **Trust pages exist** (privacy, terms, security, refund). Content is reasonable. | LOW |
| 9. Try to evaluate with a real phishing email | Scan an actual suspicious email your company received. | **Detection may or may not work.** SPF/DKIM/DMARC parser exists but orphaned. No benchmark data to evaluate accuracy. | **HIGH** |
| 10. Check if you can white-label | White-label page exists. | **Feature exists in code but untestable.** | MEDIUM |
| 11. Check API access | API keys section exists. | **API is coded but no documentation, no SDK, no test.** | MEDIUM |
| 12. Want to send a contract/POS | | **No sales process.** No quotes. No invoicing. No procurement support. | **CRITICAL** |
| 13. Decision | **Risk is too high. Cannot recommend to my boss. Pass.** | **CRITICAL** | **CRITICAL** |

**Verdict for IT Manager**: Product is not enterprise-ready. **Cannot purchase even if they want to.**

---

## Persona 4: Microsoft 365 Admin

### Journey

| Step | What Happens | Friction | Severity |
|------|-------------|----------|----------|
| 1. Want to integrate with Exchange Online | Look for Microsoft Graph API integration. | **Graph API code exists** (`graph_api.py`). Not configured. No tenant ID, client ID, client secret set. | **CRITICAL** |
| 2. Want auto-scan of user-reported phish | Outlook add-in / webhook | **`webhook.py` exists** but not deployed. Would need separate infrastructure. | **CRITICAL** |
| 3. Want SIEM integration | Splunk/Elastic/QRadar | **Code exists.** No connectors configured. No proof it works. | **CRITICAL** |
| 4. Want SCIM provisioning | User directory sync | **Code exists.** No IdP to test with. | HIGH |
| 5. Want to evaluate accuracy at scale | Ask for benchmark results against your own dataset | **Zero benchmark data.** "Trust us" is not a security purchase criterion. | **CRITICAL** |
| 6. Want SLA | Ask for uptime guarantee, support response times | **Nothing.** No SLA policy. No support tiers defined. | **CRITICAL** |

**Verdict for Microsoft 365 Admin**: Product is not deployable in any enterprise environment. **Cannot evaluate.**

---

## Friction Summary

| Friction | Severity | Blocks | Fix |
|----------|----------|--------|-----|
| No public URL | CRITICAL | Discovery | Deploy to HF Spaces |
| No SMTP → no email verification | CRITICAL | Registration | Set env vars (1h) |
| Fake trust claims + testimonials | CRITICAL | Trust | Delete them (30 min) |
| Demo gates full results | HIGH | Activation → signup | Unlock all demo data (2h) |
| No onboarding flow | HIGH | Activation | Build wizard (6h) |
| No functional pricing ("buy" does nothing) | CRITICAL | Revenue | Configure Paddle + wire buttons (8h) |
| No persistent session (logged out on refresh) | MEDIUM | Retention | Add remember-me (4h) |
| No benchmark / accuracy data | HIGH | Trust | Create dataset + measure (6h) |
| SPF/DKIM/DMARC orphaned | HIGH | Detection quality | Wire into detector (2h) |
| No AI provider configured | HIGH | AI features broken | Set Groq key (5 min) |
| Two user tables (data inconsistency risk) | MEDIUM | Reliability | Unify to `tenants` (3h) |
| Two quota systems (conflicting limits) | MEDIUM | Reliability | Unify to `usage_log` (2h) |
| No session refresh/sliding expiration | MEDIUM | Retention | Add touch_session on every page (2h) |
| SSO not configured | MEDIUM (enterprise only) | Enterprise evaluation | Not needed yet |
| SIEM/SOAR/SCIM not configured | HIGH (enterprise only) | Enterprise evaluation | Not needed yet |
| No sales/procurement process | CRITICAL (enterprise only) | Enterprise purchase | Not needed yet |

---

## Critical Path: Remove All CRITICAL Frictions

| Order | Fix | Hours | Personas Unblocked |
|-------|-----|-------|-------------------|
| 1 | Set SMTP env vars | 1 | SMB Owner, Solo Founder, IT Manager |
| 2 | Set APP_URL | 0.2 | All |
| 3 | Set Groq API key | 0.2 | All |
| 4 | Remove fake claims + testimonials | 0.5 | All |
| 5 | Deploy to public URL | 4 | All (discovery) |
| 6 | Unlock demo results | 2 | All (activation) |
| 7 | Configure Paddle + wire buy buttons | 8 | SMB Owner, Solo Founder (revenue) |
| 8 | Wire SPF/DKIM/DMARC into detector | 2 | All (detection quality) |
| 9 | Create detection benchmark | 6 | IT Manager (trust) |

**9 fixes. ~24 hours. Removes EVERY critical friction for SMB Owner and Solo Founder.**

IT Manager and M365 Admin are premature personas. Their frictions are:
- Enterprise features that don't exist yet (SSO, SIEM, SCIM, Graph API)
- Sales process that doesn't exist yet

These are not bugs. They're features not yet built. **Don't build them until an enterprise customer asks.**

**TL;DR**: The product has 9 critical frictions. 5 of them are env var configuration (2 hours total). 4 more are code/ops changes (~22 hours). After 24 hours of focused work, SMB owners and solo founders can use and pay for the product.
