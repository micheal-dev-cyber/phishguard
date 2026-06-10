# PhishGuard AI — Top 20 ROI Actions

Sorted by **(Expected Business Impact) / (Engineering Effort)**.

### Scoring

- **Business Impact**: 1-10 (Acquisition, Activation, Retention, or Revenue)
- **Engineering Effort**: 1-10 (1 = 10 min env var, 10 = multi-day refactor)
- **ROI Score**: Impact / Effort (higher is better)

---

| Rank | Action | File(s) | Impact | Effort | ROI | Channel |
|------|--------|---------|--------|--------|-----|---------|
| 1 | Remove fake trust bar claims ("10K scans", "99% detection") | `auth.py:659-663` | 10 | 1 | **10.0** | Trust |
| 2 | Remove fake testimonials | `auth.py:790-809` | 10 | 1 | **10.0** | Trust |
| 3 | Set `APP_URL` env var | `env.py:44` | 10 | 1 | **10.0** | Auth |
| 4 | Set `SMTP_HOST/USER/PASS/FROM` env vars | `env.py:45-49` | 10 | 1 | **10.0** | Auth |
| 5 | Set `GROQ_API_KEY` env var | `env.py:31` | 8 | 1 | **8.0** | Activation |
| 6 | Set `VIRUSTOTAL_API_KEY` env var | `env.py:33` | 6 | 1 | **6.0** | Activation |
| 7 | Remove fake SOC 2 / Pen Tested claims | `auth.py:831-833` | 7 | 1 | **7.0** | Trust |
| 8 | Set `PADDLE_API_KEY` + `PADDLE_CLIENT_TOKEN` | `env.py:34-35` | 10 | 2 | **5.0** | Revenue |
| 9 | Set 4 `PADDLE_PRICE_ID_*` env vars | `env.py:37-40` | 10 | 2 | **5.0** | Revenue |
| 10 | Deploy to public URL | All env vars → HF Spaces | 10 | 4 | **2.5** | Acquisition |
| 11 | Wire `show_onboarding=True` after login | `auth.py:294` | 7 | 0.5 | **14.0** | Activation |
| 12 | Wire `header_auth.analyze_auth_headers()` into detection pipeline | `detector.py:405`, `app.py:107` | 8 | 1 | **8.0** | Activation |
| 13 | Create public `/demo` deep-link | `auth.py:460` | 8 | 1 | **8.0** | Acquisition |
| 14 | Add "Resend verification email" button | `auth.py` login page | 7 | 1 | **7.0** | Activation |
| 15 | Post on Hacker News "Show HN" | — | 9 | 1 | **9.0** | Acquisition |
| 16 | Launch on Product Hunt | — | 9 | 3 | **3.0** | Acquisition |
| 17 | Post on Reddit (r/cybersecurity, r/blueteamsec, r/selfhosted) | — | 7 | 1 | **7.0** | Acquisition |
| 18 | Cold email 50 local businesses | — | 6 | 2 | **3.0** | Acquisition |
| 19 | Add "remember me" persistent session | `app.py:434-443`, `session_manager.py` | 5 | 4 | **1.2** | Retention |
| 20 | Create detection benchmark (1-pager) | — | 8 | 4 | **2.0** | Trust |

---

## Top 5 by ROI

| Action | ROI | Time | Impact |
|--------|-----|------|--------|
| 1. Remove fake claims + testimonials | 10.0 | 30 min | Visitor trust restored |
| 2. Wire onboarding after login | 14.0 | 30 min | First-time user guided to value |
| 3. Set SMTP + APP_URL + GROQ_API_KEY | 10.0 | 1 hr | Full auth flow unblocked |
| 4. Post HN "Show HN" | 9.0 | 1 hr | Biggest organic acquisition channel |
| 5. Wire header_auth into detector + `/demo` deep-link | 8.0 | 2 hr | Better detection + shareable demo |

## Actions That Should NOT Be Done (Negative ROI)

| Action | Reason | Time | Impact |
|--------|--------|------|--------|
| Unify `users`/`tenants` tables | No user-facing impact. Both return correct data. | 3 hr | 0 |
| Unify quota systems | Both return correct defaults. No bug reports. | 2 hr | 0 |
| Archive AICOS system | No user-facing impact. Engineering hygiene only. | 4 hr | 0 |
| Archive enterprise features | No user-facing impact. Engineering hygiene only. | 2 hr | 0 |
| Add MFA recovery codes | 0 users have MFA enabled. Premature. | 3 hr | 0 |
| Build team/workspace features | 0 users, no request for team features. | 6 hr | 0 |
| SSO configuration | 0 enterprise users. Needs OAuth provider setup. | 4 hr | 0 |
| Inbox Scanner (IMAP) | Users must enter IMAP creds manually — not practical. | 4 hr | 0 |
| Campaign engine | No training/simulation customers. | 4 hr | 0 |
| SIEM/SOAR/SCIM connectors | No enterprise deployment. | 6 hr | 0 |

---

## Immediate Execution Order (First 3 days)

```
Hour 0-1:  Remove fake claims (auth.py) + Add "Resend verification" + Wire onboarding flag
Hour 1-2:  Set SMTP env vars + APP_URL + GROQ_API_KEY + VIRUSTOTAL_API_KEY
Hour 2-4:  Wire header_auth into detector + Create /demo deep-link
Hour 4-8:  Deploy to HF Spaces (or Railway)
Hour 8-9:  Post HN "Show HN" + Reddit posts (3 subreddits)
Hour 9-10: Set PADDLE_API_KEY + client token + price IDs (sandbox)
Hour 10-11: Write Product Hunt launch post (schedule for Day 3)
Hour 11-12: Cold email 50 SMB IT leaders
```

**After 12 hours of focused work:**
- Product is live at public URL
- Auth flow works end-to-end
- Detection is improved (SPF/DKIM/DMARC live)
- Demo is shareable
- Paddle billing is configured
- First acquisition channels are live
