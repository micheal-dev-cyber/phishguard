# LinkedIn Launch Kit — PhishGuard AI

## Post 1 — Product Launch

**Headline:** We just open-sourced a phishing detector for small businesses. Here's why.

---

Every week, I hear another story about a small business losing $10k-$50k to a phishing email.

The problem isn't that detection technology doesn't exist. It's that the tools that work (Proofpoint, Abnormal Security, Mimecast) are priced for enterprises with 6-figure security budgets.

The tools that are affordable (free email scanners) require technical knowledge most small business owners don't have.

So we built something different.

**PhishGuard AI** is an open-source phishing detector that works in 3 seconds:

1️⃣ Paste any suspicious email
2️⃣ Click analyze
3️⃣ Get a risk score and full breakdown

No installation. No configuration. No security team required.

The detection engine checks:
• Suspicious URLs and domains
• Email authentication (SPF/DKIM/DMARC)
• Social engineering keywords in 3 languages
• AI-generated text patterns
• Phishing kit fingerprints

Free tier: 10 scans/month. Open source (MIT).

For the security folks: yes, the core detector is regex + heuristics, not ML. We're honest about what it is. When we have enough data, we'll add ML.

For everyone else: just paste an email and see if it's a phishing attack. No tech skills needed.

Try the live demo (no account required):
https://huggingface.co/spaces/phishguard

GitHub: https://github.com/phishguard

#cybersecurity #phishing #opensource #smallbusiness #infosec

---

## Post 2 — Technical Deep Dive (Target: Security Engineers)

**Headline:** Building an open-source phishing detector: what we learned

---

We built PhishGuard as an open-source (MIT) phishing analysis tool and learned some things worth sharing:

**1. Regex/heuristics catch 80% of phishing**
Before investing in ML, we benchmarked what pure pattern matching could do. The answer: a lot. URL patterns, header anomalies, keyword clusters — these catch most commodity phishing without any training data.

**2. SMBs need a different UX**
Enterprise tools assume a SOC team. Small businesses need "paste this email → tell me if it's bad → give me a PDF to show my boss." That's the entire product.

**3. Open source is an advantage**
Security products should be auditable. Every regex pattern, every scoring weight, every integration — visible in source. No black boxes.

**4. The hard part isn't detection — it's deployment**
Getting a small business to configure IMAP/OAuth is harder than building the detection engine. That's why our primary interface is "paste and scan" — zero configuration.

**Tech stack:** Python, Streamlit, SQLite, free AI APIs (Groq/OpenRouter)
**Detection:** pure Python, no external ML deps
**License:** MIT

https://github.com/phishguard

---

## Post 3 — Customer Pain (Target: Small Business Owners)

**Headline:** 3 signs an email is a phishing attack (and a free tool to check)

---

Most small business owners I talk to can't spot a sophisticated phishing email. Here are 3 red flags:

**1. Urgency + authority**
"I'm the CEO and I need this done NOW." Real executives don't send urgent requests via email without a phone call first.

**2. Slightly wrong domains**
amaz0n.com, paypaI.com, microsoft-support.xyz. Check every character.

**3. Generic greetings**
"Dear Valued Customer" from a service you use means they don't know who you are.

We built a free tool that checks all of this automatically:

→ Paste the email
→ Get a risk score in 3 seconds
→ Share a PDF report with your team

Free to use: https://huggingface.co/spaces/phishguard

No installation. No credit card. No security team required.

#smallbusiness #cybersecurity #phishing

---

## LinkedIn Posting Strategy
- Post 1 on launch day (Tuesday or Wednesday)
- Post 2 three days later (technical audience)
- Post 3 one week later (small business audience)
- Tag relevant people/groups
- Engage with every comment within 2 hours
- Share in relevant LinkedIn groups (Cybersecurity, Small Business Owners, SaaS Founders)
