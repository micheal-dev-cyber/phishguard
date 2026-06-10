# Reddit Launch Kit — PhishGuard AI

## Subreddits to Target

| Subreddit | Subs | Angle | Best Day/Time |
|-----------|------|-------|---------------|
| r/cybersecurity | 900k | Open source alternative to enterprise tools | Tue 10am ET |
| r/smallbusiness | 700k | Protect your business from phishing | Wed 9am ET |
| r/selfhosted | 350k | Self-host your own phishing scanner | Thu 10am ET |
| r/msp | 100k | Tool for MSPs offering security to clients | Tue 11am ET |
| r/sysadmin | 750k | Quick analysis tool for IT teams | Wed 10am ET |
| r/opensource | 500k | MIT-licensed phishing detection | Thu 9am ET |
| r/startups | 300k | Free tool for early-stage startups | Fri 10am ET |

## Post Templates

### r/cybersecurity

**Title:** I built an open-source phishing scanner for SMBs — paste any email, get a risk score in 3 seconds

```
I got tired of seeing small businesses get destroyed by phishing emails that any basic tool would catch.

PhishGuard is open source (MIT) and works like this:
1. Paste a suspicious email (headers + body)
2. Click analyze
3. Get a risk score (0-100), severity, and full breakdown

It checks URLs, headers (SPF/DKIM/DMARC), keywords across 3 languages, AI-generated text patterns, and phishing kit fingerprints.

It also integrates VirusTotal and OSINT when configured.

Free tier: 10 scans/month, no credit card.
Pro: $29/mo for 100 scans with VirusTotal + OSINT.

The core engine is regex/heuristics (honest about what it is). No ML hype here.

Would love feedback from real sysadmins and security pros:
- Does paste-and-scan actually help in your workflow?
- What's missing?
- Is the pricing reasonable?

Try it (no account required): https://huggingface.co/spaces/phishguard
GitHub: https://github.com/phishguard
```

### r/selfhosted

**Title:** PhishGuard — Self-hostable phishing detection (Docker, Streamlit, SQLite, MIT)

```
I built a phishing analysis tool that you can self-host with a single docker-compose command.

It's a Streamlit app that:
- Analyzes emails for phishing indicators (URLs, headers, keywords)
- Supports manual paste-and-scan AND IMAP inbox scanning
- Generates PDF threat reports
- Has VirusTotal and OSINT integration (optional)
- Stores everything in SQLite (no external deps)

Runs fine on a $5 VPS. The whole thing is ~18k LOC of Python.

GitHub: https://github.com/phishguard
Docker image: phishguard/phishguard (coming soon)

Yes, it's actually open source (MIT). No, there's no bait-and-switch.
```

### r/smallbusiness

**Title:** Free tool to check if an email is phishing — paste it in, get an answer in 3 seconds

```
Small business owner here. I built a free tool that tells you if an email is phishing.

You just paste the email (the whole thing, headers included) and it gives you:
- A risk score (0-100)
- Whether it's CRITICAL/HIGH/MEDIUM/LOW risk
- What specifically is suspicious (URLs, keywords, headers)
- A PDF report you can share with your team

No installation. No configuration. No credit card.

Free tier: 10 checks/month.
If you need more: $29/mo for 100 checks with extra features.

Try it: https://huggingface.co/spaces/phishguard
```

## Engagement Strategy
- Post in r/cybersecurity first (most relevant audience)
- Cross-post to r/selfhosted and r/smallbusiness 24 hours later
- Reply to every comment within 2 hours
- Be humble and grateful for feedback
- Don't pitch paid plans unless someone asks
- Share what you learned building it
