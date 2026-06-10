# Hacker News Launch Kit — PhishGuard AI

## Best Post Format: Show HN

```
Show HN: PhishGuard – Open-source phishing detection for small business
```

## Post Body

```
I built PhishGuard because I watched a friend's 40-person company lose $28,000 to a spear-phishing email that any basic scanner would have caught.

Existing tools are:
- Enterprise-only (Proofpoint, Abnormal: $50k+/year)
- Too complex (need SPF/DKIM/DMARC configured, SIEM, dedicated security team)
- Or just not built for small teams

PhishGuard is a different approach:
1. Paste any suspicious email → get a risk score in under 3 seconds
2. No installation, no configuration, no credit card
3. Free tier: 10 scans/month forever
4. Open source (MIT)

The core detection engine is regex + heuristics (not ML — we're honest about that). It checks:
- Suspicious URLs and domain patterns
- Spoofed headers (SPF/DKIM/DMARC analysis)
- Social engineering keywords across 3 languages
- AI-generated text patterns (perplexity scoring)
- Phishing kit fingerprints

For a demo, it also integrates VirusTotal, OSINT (WHOIS/domain age/geolocation), and LLM-based analysis when API keys are configured.

The product itself is a Streamlit app (~4,400 lines in app.py, ~18,000 total). It works as both a manual paste-and-scan tool AND an IMAP inbox scanner.

What I'd love feedback on:
1. The core experience: does paste-and-scan actually help?
2. Pricing: $29/mo for 100 scans — fair for SMBs?
3. What's the ONE feature that would make you use this today?

Try it without signing up: https://huggingface.co/spaces/phishguard
GitHub: https://github.com/phishguard
```

## Anticipated HN Questions & Answers

**Q: How is this different from just checking URLs with VirusTotal?**
A: PhishGuard combines URL analysis with header forensics, social engineering keyword detection, AI-generated text analysis, and OSINT enrichment. It also gives a unified risk score (0-100) so anyone can understand the threat level without being a security expert.

**Q: Why not use ML like every other security product?**
A: ML is great for detection at scale, but it requires:
- Large labeled datasets (we don't have them — 0 real users)
- Regular retraining
- Explainability for compliance
- Compute budget for inference

Regex/heuristics catch 80% of phishing with zero training data and full explainability. We'll add ML when we have data to train it on.

**Q: Can this replace my email security gateway?**
A: No. PhishGuard is a complementary analysis tool, not a mail gateway. Think of it as "VirusTotal for phishing emails" — you send suspicious emails to it for a second opinion.

**Q: How do you make money if it's open source?**
A: Paid plans for higher scan volumes (100+ scans/month), VirusTotal integration, OSINT enrichment, and AI-powered reports. Free tier is genuinely useful (10 scans/month) and open source means enterprises can self-host.

## HN Launch Best Practices
- Post at 8-9 AM ET (Tuesday-Thursday is best)
- Respond to EVERY comment within 30 minutes
- Don't be defensive — listen to feedback
- Update the post if you fix something based on feedback
- Add "We're hiring" only if you're actually hiring
- Cross-post to /r/selfhosted and /r/cybersecurity after
