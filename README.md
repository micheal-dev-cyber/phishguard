---
title: PhishGuard AI
emoji: 🛡
colorFrom: indigo
colorTo: blue
sdk: streamlit
sdk_version: "1.41.1"
python_version: "3.11"
app_file: app.py
pinned: false
---

# PhishGuard AI

Enterprise phishing threat detection platform powered by AI.

## Configuration

Set these in Space → Settings → Variables and secrets (or `.env` locally):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ADMIN_PASSWORD` | No | `phishguard2026` | Admin panel password |
| `OPENAI_API_KEY` | No | — | OpenAI key for AI analysis |
| `ANTHROPIC_API_KEY` | No | — | Anthropic key (fallback LLM) |
| `VIRUSTOTAL_API_KEY` | No | — | VirusTotal URL reputation |
| `SMTP_HOST` | No | `smtp.gmail.com` | SMTP server for alerts |
| `SMTP_USER` | No | — | SMTP username |
| `SMTP_PASS` | No | — | SMTP password |
| `SMTP_FROM` | No | (same as USER) | From-address for alerts |
| `APP_URL` | No | — | Public URL (for admin dashboard curl examples) |

## Local Development

```bash
pip install -r requirements.txt
streamlit run app.py
```

Run the API proxy for the Chrome extension:
```bash
python api_proxy.py --port 8080
```

## Features

- AI-powered phishing analysis with Multi-LLM Jury
- Psychological trigger detection (XAI)
- VirusTotal + OSINT threat intelligence
- Enterprise analytics dashboard
- PDF report generation
- Slack/Teams webhook alerts
- Gamified security champions leaderboard
- STIX 2.1 threat intelligence sharing
- Sender behavioral profiling & anomaly detection
- REST API proxy (stdlib, zero dependencies)
- IMAP auto-scan worker
- Health check endpoint (`/health`)
