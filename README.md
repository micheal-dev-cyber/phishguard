---
title: PhishGuard AI
emoji: 🛡
colorFrom: indigo
colorTo: blue
sdk: streamlit
sdk_version: "1.45.0"
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
| `APP_URL` | No | — | Public URL |
| `OAUTH_CLIENT_ID` | No | — | SSO OIDC client ID |
| `OAUTH_CLIENT_SECRET` | No | — | SSO OIDC client secret |
| `OAUTH_AUTHORITY` | No | — | SSO authority URL (e.g. `https://login.microsoftonline.com/common`) |
| `OAUTH_REDIRECT_URI` | No | — | SSO callback URI |
| `GRAPH_TENANT_ID` | No | — | Microsoft Graph tenant ID |
| `GRAPH_CLIENT_ID` | No | — | Microsoft Graph client ID |
| `GRAPH_CLIENT_SECRET` | No | — | Microsoft Graph client secret |
| `SIEM_SPLUNK_HEC_URL` | No | — | Splunk HEC endpoint |
| `SIEM_SPLUNK_HEC_TOKEN` | No | — | Splunk HEC token |
| `SIEM_ELASTIC_CLOUD_ID` | No | — | Elastic Cloud ID |
| `SIEM_ELASTIC_API_KEY` | No | — | Elastic API key |
| `SIEM_QRAZAR_URL` | No | — | QRadar API URL |
| `SIEM_QRAZAR_API_KEY` | No | — | QRadar API key |
| `PGHOST` | No | — | PostgreSQL host (optional, SQLite by default) |
| `PGPORT` | No | `5432` | PostgreSQL port |
| `PGUSER` | No | — | PostgreSQL user |
| `PGPASSWORD` | No | — | PostgreSQL password |
| `PGDATABASE` | No | `phishguard` | PostgreSQL database |

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
- **Enterprise SSO** (Okta, Azure AD, Google Workspace via OIDC)
- **Microsoft Graph API** integration (password-less mailbox scanning)
- **Automated Incident Response** (domain block, Graph quarantine)
- **SIEM dispatch** (Splunk HEC, Elastic Cloud, QRadar)
- **Auto-training assignment** (severity-based security campaigns)
- **Weekly PDF reports** (executive email delivery)
- **Self-service onboarding wizard** (Stripe/Paddle checkout)
- **Login lockout** (5-attempt brute-force protection)
- **bcrypt password hashing** with automatic SHA-256 migration
- **PostgreSQL** support (optional, SQLite default on HF Spaces)
- **Progressive Web App** (add to home screen, push notifications)
