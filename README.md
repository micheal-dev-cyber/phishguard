---
title: PhishGuard AI
emoji: 🛡
colorFrom: dark
colorTo: blue
sdk: streamlit
sdk_version: "1.41.1"
python_version: "3.11"
app_file: app.py
pinned: false
---

# PhishGuard AI

Enterprise phishing threat detection platform powered by AI.

## Setup

Add the following secrets in Space → Settings → Variables and secrets:

| Secret | Description |
|--------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for AI analysis |
| `ANTHROPIC_API_KEY` | Anthropic API key (fallback LLM) |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for URL reputation |
| `ADMIN_PASSWORD` | Override default admin password |

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
