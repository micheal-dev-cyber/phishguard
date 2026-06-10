# Deployment Checklist

## Prerequisites
- [ ] Python 3.11+ installed
- [ ] Git repo cloned
- [ ] `.env` file populated (see below)
- [ ] Port 8501 (Streamlit) and 5000 (Flask webhook) available

## Environment Variables Required
```ini
# REQUIRED — app will not start without these
OPENROUTER_API_KEY=sk-or-...

# REQUIRED for email delivery
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=<sendgrid-api-key>
SMTP_FROM=noreply@yourdomain.com
APP_URL=https://yourdomain.com

# REQUIRED for payments
PADDLE_ENVIRONMENT=production          # NOT sandbox
PADDLE_API_KEY=pdl_live_...           # live key
PADDLE_CLIENT_TOKEN=ct_live_...       # live token
PADDLE_PRICE_ID_STARTER=pri_starter_...
PADDLE_PRICE_ID_BUSINESS=pri_business_...

# OPTIONAL — enhanced detection
VIRUSTOTAL_API_KEY=<key>               # URL/domain reputation
GROQ_API_KEY=<key>                     # Faster AI analysis
```

## Step-by-Step

### 1. Verify Python & Dependencies
```bash
python --version  # require 3.11+
pip install -r requirements.txt
```

### 2. Database Initialization
```bash
python -c "from src.database import init_db; init_db()"
# Creates data/phishguard.db with all tables
```

### 3. Run Schema Migrations
```bash
python src/migrate.py
```

### 4. Start Webhook Server (Required for Paddle)
```bash
python webhook.py
# Listens on port 5000 — configure Paddle webhook URL to:
# https://yourdomain.com/paddle-webhook
```

### 5. Start Streamlit App
```bash
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

### 6. Health Check
```bash
curl http://localhost:8501/health
# Expected: {"status": "ok", "checks": {"database": "ok", ...}}
```

## Production Hardening
- [ ] Set `APP_URL` to production domain (not localhost)
- [ ] Set `PADDLE_ENVIRONMENT=production`
- [ ] Enable HTTPS behind reverse proxy (nginx/Caddy/Cloudflare)
- [ ] Configure Streamlit secrets for admin password
- [ ] Set up database backups (cron: `python src/backup.py`)
- [ ] Configure log rotation
- [ ] Set up monitoring (uptime check on /health)

## Docker (Alternative)
```dockerfile
# Build
docker build -t phishguard .

# Run
docker run -d -p 8501:8501 -p 5000:5000 --env-file .env phishguard
```

## Verification
- [ ] `python -m pytest tests/ -v` — all 312+ tests pass
- [ ] Visit `https://yourdomain.com` — app loads
- [ ] Paste a phishing email — analysis completes
- [ ] `/health` returns all checks OK
- [ ] Paddle checkout flow works end-to-end
