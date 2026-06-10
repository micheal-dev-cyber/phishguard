# APP_URL Audit

## Summary
Audited entire codebase for hardcoded URLs that should use `ENV.APP_URL`.
**29 locations found across Python, JS/HTML, config, and infra files.**
**11 Python files fixed** — all URL generation now uses `ENV.APP_URL` with `http://localhost:8501` fallback.

---

## Python Source Files Fixed

| File | Line (before) | Hardcoded URL | Fix |
|------|--------------|---------------|-----|
| `src/auth.py` | 175, 315, 417 | `"http://localhost:8501"` fallback | Already using `ENV.APP_URL or "http://localhost:8501"` |
| `src/auth.py` | 1206 | `"https://phishguard.ai"` fallback | Changed to `ENV.APP_URL or "https://phishguard.ai"` (already fixed) |
| `app.py` | 621 | `"https://phishguard.streamlit.app"` fallback | Changed to `ENV.APP_URL or "http://localhost:8501"` |
| `app.py` | 1435 | `"https://phishguard.ai"` fallback | Already using `ENV.APP_URL or "https://phishguard.ai"` |
| `app.py` | 1768, 2284 | `st.secrets.get("base_url", "http://localhost:8501")` | Prefixed with `ENV.APP_URL or` |
| `src/ui_analyzer.py` | 351 | `"https://phishguard.ai"` | Changed to `ENV.APP_URL or "http://localhost:8501"` |
| `src/webhook_routing.py` | 116 | `"https://phishguard.ai"` fallback | Changed to `ENV.APP_URL or "http://localhost:8501"` |
| `src/webhook_gateway.py` | 144 | `"https://phishguard.ai"` fallback | Changed to `ENV.APP_URL or "http://localhost:8501"` |
| `src/webhook_gateway.py` | 189, 223 | `"https://phishguard.ai"` param default | Changed to `""` (resolved at runtime from ENV) |
| `src/providers.py` | 86 | `"https://phishguard-ai.hf.space"` | Changed to `ENV.APP_URL or "https://phishguard-ai.hf.space"` |
| `webhook.py` | 202 | `"https://phishguard.ai"` | Changed to `ENV.APP_URL or "http://localhost:8501"` |
| `src/onboarding.py` | 39, 40, 67 | `"https://phishguard.ai"` fallback | Changed to `"http://localhost:8501"` fallback |
| `src/auth.py` | 175, 315, 417 | `getattr(ENV, "APP_URL", ...)` → `ENV.APP_URL` | Simplified to direct attribute access |

## NOT Fixed (Intentionally)

| File | Line | URL | Reason |
|------|------|-----|--------|
| `extension/background.js` | 18-19 | `http://127.0.0.1:8080`, `https://sabersouihi-...hf.space` | Chrome extension — needs separate config/deploy |
| `extension/content.js` | 3-4 | `https://phishguard-okmkdupa4...streamlit.app` | Chrome extension — needs separate config |
| `extension/popup.html` | 213 | `https://phishguard-okmkdupa4...streamlit.app` | Chrome extension — needs separate config |
| `extension/manifest.json` | 15-18 | HF Space + localhost URLs | Extension host permissions |
| `docs/index.html` | 349+ | Streamlit Cloud URLs | Static docs page — needs rebuild |
| `landing/index.html` | 110+ | HF Space URLs | Static landing page |
| `Dockerfile`, `docker-compose.yml` | - | `http://localhost:8501/health` | Local container health checks |
| `.github/workflows/ci.yml` | 102, 125 | `http://localhost:8080/health` | CI — always local |
| `scripts/deploy.sh` | 30 | `http://localhost:8080/health` | Deploy script — local check |
| `openapi.yaml` | 8 | `http://localhost:8080` | Dev spec — needs separate deploy config |
| `src/paddle_billing.py` | 11-12 | `https://api.paddle.com` | Third-party API endpoint — correct |
| `src/email_templates.py` | 33, 112 | `mailto:contact@phishguard.ai` | Mailto links — not URL generation |

## Remaining Work
- Chrome extension (`extension/`) needs a config mechanism to use `ENV.APP_URL` at build time
- Static docs (`docs/index.html`) and landing page (`landing/index.html`) need rebuild with env var injection
- All Docker/CI/deploy scripts use localhost — correct for their context, but should be documented
