"""
PhishGuard AI — B2B Enterprise API Gateway (FastAPI)

Provides secure REST endpoints for enterprise clients to submit text for
phishing analysis. Features:

- POST /api/v1/scan — analyse email/page text
- X-API-Key header authentication
- Tier-based rate limiting (sliding window)
- Full detection engine integration
- Structured JSON responses with CORS

Usage:
    DATABASE_URL=phishguard.db API_KEYS_FILE=api_keys.json \
    uvicorn api_gateway.main:app --host 0.0.0.0 --port 8080
"""

import os
import sys
import json
import time
import logging
from typing import Optional, Dict, Any
from pathlib import Path
from collections import defaultdict
from threading import Lock

sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from fastapi import FastAPI, HTTPException, Security, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.detector import analyze_email

logger = logging.getLogger("api-gateway")

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard AI — Enterprise API",
    version="3.0.0",
    description="Secure threat analysis API for enterprise clients.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth ───────────────────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

API_KEYS: Dict[str, Dict[str, Any]] = {}
_api_keys_lock = Lock()


def _load_api_keys(path: Optional[str] = None):
    """Load API keys from JSON file. Expected format:
    {
        "key_abc123": {"client": "Acme Corp", "plan": "business", "tier": "business"},
        ...
    }
    """
    path = path or os.getenv("API_KEYS_FILE", "api_keys.json")
    try:
        with open(path, "r") as f:
            keys = json.load(f)
        with _api_keys_lock:
            API_KEYS.clear()
            API_KEYS.update(keys)
        logger.info("Loaded %d API keys from %s", len(keys), path)
    except FileNotFoundError:
        logger.warning("API keys file %s not found. Using empty key set.", path)
    except json.JSONDecodeError as exc:
        logger.error("Invalid API keys file %s: %s", path, exc)


def _verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Validate an API key and return its metadata."""
    with _api_keys_lock:
        return API_KEYS.get(api_key)


# ── Tier-based rate limiting ───────────────────────────────────────────────
TIER_LIMITS = {
    "trial":     {"rpm": 5,   "concurrency": 1,  "monthly": 10},
    "starter":   {"rpm": 15,  "concurrency": 2,  "monthly": 100},
    "business":  {"rpm": 30,  "concurrency": 5,  "monthly": 500},
    "enterprise":{"rpm": 120, "concurrency": 50, "monthly": 999999},
}

_rate_buckets: Dict[str, list] = defaultdict(list)
_rate_lock = Lock()


def _check_rate_limit(api_key: str, tier: str) -> bool:
    """Sliding-window rate check. Returns True if allowed."""
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["trial"])
    now = time.time()
    cutoff = now - 60

    with _rate_lock:
        bucket = _rate_buckets[api_key]
        bucket[:] = [t for t in bucket if t > cutoff]
        if len(bucket) >= limits["rpm"]:
            return False
        bucket.append(now)
    return True


def _get_rate_limit_remaining(api_key: str, tier: str) -> int:
    """Return remaining requests in the current 60s window."""
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["trial"])
    now = time.time()
    cutoff = now - 60
    with _rate_lock:
        bucket = _rate_buckets[api_key]
        bucket[:] = [t for t in bucket if t > cutoff]
        return max(0, limits["rpm"] - len(bucket))


# ── Request / response models ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000,
                      description="Email or page text to analyse (max 50K chars)")

class ScanResponse(BaseModel):
    status: str = "ok"
    risk_score: int
    severity: str
    total_keyword_hits: int
    url_count: int
    suspicious_url_count: int
    keyword_matches: dict
    suspicious_urls: list
    has_attachments: bool
    rate_limit_remaining: int
    tier: str
    client: str


# ── Endpoints ──────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    _load_api_keys()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "phishguard-api", "version": "3.0.0"}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_email(
    request: Request,
    body: ScanRequest,
    api_key: str = Security(api_key_header),
):
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header. Provide a valid API key to access this endpoint.",
            headers={"WWW-Authenticate": "API-Key"},
        )

    client_info = _verify_api_key(api_key)
    if not client_info:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key. Please check your X-API-Key header value.",
        )

    tier = client_info.get("tier", "trial")
    client_name = client_info.get("client", "Unknown")

    if not _check_rate_limit(api_key, tier):
        remaining = _get_rate_limit_remaining(api_key, tier)
        limits = TIER_LIMITS.get(tier, TIER_LIMITS["trial"])
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "tier": tier,
                "limit_rpm": limits["rpm"],
                "retry_after_seconds": 60,
                "remaining_in_window": remaining,
            },
        )

    try:
        results = analyze_email(body.text)
    except Exception as exc:
        logger.error("Analysis error for client %s: %s", client_name, exc)
        raise HTTPException(status_code=500, detail="Analysis engine error")

    remaining = _get_rate_limit_remaining(api_key, tier)

    return ScanResponse(
        status="ok",
        risk_score=results.get("risk_score", 0),
        severity=results.get("severity", "LOW"),
        total_keyword_hits=results.get("total_keyword_hits", 0),
        url_count=results.get("url_count", 0),
        suspicious_url_count=results.get("suspicious_url_count", 0),
        keyword_matches=results.get("keyword_matches", {}),
        suspicious_urls=[u["url"] for u in results.get("suspicious_urls", [])],
        has_attachments=results.get("has_attachments", False),
        rate_limit_remaining=remaining,
        tier=tier,
        client=client_name,
    )


@app.get("/")
async def root():
    return {
        "service": "PhishGuard AI — Enterprise API Gateway",
        "version": "3.0.0",
        "endpoints": {
            "POST /api/v1/scan": "Analyse email/page text for phishing threats",
            "GET /health": "Health check",
            "GET /": "API information",
        },
        "auth": "X-API-Key header",
    }
