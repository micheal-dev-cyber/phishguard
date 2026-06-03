"""
PhishGuard AI — Headless URL Sandbox Isolation Tracker

Spins up an isolated Playwright headless browser session per high-risk URL,
captures the full redirect chain, page screenshot, login form detection,
DOM fingerprinting (SHA-384), and LLM-based visual/text analysis to verify
if the landing page mimics a known brand login screen.

Architecture:
  ┌──────────────┐     HIGH/CRIT URL      ┌──────────────────┐
  │  Detector     │ ──────────────────→  │  URL Sandbox      │
  │               │                      │  (this module)    │
  └──────────────┘                      └────────┬─────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────┐
                    ▼                             ▼                         ▼
            ┌──────────────┐             ┌──────────────┐         ┌──────────────┐
            │  Playwright   │             │  DOM Parser   │         │  LLM Verdict │
            │  (headless)   │             │  (Beautiful   │         │  (text/visual)│
            │              │             │   Soup / lxml)│         │              │
            └──────────────┘             └──────────────┘         └──────────────┘
                    │                             │                        │
                    ▼                             ▼                        ▼
            ┌──────────────────────────────────────────────────────┐
            │                  url_sandbox DB table                 │
            └──────────────────────────────────────────────────────┘
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from src.db import get_connection

logger = logging.getLogger("url-sandbox")

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SCREENSHOTS_DIR = DATA_DIR / "sandbox_screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

# ── Known brand login page fingerprints ────────────────────────────────────

BRAND_LOGIN_PATTERNS = {
    "microsoft": {
        "domains": ["login.microsoft.com", "login.live.com", "account.microsoft.com"],
        "title_patterns": [r"sign\s*in", r"microsoft\s*account", r"office\s*365"],
        "form_selectors": ["input[type='email']", "input[name='loginfmt']"],
        "brand_keywords": ["microsoft", "office", "outlook", "azure", "365"],
    },
    "google": {
        "domains": ["accounts.google.com", "accounts.youtube.com", "login.google.com"],
        "title_patterns": [r"sign\s*in", r"gmail", r"google\s*account", r"my\s*account"],
        "form_selectors": ["input[type='email']", "input[name='identifier']"],
        "brand_keywords": ["google", "gmail", "youtube", "drive", "google workspace"],
    },
    "paypal": {
        "domains": ["www.paypal.com", "login.paypal.com"],
        "title_patterns": [r"log\s*in", r"paypal"],
        "form_selectors": ["input[type='email']", "input[name='login_email']"],
        "brand_keywords": ["paypal", "paypal.com", "send money", "receive money"],
    },
    "apple": {
        "domains": ["appleid.apple.com", "signin.apple.com"],
        "title_patterns": [r"sign\s*in", r"apple\s*id", r"apple\s*account"],
        "form_selectors": ["input[type='text']", "input[name='accountName']"],
        "brand_keywords": ["apple", "icloud", "apple id", "app store"],
    },
    "amazon": {
        "domains": ["www.amazon.com", "sellercentral.amazon.com"],
        "title_patterns": [r"sign\s*in", r"amazon"],
        "form_selectors": ["input[type='email']", "input[name='email']"],
        "brand_keywords": ["amazon", "aws", "amazon.com", "prime"],
    },
    "facebook": {
        "domains": ["www.facebook.com", "m.facebook.com", "mbasic.facebook.com"],
        "title_patterns": [r"log\s*in", r"facebook"],
        "form_selectors": ["input[type='text']", "input[name='email']"],
        "brand_keywords": ["facebook", "meta", "fb"],
    },
    "linkedin": {
        "domains": ["www.linkedin.com", "linkedin.com"],
        "title_patterns": [r"sign\s*in", r"linkedin"],
        "form_selectors": ["input[type='text']", "input[name='session_key']"],
        "brand_keywords": ["linkedin", "linked"],
    },
    "generic_bank": {
        "domains": [],
        "title_patterns": [r"online\s*banking", r"log\s*in", r"secure\s*login", r"internet\s*banking"],
        "form_selectors": ["input[type='password']"],
        "brand_keywords": ["bank", "banking", "credit union", "login", "secure"],
    },
}


@dataclass
class SandboxResult:
    original_url: str
    final_url: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    screenshot_path: str = ""
    page_title: str = ""
    detected_login_form: bool = False
    detected_brand: str = ""
    detected_brand_confidence: float = 0.0
    llm_verdict: str = ""
    llm_confidence: float = 0.0
    html_hash: str = ""
    dom_checksum: str = ""
    risk_score: int = 0
    verdict: str = "UNKNOWN"
    analysis_time_ms: int = 0
    error: str = ""


# ── Playwright sandbox ─────────────────────────────────────────────────────

async def _compute_dom_fingerprint(html: str) -> dict:
    """Compute multiple fingerprint hashes of the page DOM."""
    normalized = re.sub(r'\s+', ' ', html).strip()
    return {
        "html_hash": hashlib.sha384(normalized.encode("utf-8")).hexdigest(),
        "html_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "dom_checksum": hashlib.md5(normalized.encode("utf-8")).hexdigest(),
        "length": len(html),
    }


def _detect_login_form(html: str, page_title: str) -> dict:
    """Detect login forms and identify the brand being targeted."""
    html_lower = html.lower()
    title_lower = page_title.lower()
    detected = {"has_login_form": False, "brand": "", "confidence": 0.0}

    # Check for password fields (strong indicator of a login form)
    has_password_field = bool(re.search(
        r'<input[^>]*type=["\']password["\']', html, re.IGNORECASE
    ))
    has_email_field = bool(re.search(
        r'<input[^>]*type=["\']email["\']', html, re.IGNORECASE
    ))
    has_submit_button = bool(re.search(
        r'<button[^>]*type=["\']submit["\'>]', html, re.IGNORECASE
    )) or bool(re.search(
        r'<input[^>]*type=["\']submit["\'>]', html, re.IGNORECASE
    ))

    detected["has_login_form"] = has_password_field or (has_email_field and has_submit_button)

    if not detected["has_login_form"]:
        return detected

    # Score each brand
    best_brand = ""
    best_score = 0.0

    for brand, patterns in BRAND_LOGIN_PATTERNS.items():
        score = 0.0

        # Domain match
        for d in patterns["domains"]:
            if d in html_lower:
                score += 30
                break

        # Title pattern match
        for pat in patterns["title_patterns"]:
            if re.search(pat, title_lower):
                score += 20
                break

        # Brand keywords in page content
        for kw in patterns["brand_keywords"]:
            count = html_lower.count(kw)
            score += min(count * 5, 25)

        # Form selectors present
        for sel in patterns["form_selectors"]:
            sel_clean = sel.replace("input[type='", "").replace("']", "")
            if sel_clean in html_lower:
                score += 10
                break

        if score > best_score:
            best_score = score
            best_brand = brand

    detected["brand"] = best_brand if best_score >= 20 else "unknown"
    detected["confidence"] = min(best_score, 100)

    return detected


async def _build_llm_prompt(sandbox: SandboxResult, page_text: str) -> str:
    """Build a structured prompt for LLM phishing login verification."""
    return f"""You are a phishing detection expert. Analyse the following captured page data from a headless browser sandbox and determine if this page is a phishing login attempt.

PAGE TITLE: {sandbox.page_title}
FINAL URL: {sandbox.final_url}
REDIRECT CHAIN: {" → ".join(sandbox.redirect_chain[:5])}
DETECTED BRAND: {sandbox.detected_brand}
LOGIN FORM DETECTED: {sandbox.detected_login_form}
PAGE TEXT SNIPPET:
{page_text[:3000]}

Analyse the following:
1. Does the final URL match the detected brand's legitimate domain?
2. Are there any visual or textual inconsistencies?
3. Is this likely a phishing page mimicking a brand login?

Respond in JSON format ONLY with these fields:
{{
  "is_phishing": boolean,
  "confidence": 0.0-1.0,
  "verdict": "BRIEF EXPLANATION",
  "suspicious_indicators": ["list", "of", "flags"],
  "targeted_brand": "BRAND_NAME_OR_UNKNOWN"
}}"""


async def _call_llm_verification(prompt: str) -> dict:
    """Call an LLM for login-page phishing verification.

    Supports OpenAI, Anthropic, or a mock fallback for testing.
    """
    # Prefer OpenAI if available
    try:
        from openai import OpenAI
        client = OpenAI()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=500,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content
        return json.loads(content)
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("OpenAI call failed: %s", exc)

    # Fallback: Anthropic
    try:
        from anthropic import Anthropic
        client = Anthropic()
        resp = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
        )
        content = resp.content[0].text
        return json.loads(content)
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("Anthropic call failed: %s", exc)

    # Mock fallback for testing — rule-based heuristic
    return _mock_llm_verdict(prompt)


def _mock_llm_verdict(prompt: str) -> dict:
    """Rule-based mock LLM for offline / test mode."""
    is_phishing = False
    indicators = []
    confidence = 0.3

    if "login" in prompt.lower() and "password" in prompt.lower():
        confidence = 0.5

    # Simple heuristics
    if "paypal" in prompt.lower() and "paypal.com" not in prompt.lower():
        is_phishing = True
        indicators.append("domain_mismatch:paypal_brand_on_non_paypal_domain")
        confidence = max(confidence, 0.7)
    elif "microsoft" in prompt.lower() and "login.microsoft.com" not in prompt.lower():
        is_phishing = True
        indicators.append("domain_mismatch:microsoft_brand_on_non_microsoft_domain")
        confidence = max(confidence, 0.65)
    elif "apple" in prompt.lower() and "apple.com" not in prompt.lower():
        is_phishing = True
        indicators.append("domain_mismatch:apple_brand_on_non_apple_domain")
        confidence = max(confidence, 0.65)

    if not is_phishing and "sign in" in prompt.lower():
        confidence = max(confidence, 0.4)

    return {
        "is_phishing": is_phishing,
        "confidence": round(confidence, 2),
        "verdict": "Brand mismatch detected" if is_phishing else "No obvious phishing indicators",
        "suspicious_indicators": indicators,
        "targeted_brand": "unknown",
    }


# ── Main sandbox session ───────────────────────────────────────────────────

async def analyse_url_sandbox(
    url: str,
    timeout_ms: int = 30000,
    screenshot: bool = True,
    use_llm: bool = True,
    sandbox_id: Optional[str] = None,
) -> dict:
    """Full headless sandbox analysis of a URL.

    Launches an isolated Playwright browser, navigates to the URL, monitors
    redirects, captures screenshots, fingerprints the DOM, detects login
    forms, and runs optional LLM verification.
    """
    start = time.perf_counter()
    result = SandboxResult(original_url=url)
    redirect_chain = [url]

    try:
        from playwright.async_api import async_playwright

        # SECURITY WARNING: --no-sandbox and --disable-web-security bypass
        # Chromium's security model. These are needed when running as root
        # (e.g. HF Spaces) because Chromium refuses to start a sandbox as root.
        # Set PHISHGUARD_SANDBOX_UNSAFE=1 to allow these flags.
        # In production or CI, remove these flags or run as a non-root user.
        _unsafe_flags = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
        ]
        _launch_args = _unsafe_flags if os.environ.get("PHISHGUARD_SANDBOX_UNSAFE") == "1" else []
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=_launch_args,
            )

            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            page = await context.new_page()

            # Track redirects
            redirect_urls = []

            async def _on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    redirect_urls.append(response.url)

            page.on("response", _on_response)

            # Capture initial request for redirect chain
            async def _on_request(request):
                if len(redirect_urls) < 10:
                    if request.redirected_from:
                        redirect_urls.append(request.url)

            page.on("request", _on_request)

            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )

                # Wait a bit for JS redirects and dynamic content
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    logger.warning("url_sandbox: Network idle wait failed for %s", url)

                # Build redirect chain
                if response:
                    result.final_url = response.url
                else:
                    result.final_url = page.url

                # Deduplicate redirect chain
                seen = set()
                chain = [url]
                for r_url in redirect_urls:
                    if r_url not in seen:
                        seen.add(r_url)
                        chain.append(r_url)
                if result.final_url and result.final_url not in seen:
                    chain.append(result.final_url)
                result.redirect_chain = chain

            except Exception as exc:
                result.final_url = page.url
                result.redirect_chain = redirect_chain + [page.url]
                logger.warning("Page navigation issue for %s: %s", url, exc)

            # Page title
            try:
                result.page_title = await page.title()
            except Exception:
                logger.warning("url_sandbox: Failed to get page title for %s", url)
                result.page_title = ""

            # Screenshot
            if screenshot:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_name = re.sub(r'[^\w]', '_', url)[:40]
                screenshot_path = str(SCREENSHOTS_DIR / f"{ts}_{safe_name}.png")
                try:
                    await page.screenshot(path=screenshot_path, full_page=False)
                    result.screenshot_path = screenshot_path
                except Exception as exc:
                    logger.warning("Screenshot failed for %s: %s", url, exc)

            # DOM extraction and fingerprinting
            html_content = ""
            page_text = ""
            try:
                html_content = await page.content()
                page_text = await page.evaluate("() => document.body.innerText")
                fps = await _compute_dom_fingerprint(html_content)
                result.html_hash = fps["html_hash"]
                result.dom_checksum = fps["dom_checksum"]
            except Exception as exc:
                logger.warning("DOM extraction failed for %s: %s", url, exc)
                result.html_hash = hashlib.sha384(url.encode()).hexdigest()
                result.dom_checksum = hashlib.md5(url.encode()).hexdigest()

            # Login form detection
            login_info = _detect_login_form(html_content or "", result.page_title)
            result.detected_login_form = login_info["has_login_form"]
            result.detected_brand = login_info["brand"]
            result.detected_brand_confidence = login_info["confidence"]

            # LLM verification
            if use_llm and result.detected_login_form:
                prompt = await _build_llm_prompt(result, page_text or "")
                try:
                    llm_result = await _call_llm_verification(prompt)
                    if isinstance(llm_result, dict):
                        result.llm_verdict = llm_result.get("verdict", "")
                        result.llm_confidence = llm_result.get("confidence", 0.0)
                        if llm_result.get("is_phishing"):
                            result.verdict = "PHISHING"
                        elif llm_result.get("confidence", 0) >= 0.5:
                            result.verdict = "SUSPICIOUS"
                        else:
                            result.verdict = "LEGITIMATE"
                except Exception as exc:
                    logger.warning("LLM verification failed for %s: %s", url, exc)
                    result.llm_verdict = f"LLM error: {exc}"

            # Composite risk score
            risk = 0
            if result.detected_login_form:
                risk += 20
            if result.detected_brand and result.detected_brand != "unknown":
                if result.llm_confidence > 0:
                    risk += int(result.llm_confidence * 40)
                else:
                    risk += 15
            redirect_count = len(result.redirect_chain) - 1
            risk += min(redirect_count * 5, 15)
            result.risk_score = min(risk, 100)

            if result.verdict == "UNKNOWN":
                if result.risk_score >= 60:
                    result.verdict = "SUSPICIOUS"
                elif result.risk_score >= 30:
                    result.verdict = "MONITOR"
                else:
                    result.verdict = "SAFE"

            await browser.close()

    except ImportError:
        logger.error("playwright not installed — cannot run URL sandbox")
        result.error = "playwright_not_installed"
    except Exception as exc:
        logger.error("Sandbox analysis failed for %s: %s", url, exc)
        result.error = str(exc)

    result.analysis_time_ms = int((time.perf_counter() - start) * 1000)

    # Persist
    _persist_sandbox_result(result)

    return {
        "original_url": result.original_url,
        "final_url": result.final_url,
        "redirect_chain": result.redirect_chain,
        "screenshot_path": result.screenshot_path,
        "page_title": result.page_title,
        "detected_login_form": result.detected_login_form,
        "detected_brand": result.detected_brand,
        "detected_brand_confidence": result.detected_brand_confidence,
        "llm_verdict": result.llm_verdict,
        "llm_confidence": result.llm_confidence,
        "html_hash": result.html_hash,
        "dom_checksum": result.dom_checksum,
        "risk_score": result.risk_score,
        "verdict": result.verdict,
        "analysis_time_ms": result.analysis_time_ms,
        "error": result.error,
    }


def _persist_sandbox_result(result: SandboxResult):
    """Write sandbox results to the database."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO url_sandbox
                (original_url, final_url, redirect_chain, screenshot_path,
                 page_title, detected_login_form, detected_brand,
                 llm_verdict, llm_confidence, html_hash, dom_checksum,
                 risk_score, verdict, analysis_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.original_url,
            result.final_url,
            json.dumps(result.redirect_chain),
            result.screenshot_path,
            result.page_title[:200],
            1 if result.detected_login_form else 0,
            result.detected_brand,
            result.llm_verdict[:500],
            result.llm_confidence,
            result.html_hash,
            result.dom_checksum,
            result.risk_score,
            result.verdict,
            result.analysis_time_ms,
        ))
        conn.commit()
    except Exception as exc:
        logger.error("Failed to persist sandbox result: %s", exc)
    finally:
        conn.close()


# ── Batch sandbox analysis ─────────────────────────────────────────────────

async def analyse_urls_batch(urls: List[str], concurrency: int = 3) -> List[dict]:
    """Analyse multiple URLs in a controlled concurrent batch."""
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(url: str) -> dict:
        async with sem:
            return await analyse_url_sandbox(url)

    tasks = [_bounded(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    output = []
    for url, res in zip(urls, results):
        if isinstance(res, Exception):
            output.append({
                "original_url": url,
                "error": str(res),
                "verdict": "ERROR",
                "risk_score": 0,
            })
        else:
            output.append(res)
    return output


# ── Sync wrapper ───────────────────────────────────────────────────────────

def analyse_url_sandbox_sync(
    url: str,
    timeout_ms: int = 30000,
    screenshot: bool = True,
    use_llm: bool = True,
) -> dict:
    """Synchronous wrapper for the async sandbox analysis."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                lambda: asyncio.run(
                    analyse_url_sandbox(url, timeout_ms, screenshot, use_llm)
                )
            )
            return future.result()
    else:
        return asyncio.run(
            analyse_url_sandbox(url, timeout_ms, screenshot, use_llm)
        )


def get_sandbox_history(limit: int = 20) -> list:
    """Get recent sandbox analysis results."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT original_url, final_url, detected_brand, detected_login_form,
                   llm_verdict, risk_score, verdict, timestamp
            FROM url_sandbox
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        return c.fetchall()
    finally:
        conn.close()
