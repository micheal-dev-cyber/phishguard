# PhishGuard AI — Detection V2 Roadmap

> Current state: Regex-only heuristic scoring (0-100). SPF/DKIM/DMARC parser exists but orphaned. Zero benchmarking. Zero ML. Zero accuracy data.

---

## Pipeline Architecture (Current)

```
Email Text
  ↓
detector.py:analyze_email()
  ├── extract_urls() → check_urls()          # Regex URL pattern matching
  ├── scan_keywords()                         # Phishing keyword bag-of-words
  ├── detect_attachments()                    # Simple keyword check
  ├── analyze_headers()                       # Regex header analysis
  ├── analyze_attachments()                   # File extension checks
  ├── analyze_language()                      # Urgency/fear/grammar regex
  ├── fingerprint_email()                     # Phishing kit fingerprinting
  └── calculate_risk_score()                  # Weighted sum → 0-100
```

## Pipeline Architecture (Target V2)

```
Email Text
  ↓
detector.py:analyze_email_v2()
  ├── HEADER AUTH ENGINE (NEW — wire header_auth.py)
  │   ├── SPF validation
  │   ├── DKIM validation
  │   ├── DMARC validation
  │   └── Reply-To / From mismatch
  ├── URL REPUTATION ENGINE (NEW — wire VirusTotal)
  │   ├── VirusTotal scan (if key configured)
  │   ├── TLD risk scoring
  │   ├── URL shortener expansion
  │   └── Known malicious domain check
  ├── DOMAIN INTELLIGENCE (NEW — WHOIS integration)
  │   ├── Domain age
  │   ├── WHOIS privacy check
  │   ├── Registrar reputation
  │   └── SSL certificate age (if available)
  ├── SENDER PROFILER (IMPROVE — wire sender_profiler.py)
  │   ├── First contact vs known sender
  │   ├── Communication pattern matching
  │   └── Behavioral baseline deviation
  ├── ATTACHMENT SANDBOX (NEW — wire attachment_scanner.py)
  │   ├── File type verification (extension vs magic bytes)
  │   ├── Macro detection
  │   ├── Encrypted/password-protected archive detection
  │   └── Hash check against known malware DB
  ├── HEURISTIC ENGINE (existing — keep)
  │   ├── Keywords, urgency, fear, spoofing
  │   └── Language manipulation
  ├── LLM JURY (IMPROVE — when AI provider configured)
  │   ├── Linguistic analysis
  │   ├── Corporate context (BEC)
  │   └── Plain-English explanation
  ├── THREAT INTEL CORRELATION (IMPROVE)
  │   ├── STIX pattern matching
  │   ├── Phishing DNA fingerprinting
  │   └── Known campaign matching
  └── ENSEMBLE SCORING (improve weighting)
      ├── ML-weighted scoring (future)
      └── Confidence-calibrated output
```

---

## 10 Upgrade Items — Prioritized

### 1. SPF Validation — 4 hours | Impact: HIGH | Dependencies: None

**What**: Wire existing `header_auth.py:analyze_auth_headers()` into `detector.py:analyze_email()`. The parser already extracts SPF status from email headers and computes a risk contribution (0-40).

**Current gap**: Parser exists but `detector.py` never calls it. The `header_analysis` in `analyze_email()` uses a separate regex-based function `analyze_headers()` that checks fake sender patterns — it does NOT use the authentication header parser.

**Implementation**:
```python
# In detector.py:analyze_email()
from src.header_auth import analyze_auth_headers
auth_results = analyze_auth_headers(email_text)
# Already have header_analysis — merge auth_results into it
```

**Impact**: Catches the #1 phishing signal (domain spoofing) that is currently completely missed. A `fail` SPF result should immediately flag an email as suspicious.

**Test**: Create test emails with forged SPF headers, verify detection pipeline catches them.

---

### 2. DKIM Validation — 3 hours | Impact: HIGH | Dependencies: #1

**What**: Wire DKIM parsing from `header_auth.py`. The parser already reads `Authentication-Results` header for DKIM status.

**Current gap**: Same as SPF — parser exists, not called.

**Implementation**: Already handled if we wire `analyze_auth_headers()` into the pipeline (SPF/DKIM/DMARC come as a package).

**Impact**: Detects tampered emails and signature failures.

---

### 3. DMARC Validation — 2 hours | Impact: HIGH | Dependencies: #1

**What**: Wire DMARC parsing from `header_auth.py`.

**Implementation**: Same as #1 — `analyze_auth_headers()` returns DMARC status.

**Impact**: DMARC failures indicate domain alignment broken — strong phishing signal.

---

### 4. VirusTotal URL Reputation — 4 hours | Impact: HIGH | Dependencies: VIRUSTOTAL_API_KEY

**What**: Wire existing VirusTotal API integration into the URL analysis pipeline.

**Current gap**: `src/threat_intel.py` or `src/url_intel.py` likely have VT code, but `detector.py:analyze_email()` does not call it. URLs are checked via regex patterns only.

**Implementation**:
```python
# Add to detector.py:analyze_email()
if ENV.VIRUSTOTAL_API_KEY:
    from src.url_intel import check_url_reputation
    vt_results = check_url_reputation(urls)
    # Merge into risk score
```

**Impact**: Real-time cross-reference against 90+ security vendors. Catches zero-day phishing URLs that regex patterns miss.

**Dependencies**: User must set `VIRUSTOTAL_API_KEY` (free tier: 500 req/day)

---

### 5. Domain Age / WHOIS — 8 hours | Impact: MEDIUM-HIGH | Dependencies: whois library

**What**: Add domain age check. Newly registered domains (<30 days old) that appear in phishing emails are a strong signal.

**Current gap**: Zero domain intelligence in the pipeline.

**Implementation**:
```python
# New function in detector.py or src/domain_intel.py
import whois
from datetime import datetime

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = (datetime.now() - creation).days
        return {"age_days": age_days, "is_new": age_days < 30}
    except:
        return {"age_days": None, "is_new": None}
```

**Impact**: New domains (<30 days) are 10x more likely to be malicious. This single check catches many phishing sites.

**Dependencies**: `pip install python-whois`. Rate limits on WHOIS servers (usually 1 req/sec).

---

### 6. WHOIS Enrichment — 6 hours | Impact: MEDIUM | Dependencies: #5

**What**: Beyond domain age, extract registrar, registrant country, privacy protection status. Cross-reference against known-bad registrars.

**Implementation**: Extend the WHOIS function from #5.

**Impact**: Additional signals for scoring. Domains with WHOIS privacy + new registration + suspicious TLD = high risk.

---

### 7. Sender Reputation — 12 hours | Impact: MEDIUM | Dependencies: Database

**What**: Build a sender reputation system on top of existing `sender_profiler.py`. Track communication patterns, compute trust scores.

**Current gap**: `sender_profiler.py` and `database.py:86-107` create `sender_profiles` table. But no code records communication history or computes reputation scores.

**Implementation**:
```python
# New module: src/sender_reputation.py
def get_sender_trust(sender_email):
    """Return trust score 0-100 for a known sender."""
    # Check sender_profiles table
    # Factors: age of relationship, volume, avg risk score, response rate
    pass
```

**Impact**: Enables "known good sender" whitelisting. Dramatically reduces false positives for trusted contacts.

**Dependencies**: Database with sender history (empty at launch). Takes time to build.

---

### 8. Threat Intelligence Correlation — 8 hours | Impact: MEDIUM | Dependencies: Active users

**What**: Match incoming emails against known phishing campaigns using STIX patterns and phishing DNA fingerprints.

**Current gap**: `src/threat_intel.py`, `src/stix_exporter.py`, `src/phishing_dna.py` exist but are not integrated into the main detection pipeline.

**Implementation**: Wire `phishing_dna.match_fingerprint(email_text)` into `analyze_email()`.

**Impact**: Catch campaign-scale attacks. Phishing kits leave consistent fingerprints.

**Dependencies**: Needs campaign data to match against — empty without existing threat intel feed.

---

### 9. Attachment Sandbox — 4 hours | Impact: LOW (for text-based threat) | Dependencies: None

**What**: Verify file extensions match actual file types (magic bytes). Detect encrypted/password-protected archives.

**Current gap**: `detector.py` only checks file extensions via regex. No magic byte verification.

**Implementation**: Use python `magic` library (or `file` command) to verify MIME type matches extension.

**Impact**: Catches `invoice.pdf.exe` type attacks and encrypted payloads.

---

### 10. LLM-Assisted Explanation Layer — 3 hours | Impact: HIGH (UX) | Dependencies: AI provider (#3)

**What**: After detection pipeline runs, generate a plain-English explanation of findings using an LLM.

**Current gap**: `ai_analyzer.py:generate_ai_report()` exists but takes the raw email, not the structured detection results. It re-analyzes independently rather than explaining what the detection pipeline found.

**Implementation**: Create a new function that takes `detection_results` dict and produces a narrative.
```python
def generate_threat_narrative(detection_results: dict) -> str:
    """Use LLM to explain detection results in plain English."""
    prompt = f"Explain this phishing analysis in simple terms: {json.dumps(detection_results)}"
    return get_completion(system_prompt, prompt)
```

**Impact**: Makes detection results accessible to non-technical users. Single biggest UX improvement for the analysis page.

---

## Effort Summary

| # | Item | Hours | Impact | ROI |
|---|------|-------|--------|-----|
| 1 | SPF validation | 4 | HIGH | 25 |
| 2 | DKIM validation | 3 | HIGH | 33 |
| 3 | DMARC validation | 2 | HIGH | 50 |
| 4 | VirusTotal URL reputation | 4 | HIGH | 25 |
| 5 | Domain age | 8 | MED-HIGH | 12 |
| 6 | WHOIS enrichment | 6 | MED | 10 |
| 7 | Sender reputation | 12 | MED | 8 |
| 8 | Threat intel correlation | 8 | MED | 6 |
| 9 | Attachment sandbox | 4 | LOW | 2 |
| 10 | LLM explanation layer | 3 | HIGH (UX) | 33 |
| | **Total** | **54h** | | |

---

## Recommended Sprint Plan

**Sprint 1 (Week 1-2) — Foundation (14h)**
- #1, #2, #3: Wire SPF/DKIM/DMARC parser (2h — they're a package)
- #4: Wire VirusTotal URL reputation (4h)
- #10: LLM explanation layer (3h)
- Fix demo to show full results (2h, from blockers)
- Test and benchmark against 50 known phishing emails (3h)

**Sprint 2 (Week 3-4) — Intelligence (18h)**
- #5: Domain age / WHOIS (8h)
- #7: Sender reputation (12h, partial)

**Sprint 3 (Week 5-6) — Advanced (22h)**
- #6: WHOIS enrichment (6h)
- #8: Threat intel correlation (8h)
- #9: Attachment sandbox (4h)
- Full benchmark suite (4h)
