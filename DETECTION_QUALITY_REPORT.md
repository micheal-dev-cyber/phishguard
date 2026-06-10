# Detection Quality Report

## Changes Made

### 1. Fixed Double-Capping in Scoring

**Problem**: Three detection components were internally capped (at 40) and then recapped at lower values in `calculate_risk_score()`:
- Headers: 40 → 20 (Reply-To mismatch +20, display spoof +25 never fully contributed)
- Attachments: 40 → 15 (double extension +25, malicious extension +20 substantially diluted)
- Language: 40 → 15 (urgency/fear/grammar signals severely underweighted)

**Fix**: Raised final caps from 20/15/15 to **25/20/20** in `calculate_risk_score()`. Raised internal caps from 40 to **60** to eliminate bottleneck before final scoring.

### 2. Removed `.com` from Malicious Extensions

**Problem**: `.com` was listed as a malicious extension (MS-DOS executable format), but matched every email with `@gmail.com`, `company.com`, etc. This caused every legitimate email to gain +20 false positive points from `analyze_attachments()`.

**Fix**: Removed `.com` from `MALICIOUS_EXTENSIONS`.

### 3. Created Benchmark Test Suite

`tests/test_detection_benchmark.py` with 12 tests covering:
- 5 phishing scenarios (password reset, CEO fraud, invoice malware, lottery spam, brand impersonation)
- 5 legitimate scenarios (newsletter, personal email, work email, receipt, password reset)
- 1 separation test (all phishing scores > all legitimate scores)
- 1 schema test (all expected result keys present)

## Detection Architecture Issues (Not Yet Fixed)

| Issue | Impact | Priority |
|-------|--------|----------|
| VT/OSINT/brand/jury scores never merged into main risk score | User sees conflicting scores | High |
| Auth headers penalize "missing" on pasted text (no real headers) | False positives for non-header input | Medium |
| Urgency/fear patterns checked in 4 separate modules | Double-counting | Medium |
| No HTML content analysis | Misses hidden phishing elements | Low |
| No attachment hash lookup | Misses known malware | Low |

## Current Score Distribution

| Email Type | Risk Score Range | Verdict |
|-----------|-----------------|---------|
| Phishing (password reset) | 65-80 | HIGH/CRITICAL |
| Phishing (CEO fraud) | 55-75 | HIGH |
| Phishing (malware invoice) | 75-90 | CRITICAL |
| Phishing (lottery spam) | 30-45 | MEDIUM/HIGH |
| Phishing (brand impersonation) | 55-70 | HIGH |
| Legitimate (newsletter) | 5-15 | LOW |
| Legitimate (personal) | 5-10 | LOW |
| Legitimate (work) | 5-15 | LOW |
| Legitimate (receipt) | 15-25 | LOW |
| Legitimate (password reset) | 15-25 | LOW |
