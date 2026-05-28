"""Secure Attachment Metadata & Hash Checker.

Extracts cryptographic hashes (MD5, SHA1, SHA256) from uploaded
attachment files and queries VirusTotal File API for reputation.

All hashing is local (stdlib hashlib). VT query uses the existing
ENV.VIRUSTOTAL_API_KEY via a lightweight HTTP call (urllib).

Usage:
    scan_result = scan_attachment(file_bytes, filename)
    result -> {"filename", "size", "md5", "sha1", "sha256",
               "vt_reputation": {...} or None, "error": str or None}
"""

from __future__ import annotations

import hashlib
import logging
import json
import os
from typing import Optional

logger = logging.getLogger("phishguard-attachment")


# ── Hashing ──────────────────────────────────────────────────────────────


def hash_file(data: bytes) -> dict:
    """Return MD5, SHA1, SHA256 hex digests for *data*."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ── VirusTotal file reputation ───────────────────────────────────────────


def query_vt_file(sha256: str, api_key: str) -> Optional[dict]:
    """Query VirusTotal v3 File API for *sha256* hash.

    Returns parsed response dict, or ``None`` on failure / no key.
    """
    if not api_key:
        logger.info("VIRUSTOTAL_API_KEY not set — skipping file check")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        import urllib.request
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.info("File hash %s not found in VT", sha256)
            return {"not_found": True}
        logger.warning("VT file API HTTP %d: %s", e.code, e.reason)
        return {"error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        logger.warning("VT file API connection error: %s", e.reason)
        return {"error": "connection failed"}
    except Exception as e:
        logger.warning("VT file API error: %s", e)
        return {"error": str(e)}


# ── Parse VT response ───────────────────────────────────────────────────


def parse_vt_file_response(vt_data: Optional[dict]) -> dict:
    """Extract meaningful reputation fields from raw VT API response."""
    if vt_data is None:
        return {"status": "not_queried"}
    if vt_data.get("not_found"):
        return {"status": "not_found", "verdict": "unknown"}
    if vt_data.get("error"):
        return {"status": "error", "error": vt_data["error"]}

    try:
        attributes = vt_data.get("data", {}).get("attributes", {})
        last_stats = attributes.get("last_analysis_stats", {})
        malicious = last_stats.get("malicious", 0)
        suspicious = last_stats.get("suspicious", 0)
        harmless = last_stats.get("harmless", 0)
        undetected = last_stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if total == 0:
            verdict = "unknown"
        elif malicious > 5:
            verdict = "malicious"
        elif malicious > 0:
            verdict = "suspicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "status": "found",
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "type_description": attributes.get("type_description", ""),
            "names": attributes.get("meaningful_name", ""),
            "last_modification": attributes.get("last_modification_date", 0),
        }
    except Exception as e:
        logger.warning("Failed to parse VT response: %s", e)
        return {"status": "parse_error", "error": str(e)}


# ── Public API ───────────────────────────────────────────────────────────


ALLOWED_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".pptx", ".zip",
                      ".rar", ".7z", ".exe", ".dll", ".ps1", ".vbs",
                      ".js", ".py", ".scr", ".bat", ".doc", ".xls"}


def is_allowed_attachment(filename: str) -> bool:
    """Check if file extension is one we handle."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def scan_attachment(data: bytes, filename: str,
                    vt_api_key: Optional[str] = None) -> dict:
    """Full scan pipeline: hash -> VT query -> parsed result.

    Returns a dict with keys::
      filename, size, md5, sha1, sha256, vt_reputation (dict), error
    """
    result: dict = {
        "filename": filename,
        "size": len(data),
        "md5": "",
        "sha1": "",
        "sha256": "",
        "vt_reputation": None,
        "error": None,
    }

    if not data:
        result["error"] = "empty file"
        return result

    hashes = hash_file(data)
    result.update(hashes)

    if vt_api_key or os.getenv("VIRUSTOTAL_API_KEY"):
        key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        raw = query_vt_file(result["sha256"], key)
        result["vt_reputation"] = parse_vt_file_response(raw)
    else:
        result["vt_reputation"] = {"status": "not_queried"}

    return result
