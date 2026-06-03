"""
PhishGuard AI — Computer Vision OCR & Anti-Homograph Engine

Extracts hidden text from embedded images inside emails using EasyOCR
(or pytesseract fallback), then runs a strict homograph defence layer
that decodes Punycode via the `idna` module and flags visual lookalike
spoofing (Cyrillic / Latin confusables).

Layers:
  1. Image extraction from email bytes / base64
  2. OCR text extraction (EasyOCR async → pytesseract sync fallback)
  3. URL / email detection inside OCR text
  4. IDN homograph decoding (idna encode/decode)
  5. Unicode confusable detection via confusable_map
  6. Risk scoring and alert logging
"""

import asyncio
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from typing import Optional

from src.db import get_connection

logger = logging.getLogger("ocr-homograph")

# ── Unicode confusable map (common Latin → Cyrillic/Greek lookalikes) ──────
# These are the most dangerous homograph substitutions used in IDN spoofing.
CONFUSABLE_MAP = {
    "а": "a",  # Cyrillic small a
    "е": "e",  # Cyrillic small ie
    "о": "o",  # Cyrillic small o
    "р": "p",  # Cyrillic small er
    "с": "c",  # Cyrillic small es
    "у": "y",  # Cyrillic small u
    "х": "x",  # Cyrillic small kha
    "і": "i",  # Cyrillic small Byelorussian i
    "ј": "j",  # Cyrillic small a (duplicate — keep for clarity)
    "Ь": "b",  # Cyrillic soft sign → b
    "Н": "H",  # Cyrillic en → H
    "Т": "T",  # Cyrillic te → T
    "К": "K",  # Cyrillic ka → K
    "М": "M",  # Cyrillic em → M
    "В": "B",  # Cyrillic ve → B
    "Е": "E",  # Cyrillic ie → E
    "О": "O",  # Cyrillic o → O
    "Р": "P",  # Cyrillic er → P
    "С": "C",  # Cyrillic es → C
    "У": "Y",  # Cyrillic u → Y
    "Х": "X",  # Cyrillic kha → X
    "Α": "A",  # Greek alpha
    "Β": "B",  # Greek beta
    "Ε": "E",  # Greek epsilon
    "Ζ": "Z",  # Greek zeta
    "Η": "H",  # Greek eta
    "Ι": "I",  # Greek iota
    "Κ": "K",  # Greek kappa
    "Μ": "M",  # Greek mu
    "Ν": "N",  # Greek nu
    "Ο": "O",  # Greek omicron
    "Ρ": "P",  # Greek rho
    "Τ": "T",  # Greek tau
    "Υ": "Y",  # Greek upsilon
    "Χ": "X",  # Greek chi
}

# Known brands that are frequently targeted by homograph attacks
BRAND_HOMOGRAPH_TARGETS = [
    "apple", "google", "microsoft", "paypal", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "twitter", "whatsapp",
    "chase", "wellsfargo", "bankofamerica", "hsbc", "barclays",
    "dropbox", "adobe", "salesforce", "github", "bitbucket",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+", re.IGNORECASE)

_ocr_executor = ThreadPoolExecutor(max_workers=2)
_ocr_enabled = True

# ── Attempt lazy imports ───────────────────────────────────────────────────

try:
    import easyocr
    _easyocr_reader = None
    _easyocr_available = True
except ImportError:
    _easyocr_available = False
    logger.warning("easyocr not installed — falling back to pytesseract")

try:
    import pytesseract
    from PIL import Image  # noqa: F401
    _tesseract_available = True
except ImportError:
    _tesseract_available = False
    logger.warning("pytesseract/PIL not installed — OCR disabled")

try:
    import idna
    _idna_available = True
except ImportError:
    _idna_available = False
    logger.warning("idna module not installed — homograph IDN detection disabled")


def _get_easyocr_reader():
    global _easyocr_reader
    if _easyocr_available and _easyocr_reader is None:
        _easyocr_reader = easyocr.Reader(["en"], gpu=False)
    return _easyocr_reader


# ── Image extraction ───────────────────────────────────────────────────────

def extract_images_from_bytes(data: bytes) -> list:
    """Extract embedded images from raw email bytes or base64.

    Returns a list of PIL Image objects for OCR processing.
    """
    if not _tesseract_available:
        return []

    images = []
    try:
        import io

        from PIL import Image

        stream = io.BytesIO(data)
        try:
            img = Image.open(stream)
            img.verify()
            stream.seek(0)
            img = Image.open(stream)
            images.append(img.convert("RGB"))
        except Exception as e:
            logger.warning("ocr_homograph: Failed to open image from stream: %s", e)

        if not images:
            try:
                from email import policy
                from email.parser import BytesParser

                msg = BytesParser(policy=policy.default).parsebytes(data)
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype.startswith("image/"):
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                img = Image.open(BytesIO(payload))
                                images.append(img.convert("RGB"))
                            except Exception as e:
                                logger.warning("ocr_homograph: Failed to open image from email part: %s", e)
            except Exception as e:
                logger.warning("ocr_homograph: Failed to parse email for images: %s", e)
    except Exception as exc:
        logger.error("Image extraction error: %s", exc)

    return images


# ── OCR extraction (async) ─────────────────────────────────────────────────

async def _ocr_easycoxr_async(image_bytes: bytes) -> str:
    """Run EasyOCR asynchronously in a thread pool."""
    if not _easyocr_available:
        return ""

    reader = _get_easyocr_reader()
    if reader is None:
        return ""

    def _run():
        import numpy as np
        from PIL import Image
        img = Image.open(BytesIO(image_bytes)).convert("RGB")
        np_arr = np.array(img)
        results = reader.readtext(np_arr)
        return " ".join(r[1] for r in results)

    return await asyncio.get_event_loop().run_in_executor(_ocr_executor, _run)


async def _ocr_tesseract_async(image_bytes: bytes) -> str:
    """Fallback: run pytesseract asynchronously."""
    if not _tesseract_available:
        return ""

    def _run():
        from PIL import Image
        img = Image.open(BytesIO(image_bytes)).convert("RGB")
        return pytesseract.image_to_string(img).strip()

    return await asyncio.get_event_loop().run_in_executor(_ocr_executor, _run)


async def extract_text_from_image(image_bytes: bytes) -> dict:
    """Extract text from image bytes using available OCR engine.

    Returns dict with extracted_text, confidence, engine_used, and timing.
    """
    start = time.perf_counter()

    result = ""
    confidence = 0.0
    engine = "none"

    if _easyocr_available:
        try:
            result = await _ocr_easycoxr_async(image_bytes)
            if result.strip():
                engine = "easyocr"
                confidence = 80.0
        except Exception as exc:
            logger.warning("EasyOCR failed: %s — falling back", exc)

    if not result.strip() and _tesseract_available:
        try:
            result = await _ocr_tesseract_async(image_bytes)
            if result.strip():
                engine = "tesseract"
                confidence = 60.0
        except Exception as exc:
            logger.warning("Tesseract failed: %s", exc)

    elapsed = int((time.perf_counter() - start) * 1000)

    return {
        "extracted_text": result.strip(),
        "confidence": confidence,
        "engine_used": engine,
        "processing_time_ms": elapsed,
    }


# ── Homograph detection ────────────────────────────────────────────────────

def decode_punycode(encoded_domain: str) -> dict:
    """Decode a Punycode IDN domain and check for homograph attacks.

    Returns a dict with the decoded form, ASCII form, and any detected
    visual lookalike attempts.
    """
    if not _idna_available:
        return {"original": encoded_domain, "decoded": encoded_domain, "homograph_risk": "unknown"}

    try:
        decoded = idna.decode(encoded_domain)
        ascii_form = idna.encode(decoded).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError) as exc:
        return {
            "original": encoded_domain,
            "decoded": encoded_domain,
            "ascii": encoded_domain,
            "homograph_risk": "error",
            "error": str(exc),
        }

    risk_flags = []
    visual_lookalike_of = None

    if decoded.lower() != ascii_form.lower():
        risk_flags.append("punycode_mismatch")

    # Check for confusable characters
    for i, ch in enumerate(decoded):
        if ch in CONFUSABLE_MAP:
            expected = CONFUSABLE_MAP[ch]
            risk_flags.append(f"confusable_char_at_{i}:{ch}(U+{ord(ch):04X})→{expected}")

    # Check if it visually resembles a known brand
    decoded_clean = decoded.lower().replace("-", "").replace("_", "")
    for brand in BRAND_HOMOGRAPH_TARGETS:
        if brand in decoded_clean or decoded_clean in brand:
            visual_lookalike_of = brand
            risk_flags.append(f"visual_lookalike:{brand}")
            break

    score = len(risk_flags) * 15
    if visual_lookalike_of:
        score += 30

    return {
        "original": encoded_domain,
        "decoded": decoded,
        "ascii": ascii_form,
        "homograph_risk": "critical" if score >= 45 else "high" if score >= 25 else "low",
        "risk_score": min(score, 100),
        "flags": risk_flags,
        "visual_lookalike_of": visual_lookalike_of,
    }


def get_ascii_visualisation(domain: str) -> str:
    """Translate any confusable characters to their ASCII equivalents."""
    result = []
    for ch in domain:
        result.append(CONFUSABLE_MAP.get(ch, ch))
    return "".join(result)


def check_url_for_homograph(url: str) -> dict:
    """Parse the domain from a URL and check for homograph / IDN attacks."""
    domain_match = re.match(r"https?://([^/?#:]+)", url)
    if not domain_match:
        return {"url": url, "homograph_detected": False}

    domain = domain_match.group(1)

    # Check if it's Punycode
    if domain.startswith("xn--"):
        decoded = decode_punycode(domain)
        homograph = decoded.get("homograph_risk") in ("critical", "high")
        ascii_vis = get_ascii_visualisation(decoded["decoded"])
        return {
            "url": url,
            "homograph_detected": homograph,
            "punycode_domain": domain,
            "decoded_domain": decoded["decoded"],
            "ascii_visualisation": ascii_vis,
            "risk_score": decoded.get("risk_score", 0),
            "flags": decoded.get("flags", []),
            "visual_lookalike_of": decoded.get("visual_lookalike_of"),
        }

    # Non-Punycode: check for confusable chars directly in domain
    ascii_vis = get_ascii_visualisation(domain)
    if ascii_vis.lower() != domain.lower():
        risk_score = 0
        flags = []
        visual_lookalike_of = None

        for ch in domain:
            if ch in CONFUSABLE_MAP:
                expected = CONFUSABLE_MAP[ch]
                flags.append(f"confusable_char:{ch}(U+{ord(ch):04X})→{expected}")
                risk_score += 15

        domain_clean = domain.lower().replace("-", "").replace("_", "")
        for brand in BRAND_HOMOGRAPH_TARGETS:
            if brand in domain_clean or domain_clean in brand:
                visual_lookalike_of = brand
                risk_score += 30
                break

        return {
            "url": url,
            "homograph_detected": risk_score >= 25,
            "punycode_domain": None,
            "decoded_domain": domain,
            "ascii_visualisation": ascii_vis,
            "risk_score": min(risk_score, 100),
            "flags": flags,
            "visual_lookalike_of": visual_lookalike_of,
        }

    return {"url": url, "homograph_detected": False}


# ── scan OCR text and check homogeneous URLs ───────────────────────────────

def scan_ocr_text_for_threats(extracted_text: str) -> dict:
    """Scan OCR-extracted text for URLs and emails, then check homographs."""
    urls = URL_PATTERN.findall(extracted_text)
    emails = EMAIL_PATTERN.findall(extracted_text)

    homograph_results = []
    for url in urls:
        hr = check_url_for_homograph(url)
        if hr.get("homograph_detected"):
            homograph_results.append(hr)

    return {
        "urls_found": urls,
        "emails_found": emails,
        "homograph_urls": homograph_results,
        "total_homographs": len(homograph_results),
    }


# ── Persistence ────────────────────────────────────────────────────────────

def log_ocr_result(
    analysis_id: Optional[int],
    extracted_text: str,
    urls: list,
    emails: list,
    homograph_urls: list,
    confidence: float,
    processing_time_ms: int,
):
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO ocr_extractions
                (analysis_id, extracted_text, detected_urls, detected_emails,
                 homograph_urls, ocr_confidence, processing_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            extracted_text[:2000],
            json.dumps(urls[:50]),
            json.dumps(emails[:50]),
            json.dumps(homograph_urls[:20]),
            confidence,
            processing_time_ms,
        ))
        conn.commit()
    except Exception as exc:
        logger.error("Failed to log OCR result: %s", exc)
    finally:
        conn.close()


def log_homograph_alert(
    original_domain: str,
    decoded_punycode: Optional[str],
    ascii_domain: str,
    homograph_type: str,
    visual_lookalike_of: Optional[str],
    risk_score: int,
    found_in_email: str = "",
):
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO homograph_alerts
                (original_domain, decoded_punycode, ascii_domain, homograph_type,
                 visual_lookalike_of, risk_score, found_in_email)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            original_domain,
            decoded_punycode,
            ascii_domain,
            homograph_type,
            visual_lookalike_of,
            risk_score,
            found_in_email[:500],
        ))
        conn.commit()
    except Exception as exc:
        logger.error("Failed to log homograph alert: %s", exc)
    finally:
        conn.close()


# ── Master pipeline ────────────────────────────────────────────────────────

async def analyze_images_in_email(
    email_data: bytes,
    email_text: str,
    analysis_id: Optional[int] = None,
) -> dict:
    """Full pipeline: extract images → OCR → homograph scan → persist."""
    start = time.perf_counter()
    images = extract_images_from_bytes(email_data)

    if not images:
        return {
            "images_found": 0,
            "ocr_results": [],
            "homograph_results": [],
            "total_homographs": 0,
            "processing_time_ms": int((time.perf_counter() - start) * 1000),
        }

    ocr_results = []
    all_extracted_text = ""
    all_homographs = []

    for img in images:
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        image_bytes = buf.read()

        ocr = await extract_text_from_image(image_bytes)
        ocr_results.append(ocr)
        all_extracted_text += ocr.get("extracted_text", "") + "\n"

        threats = scan_ocr_text_for_threats(ocr.get("extracted_text", ""))
        all_homographs.extend(threats.get("homograph_urls", []))

    # Log homographs found in email text too (not just OCR)
    text_threats = scan_ocr_text_for_threats(email_text)
    for hr in text_threats.get("homograph_urls", []):
        if hr not in all_homographs:
            all_homographs.append(hr)

    # Persist
    if analysis_id:
        combined_ocr = "\n".join(
            r["extracted_text"] for r in ocr_results if r["extracted_text"]
        )
        log_ocr_result(
            analysis_id,
            combined_ocr,
            text_threats["urls_found"],
            text_threats["emails_found"],
            all_homographs,
            max((r["confidence"] for r in ocr_results), default=0.0),
            int((time.perf_counter() - start) * 1000),
        )

    for hr in all_homographs:
        log_homograph_alert(
            original_domain=hr.get("decoded_domain", hr.get("url", "")),
            decoded_punycode=hr.get("punycode_domain"),
            ascii_domain=hr.get("ascii_visualisation", ""),
            homograph_type="punycode_spoof" if hr.get("punycode_domain") else "unicode_confusable",
            visual_lookalike_of=hr.get("visual_lookalike_of"),
            risk_score=hr.get("risk_score", 0),
            found_in_email=email_text[:500],
        )

    return {
        "images_found": len(images),
        "ocr_results": ocr_results,
        "combined_text": all_extracted_text.strip(),
        "homograph_results": all_homographs,
        "total_homographs": len(all_homographs),
        "processing_time_ms": int((time.perf_counter() - start) * 1000),
    }


# ── Sync wrapper for non-async contexts ────────────────────────────────────

def analyze_images_in_email_sync(
    email_data: bytes,
    email_text: str,
    analysis_id: Optional[int] = None,
) -> dict:
    """Synchronous wrapper for the async pipeline."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                lambda: asyncio.run(
                    analyze_images_in_email(email_data, email_text, analysis_id)
                )
            )
            return future.result()
    else:
        return asyncio.run(
            analyze_images_in_email(email_data, email_text, analysis_id)
        )
