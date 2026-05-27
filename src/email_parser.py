import email
import re
import base64
import quopri
from email import policy
from email.utils import parsedate_to_datetime, parseaddr
from typing import Optional, Dict, Any, List

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import extract_msg
    HAS_MSG = True
except ImportError:
    HAS_MSG = False


def _decode_mime_header(header_value: str) -> str:
    """Safely decode a MIME-encoded header to plain text."""
    if not header_value:
        return ""
    try:
        decoded_parts = email.header.decode_header(header_value)
        parts = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                try:
                    charset = charset or "utf-8"
                    parts.append(part.decode(charset, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    parts.append(part.decode("utf-8", errors="replace"))
            else:
                parts.append(part)
        return " ".join(parts)
    except Exception:
        return str(header_value)


def _html_to_text(html: str) -> str:
    """Convert HTML email body to clean plain text."""
    if not html:
        return ""
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style", "meta", "link", "noscript"]):
                tag.decompose()
            text = soup.get_text(separator="\n")
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            return "\n".join(lines)
        except Exception:
            pass
    # Fallback: strip tags with regex
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _decode_payload(part) -> Optional[str]:
    """Decode an email part payload to string, handling encodings."""
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return None
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return payload.decode("utf-8", errors="replace")
    except Exception:
        return None


def _extract_body_from_message(msg) -> str:
    """Walk a MIME message and extract the best text body."""
    body_text = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get_content_disposition() or "")

            if "attachment" in content_disposition.lower():
                continue

            decoded = _decode_payload(part)
            if decoded is None:
                continue

            if content_type == "text/plain":
                body_text = decoded
            elif content_type == "text/html":
                html_body = decoded
    else:
        decoded = _decode_payload(msg)
        if decoded:
            content_type = msg.get_content_type()
            if content_type == "text/html":
                html_body = decoded
            else:
                body_text = decoded

    if body_text:
        return body_text.strip()
    if html_body:
        return _html_to_text(html_body).strip()
    return ""


def _extract_headers(msg) -> Dict[str, Any]:
    """Extract and decode all relevant email headers."""
    headers = {
        "from": "",
        "from_name": "",
        "from_address": "",
        "to": "",
        "cc": "",
        "subject": "",
        "date": "",
        "date_iso": "",
        "message_id": "",
        "reply_to": "",
        "return_path": "",
        "authentication_results": "",
        "received_spf": "",
        "dkim_signature": "",
        "x_originating_ip": "",
        "content_type": "",
    }

    try:
        from_val = _decode_mime_header(msg.get("From", ""))
        headers["from"] = from_val
        name, addr = parseaddr(from_val)
        headers["from_name"] = name
        headers["from_address"] = addr
    except Exception:
        pass

    try:
        headers["to"] = _decode_mime_header(msg.get("To", ""))
    except Exception:
        pass
    try:
        headers["cc"] = _decode_mime_header(msg.get("Cc", ""))
    except Exception:
        pass
    try:
        headers["subject"] = _decode_mime_header(msg.get("Subject", ""))
    except Exception:
        pass
    try:
        date_str = msg.get("Date", "")
        headers["date"] = date_str
        parsed = parsedate_to_datetime(date_str)
        if parsed:
            headers["date_iso"] = parsed.isoformat()
    except Exception:
        pass
    try:
        headers["message_id"] = str(msg.get("Message-ID", "")).strip("<>")
    except Exception:
        pass
    try:
        headers["reply_to"] = _decode_mime_header(msg.get("Reply-To", ""))
    except Exception:
        pass
    try:
        headers["return_path"] = str(msg.get("Return-Path", ""))
    except Exception:
        pass
    try:
        headers["authentication_results"] = str(msg.get("Authentication-Results", ""))
    except Exception:
        pass
    try:
        headers["received_spf"] = str(msg.get("Received-SPF", ""))
    except Exception:
        pass
    try:
        headers["dkim_signature"] = str(msg.get("DKIM-Signature", ""))[:100]
    except Exception:
        pass
    try:
        headers["x_originating_ip"] = str(msg.get("X-Originating-IP", ""))
    except Exception:
        pass
    try:
        headers["content_type"] = str(msg.get("Content-Type", ""))
    except Exception:
        pass

    return headers


def _extract_attachments(msg) -> List[Dict[str, Any]]:
    """Extract attachment metadata from the message."""
    attachments = []
    try:
        for part in msg.walk():
            content_disposition = str(part.get_content_disposition() or "")
            if "attachment" not in content_disposition.lower():
                continue
            filename = part.get_filename()
            if filename:
                filename = _decode_mime_header(filename)
            attachments.append({
                "filename": filename or "unnamed",
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b""),
            })
    except Exception:
        pass
    return attachments


def parse_eml(file_bytes: bytes) -> Dict[str, Any]:
    """
    Parse a .eml file (MIME format) and return structured email data.
    """
    result = {
        "format": "eml",
        "subject": "",
        "from": "",
        "from_address": "",
        "to": "",
        "body": "",
        "headers": {},
        "attachments": [],
        "has_html": False,
        "urls_found": [],
        "error": None,
    }

    try:
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
    except Exception as exc:
        # Try with different policy
        try:
            msg = email.message_from_bytes(file_bytes)
        except Exception as exc2:
            result["error"] = f"Failed to parse .eml: {exc2}"
            return result

    try:
        headers = _extract_headers(msg)
        result["headers"] = headers
        result["subject"] = headers["subject"]
        result["from"] = headers["from"]
        result["from_address"] = headers["from_address"]
        result["to"] = headers["to"]

        body = _extract_body_from_message(msg)
        result["body"] = body
        result["has_html"] = bool(
            body and body != _extract_body_from_message(msg)
        )

        result["attachments"] = _extract_attachments(msg)

        url_pattern = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE)
        result["urls_found"] = list(set(url_pattern.findall(body)))

    except Exception as exc:
        result["error"] = f"Error extracting email content: {exc}"

    return result


def parse_msg(file_bytes: bytes) -> Dict[str, Any]:
    """
    Parse a .msg file (Outlook format) and return structured email data.
    Falls back to basic extraction if extract-msg is not installed.
    """
    result = {
        "format": "msg",
        "subject": "",
        "from": "",
        "from_address": "",
        "to": "",
        "body": "",
        "headers": {},
        "attachments": [],
        "has_html": False,
        "urls_found": [],
        "error": None,
    }

    if not HAS_MSG:
        result["error"] = (
            "extract-msg library not installed. Install with: pip install extract-msg"
        )
        return result

    try:
        msg = extract_msg.Message(file_bytes)
        msg.message

        result["subject"] = msg.subject or ""
        result["from"] = msg.sender or ""
        result["to"] = msg.to or ""

        body = msg.body or ""
        html_body = msg.htmlBody or ""

        if body.strip():
            result["body"] = body.strip()
        elif html_body:
            result["body"] = _html_to_text(html_body)
            result["has_html"] = True

        result["headers"] = {
            "from": result["from"],
            "to": result["to"],
            "subject": result["subject"],
            "date": str(msg.date or ""),
            "message_id": str(msg.messageId or ""),
        }

        for attachment in msg.attachments:
            result["attachments"].append({
                "filename": attachment.longFilename or attachment.shortFilename or "unnamed",
                "size": attachment.dataSize if hasattr(attachment, "dataSize") else 0,
            })

        url_pattern = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE)
        result["urls_found"] = list(set(url_pattern.findall(result["body"])))

        # Extract from address
        if result["from"]:
            _, addr = parseaddr(result["from"])
            result["from_address"] = addr

        msg.close()

    except Exception as exc:
        result["error"] = f"Failed to parse .msg: {exc}"

    return result


def parse_email_file(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Auto-detect email format (.eml or .msg) and parse accordingly.
    """
    lower = filename.lower()
    if lower.endswith(".msg"):
        return parse_msg(file_bytes)
    return parse_eml(file_bytes)
