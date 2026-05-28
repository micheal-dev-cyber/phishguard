"""Tests for the Secure Attachment Scanner."""

import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.attachment_scanner import (
    hash_file,
    is_allowed_attachment,
    scan_attachment,
    parse_vt_file_response,
)


class TestHashFile:
    def test_md5_length(self):
        result = hash_file(b"test content")
        assert len(result["md5"]) == 32

    def test_sha1_length(self):
        result = hash_file(b"test content")
        assert len(result["sha1"]) == 40

    def test_sha256_length(self):
        result = hash_file(b"test content")
        assert len(result["sha256"]) == 64

    def test_deterministic(self):
        a = hash_file(b"hello")
        b = hash_file(b"hello")
        assert a == b

    def test_differs_by_content(self):
        a = hash_file(b"hello")
        b = hash_file(b"world")
        assert a != b


class TestIsAllowedExtension:
    def test_pdf_allowed(self):
        assert is_allowed_attachment("report.pdf")

    def test_docx_allowed(self):
        assert is_allowed_attachment("document.docx")

    def test_py_allowed(self):
        assert is_allowed_attachment("script.py")

    def test_txt_not_allowed(self):
        assert not is_allowed_attachment("notes.txt")

    def test_png_not_allowed(self):
        assert not is_allowed_attachment("image.png")

    def test_no_ext_not_allowed(self):
        assert not is_allowed_attachment("Makefile")


class TestParseVTResponse:
    def test_none_data(self):
        result = parse_vt_file_response(None)
        assert result["status"] == "not_queried"

    def test_not_found(self):
        result = parse_vt_file_response({"not_found": True})
        assert result["status"] == "not_found"

    def test_error(self):
        result = parse_vt_file_response({"error": "HTTP 429"})
        assert result["status"] == "error"

    def test_clean_verdict(self):
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 5,
                        "undetected": 55,
                    },
                    "type_description": "PE32 executable",
                    "meaningful_name": "setup.exe",
                    "last_modification_date": 1700000000,
                }
            }
        }
        result = parse_vt_file_response(data)
        assert result["verdict"] == "clean"

    def test_malicious_verdict(self):
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 12,
                        "suspicious": 3,
                        "harmless": 0,
                        "undetected": 45,
                    }
                }
            }
        }
        result = parse_vt_file_response(data)
        assert result["verdict"] == "malicious"


class TestScanAttachment:
    def test_empty_data_returns_error(self):
        result = scan_attachment(b"", "empty.pdf")
        assert result["error"] == "empty file"

    def test_hashes_populated(self):
        result = scan_attachment(b"some file data", "test.pdf")
        assert len(result["md5"]) == 32
        assert len(result["sha256"]) == 64
        assert result["filename"] == "test.pdf"
        assert result["size"] == 14
