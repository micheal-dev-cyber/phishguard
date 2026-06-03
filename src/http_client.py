"""Centralized HTTP client with retries, timeouts, and structured logging.

Usage:
    from src.http_client import get, post, put, patch, delete

    resp = get("https://api.example.com/data", headers={...})
    resp = post("https://api.example.com/data", json={...})

All methods return requests.Response (same API as requests.*).
Retries: 3 attempts with exponential backoff on 429, 5xx, and connection errors.
Timeout: 30s default, configurable per call via timeout= kwarg.
"""

import logging
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("http_client")

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5

_session: Optional[requests.Session] = None


def _get_session() -> requests.Session:
    global _session
    if _session is None:
        _session = requests.Session()
        retries = Retry(
            total=DEFAULT_MAX_RETRIES,
            read=DEFAULT_MAX_RETRIES,
            connect=DEFAULT_MAX_RETRIES,
            backoff_factor=DEFAULT_BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retries)
        _session.mount("https://", adapter)
        _session.mount("http://", adapter)
    return _session


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    session = _get_session()
    logger.debug("HTTP %s %s (timeout=%s)", method.upper(), url, timeout)
    try:
        resp = session.request(method, url, timeout=timeout, **kwargs)
        logger.debug("HTTP %s %s -> %s", method.upper(), url, resp.status_code)
        return resp
    except requests.exceptions.Timeout:
        logger.warning("HTTP %s %s timed out after %ss", method.upper(), url, timeout)
        raise
    except requests.exceptions.ConnectionError as exc:
        logger.warning("HTTP %s %s connection failed: %s", method.upper(), url, exc)
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("HTTP %s %s failed: %s", method.upper(), url, exc)
        raise


def get(url: str, **kwargs: Any) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    return request("POST", url, **kwargs)


def put(url: str, **kwargs: Any) -> requests.Response:
    return request("PUT", url, **kwargs)


def patch(url: str, **kwargs: Any) -> requests.Response:
    return request("PATCH", url, **kwargs)


def delete(url: str, **kwargs: Any) -> requests.Response:
    return request("DELETE", url, **kwargs)
