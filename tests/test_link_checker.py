import pytest
from src.link_checker import check_url_safety, resolve_redirect_chain


def test_ip_based_url():
    result = check_url_safety("http://192.168.1.1/login")
    assert result["is_ip_based"]
    assert result["risk_score"] >= 30


def test_suspicious_tld():
    result = check_url_safety("http://login-page.tk/verify")
    assert result["suspicious_tld"]
    assert result["risk_score"] >= 25


def test_suspicious_keywords():
    result = check_url_safety("https://secure-login.example.com/verify-account")
    assert result["suspicious_keywords"]


def test_clean_url():
    result = check_url_safety("https://github.com/example/repo")
    assert not result["is_ip_based"]
    assert not result["suspicious_tld"]


def test_resolve_redirect_empty():
    chain = resolve_redirect_chain("https://example.com", max_depth=0)
    assert chain == ["https://example.com"]
