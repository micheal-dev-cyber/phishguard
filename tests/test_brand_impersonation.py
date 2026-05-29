import pytest
from src.brand_impersonation import (
    init_brand_protection, add_custom_brand, remove_custom_brand,
    get_all_brands, is_lookalike, analyze_sender_domain,
    run_brand_impersonation_check, extract_domains,
)


@pytest.fixture(autouse=True)
def setup():
    init_brand_protection()
    yield


def test_is_lookalike():
    assert is_lookalike("g00gle.com", "google.com")[0] is True
    assert is_lookalike("paypa1.com", "paypal.com")[0] is True
    assert is_lookalike("google.com", "google.com")[0] is False
    assert is_lookalike("example.com", "google.com")[0] is False


def test_add_custom_brand():
    # Remove if already exists
    import sqlite3
    from pathlib import Path
    conn = sqlite3.connect(str(Path(__file__).parent.parent / "data" / "phishguard.db"))
    c = conn.cursor()
    c.execute("DELETE FROM brand_protection WHERE domain='mycompany.com'")
    conn.commit()
    conn.close()
    assert add_custom_brand("mycompany.com", "MyCompany") is True
    brands = get_all_brands()
    assert any(b["domain"] == "mycompany.com" for b in brands)


def test_remove_custom_brand():
    add_custom_brand("tempbrand.com")
    assert remove_custom_brand("tempbrand.com") is True


def test_analyze_sender_domain():
    result = analyze_sender_domain("attacker@g00gle.com")
    assert len(result["lookalikes"]) > 0
    assert result["risk_score"] >= 50


def test_analyze_sender_no_match():
    result = analyze_sender_domain("user@unknown-domain-xyz.com")
    assert len(result["lookalikes"]) == 0


def test_extract_domains():
    urls = extract_domains("Check https://g00gle.com and http://paypa1.com/login")
    assert "g00gle.com" in urls
    assert "paypa1.com" in urls


def test_run_brand_check():
    result = run_brand_impersonation_check(
        "Click here to reset your PayPal password",
        sender="phish@paypa1.com",
    )
    assert result["impersonation_detected"] is True or result["total_risk"] > 0
