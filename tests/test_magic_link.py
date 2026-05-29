import pytest
from src.magic_link import generate_magic_link, verify_magic_link, init_magic_links


def test_generate_and_verify():
    init_magic_links()
    token = generate_magic_link("user@test.com", expiry_minutes=15)
    assert len(token) > 20
    assert verify_magic_link("user@test.com", token)
    # Second use should fail (one-time)
    assert not verify_magic_link("user@test.com", token)


def test_wrong_email():
    init_magic_links()
    token = generate_magic_link("alice@test.com", expiry_minutes=15)
    assert not verify_magic_link("bob@test.com", token)


def test_bad_token():
    init_magic_links()
    assert not verify_magic_link("any@test.com", "faketoken123")
