import pytest
import sqlite3
from pathlib import Path
from src.scim import handle_scim_request, _list_users

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


@pytest.fixture
def clean_users():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM users")
    conn.commit()
    conn.close()
    yield


def test_list_users(clean_users):
    result = handle_scim_request("GET", "/api/v1/scim/Users", None)
    assert result["schemas"][0] == "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    assert isinstance(result["Resources"], list)


def test_create_user(clean_users):
    result = handle_scim_request("POST", "/api/v1/scim/Users", {
        "userName": "scim_test_user",
        "emails": [{"value": "scim@test.com"}],
    })
    assert result["userName"] == "scim_test_user"
    assert "id" in result


def test_create_duplicate(clean_users):
    handle_scim_request("POST", "/api/v1/scim/Users", {"userName": "dup_user"})
    result = handle_scim_request("POST", "/api/v1/scim/Users", {"userName": "dup_user"})
    assert "status" in result and result["status"] == "409"


def test_get_user(clean_users):
    created = handle_scim_request("POST", "/api/v1/scim/Users", {"userName": "get_user_test"})
    uid = created["id"]
    result = handle_scim_request("GET", f"/api/v1/scim/Users/{uid}", None)
    assert result["userName"] == "get_user_test"


def test_get_nonexistent():
    result = handle_scim_request("GET", "/api/v1/scim/Users/99999", None)
    assert "status" in result and result["status"] == "404"


def test_deactivate_user(clean_users):
    created = handle_scim_request("POST", "/api/v1/scim/Users", {"userName": "deact_test"})
    uid = created["id"]
    result = handle_scim_request("DELETE", f"/api/v1/scim/Users/{uid}", None)
    assert result["active"] is False
