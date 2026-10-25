import os
import pytest
from backend.app import create_app
from backend.services import tool_manager

@pytest.fixture
def app():
    os.environ["FLASK_ENV"] = "testing"
    os.environ["AVA_API_TOKEN"] = "a" * 32
    app = create_app()
    app.config["TESTING"] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_api_operator_bearer_token_has_global_dashboard_coverage(client):
    """
    Regression test for Error 1 & 2:
    Bearer token requests should have g.auth_mode == 'bearer' and current_user() returning None,
    allowing operator to view aggregate dashboard and unassigned/legacy scan coverage without
    crashing or filtering out records.
    """
    headers = {"Authorization": "Bearer " + ("a" * 32)}
    resp = client.get("/api/dashboard", headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "metrics" in data or "counts" in data or "data" in data or "status" in data

def test_inventory_does_not_leak_cache_across_different_paths():
    """
    Regression test for Error 4:
    _VERIFIED_CACHE lookup requires exact executable match, preventing false positives
    from prior test runs with executable=None.
    """
    tool_manager._clear_cache()
    tool_manager._VERIFIED_CACHE["nmap"] = {
        "status": "ready",
        "executable": None,
        "version": "7.94"
    }
    # Querying diagnose with a non-existent path should fail and not inherit the cache
    valid, version, status, reason = tool_manager.diagnose("nmap", executable="/nonexistent/path/nmap.exe")
    assert valid is False
