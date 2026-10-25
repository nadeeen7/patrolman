"""Phase 3: Targeted regression tests for token-optional startup and authentication matrix.

Tests:
- Test A: Token-free startup (normal website mode without AVA_API_TOKEN)
- Test B: Normal login (valid credentials, invalid credentials, session persistence)
- Test C: Session isolation (User A vs User B, dashboard metrics, record isolation)
- Test D: Unauthenticated requests (rejection on protected endpoints)
- Test E: Missing Bearer token (when AVA_API_TOKEN is not configured, Bearer requests are rejected)
- Test F: Invalid Bearer token (when AVA_API_TOKEN is configured, invalid Bearer rejected and never falls back to session)
- Test G: Valid Bearer token (authenticated API operator access, no token leakage)
- Test H: Startup launcher (Start-Patrolman.ps1 supports token-free startup)
"""

import os
import shutil
import subprocess
import pytest
from datetime import datetime, timezone
from pathlib import Path
from flask import g
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app import create_app
from backend.config import Settings
from backend.models import AdminAccount, AdminSession, Scan, Finding, ToolExecution
from backend.auth import (
    SESSION_COOKIE, CSRF_COOKIE, initialize_admin
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Test A: Token-free startup
# ---------------------------------------------------------------------------
def test_token_free_startup_succeeds(tmp_path, monkeypatch):
    """Test A: Normal website mode initializes successfully without AVA_API_TOKEN."""
    monkeypatch.delenv("AVA_API_TOKEN", raising=False)
    monkeypatch.delenv("AVA_REQUIRE_API_TOKEN", raising=False)

    settings = Settings(
        data_dir=tmp_path,
        api_token="",
        allowed_targets=("127.0.0.1",),
        require_api_token=False,
    )
    settings.validate()
    assert settings.api_token == ""

    app = create_app(settings)
    app.config["TESTING"] = True
    client = app.test_client()

    # Public health endpoint responds normally
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["data"]["status"] == "ok"


# ---------------------------------------------------------------------------
# Test B: Normal login
# ---------------------------------------------------------------------------
def test_normal_login_workflow(tmp_path, monkeypatch):
    """Test B: Standard username/password login, session cookie, and authenticated endpoint."""
    monkeypatch.delenv("AVA_API_TOKEN", raising=False)

    settings = Settings(data_dir=tmp_path, api_token="", allowed_targets=("127.0.0.1",))
    app = create_app(settings)
    app.config["TESTING"] = True
    engine = app.extensions["database"]

    initialize_admin(engine, "auditor_bob", "SecureBobPassword123!", "SecureBobPassword123!")

    client = app.test_client()

    # Pre-auth CSRF token
    csrf_resp = client.get("/api/auth/csrf")
    assert csrf_resp.status_code == 200
    pre_csrf = csrf_resp.get_json()["data"]["csrf_token"]

    # 1. Invalid credentials rejected
    bad_login = client.post(
        "/api/auth/login",
        json={"username": "auditor_bob", "password": "WrongPassword999!"},
        headers={"X-CSRF-Token": pre_csrf},
    )
    assert bad_login.status_code == 401

    # 2. Valid credentials succeed
    good_login = client.post(
        "/api/auth/login",
        json={"username": "auditor_bob", "password": "SecureBobPassword123!"},
        headers={"X-CSRF-Token": pre_csrf},
    )
    assert good_login.status_code == 200
    login_data = good_login.get_json()["data"]
    assert login_data["username"] == "auditor_bob"
    session_csrf = login_data["csrf_token"]

    # Session cookie received
    cookie = client.get_cookie(SESSION_COOKIE)
    assert cookie is not None

    # 3. Access protected endpoint with valid session
    session_resp = client.get("/api/auth/session")
    assert session_resp.status_code == 200
    assert session_resp.get_json()["data"]["username"] == "auditor_bob"

    dashboard_resp = client.get("/api/dashboard")
    assert dashboard_resp.status_code == 200
    assert "metrics" in dashboard_resp.get_json() or "total_scans" in dashboard_resp.get_json()["data"]


# ---------------------------------------------------------------------------
# Test C: Session isolation
# ---------------------------------------------------------------------------
def test_multi_user_session_isolation(tmp_path, monkeypatch):
    """Test C: User A cannot see or access User B's scans or dashboard counts."""
    monkeypatch.delenv("AVA_API_TOKEN", raising=False)

    settings = Settings(data_dir=tmp_path, api_token="", allowed_targets=("127.0.0.1",))
    app = create_app(settings)
    app.config["TESTING"] = True
    engine = app.extensions["database"]

    initialize_admin(engine, "user_alpha", "PasswordAlpha123!", "PasswordAlpha123!")

    # Register second user
    client_reg = app.test_client()
    csrf_resp = client_reg.get("/api/auth/csrf")
    pre_csrf = csrf_resp.get_json()["data"]["csrf_token"]
    signup_resp = client_reg.post(
        "/api/auth/signup",
        json={
            "username": "user_beta",
            "password": "PasswordBeta123!",
            "confirm_password": "PasswordBeta123!",
        },
        headers={"X-CSRF-Token": pre_csrf},
    )
    assert signup_resp.status_code == 200

    # Create scans for User Alpha and User Beta in database
    with Session(engine) as db_session:
        scan_alpha = Scan(
            id="scan-alpha-111",
            target="127.0.0.1",
            profile="quick",
            created_by="user_alpha",
            state="completed",
        )
        scan_beta = Scan(
            id="scan-beta-222",
            target="127.0.0.1",
            profile="quick",
            created_by="user_beta",
            state="completed",
        )
        db_session.add_all([scan_alpha, scan_beta])
        db_session.commit()

    # Log in as user_alpha
    client_alpha = app.test_client()
    csrf_alpha = client_alpha.get("/api/auth/csrf").get_json()["data"]["csrf_token"]
    client_alpha.post(
        "/api/auth/login",
        json={"username": "user_alpha", "password": "PasswordAlpha123!"},
        headers={"X-CSRF-Token": csrf_alpha},
    )

    # User Alpha can see own scan
    resp = client_alpha.get("/api/scans/scan-alpha-111")
    assert resp.status_code == 200
    assert resp.get_json()["data"]["id"] == "scan-alpha-111"

    # User Alpha CANNOT see User Beta's scan (returns 404, no data leakage)
    resp = client_alpha.get("/api/scans/scan-beta-222")
    assert resp.status_code == 404

    # User Alpha dashboard shows only 1 scan
    dash = client_alpha.get("/api/dashboard").get_json()["data"]
    assert dash["total_scans"] == 1

    # Log in as user_beta
    client_beta = app.test_client()
    csrf_beta = client_beta.get("/api/auth/csrf").get_json()["data"]["csrf_token"]
    client_beta.post(
        "/api/auth/login",
        json={"username": "user_beta", "password": "PasswordBeta123!"},
        headers={"X-CSRF-Token": csrf_beta},
    )

    # User Beta can see own scan
    resp = client_beta.get("/api/scans/scan-beta-222")
    assert resp.status_code == 200

    # User Beta CANNOT see User Alpha's scan
    resp = client_beta.get("/api/scans/scan-alpha-111")
    assert resp.status_code == 404

    # User Beta dashboard shows only 1 scan
    dash_beta = client_beta.get("/api/dashboard").get_json()["data"]
    assert dash_beta["total_scans"] == 1


# ---------------------------------------------------------------------------
# Test D: Unauthenticated requests
# ---------------------------------------------------------------------------
def test_unauthenticated_requests_are_rejected(tmp_path, monkeypatch):
    """Test D: Protected endpoints reject unauthenticated requests."""
    monkeypatch.delenv("AVA_API_TOKEN", raising=False)

    settings = Settings(data_dir=tmp_path, api_token="", allowed_targets=("127.0.0.1",))
    app = create_app(settings)
    app.config["TESTING"] = True
    client = app.test_client()

    endpoints = [
        ("GET", "/api/dashboard"),
        ("GET", "/api/scans"),
        ("GET", "/api/tools"),
        ("GET", "/api/targets"),
        ("GET", "/api/audit-events"),
        ("POST", "/api/scans"),
    ]
    for method, path in endpoints:
        if method == "GET":
            r = client.get(path)
        else:
            r = client.post(path, json={})
        assert r.status_code == 401
        assert r.get_json()["error"]["code"] == "unauthorized"


# ---------------------------------------------------------------------------
# Test E: Missing Bearer token when AVA_API_TOKEN is not configured
# ---------------------------------------------------------------------------
def test_bearer_token_rejected_when_not_configured(tmp_path, monkeypatch):
    """Test E: When AVA_API_TOKEN is empty, any Bearer token is rejected with 401."""
    monkeypatch.delenv("AVA_API_TOKEN", raising=False)

    settings = Settings(data_dir=tmp_path, api_token="", allowed_targets=("127.0.0.1",))
    app = create_app(settings)
    app.config["TESTING"] = True
    client = app.test_client()

    headers = {"Authorization": "Bearer some-arbitrary-token-here-1234567890"}
    resp = client.get("/api/dashboard", headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


# ---------------------------------------------------------------------------
# Test F: Invalid Bearer token rejection and no fallback
# ---------------------------------------------------------------------------
def test_invalid_bearer_token_rejected_without_fallback(tmp_path):
    """Test F: Invalid Bearer token is rejected even if a valid session cookie exists."""
    valid_token = "K" * 32
    settings = Settings(data_dir=tmp_path, api_token=valid_token, allowed_targets=("127.0.0.1",))
    app = create_app(settings)
    app.config["TESTING"] = True
    engine = app.extensions["database"]

    initialize_admin(engine, "charlie", "PasswordCharlie123!", "PasswordCharlie123!")

    client = app.test_client()
    csrf = client.get("/api/auth/csrf").get_json()["data"]["csrf_token"]
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "charlie", "password": "PasswordCharlie123!"},
        headers={"X-CSRF-Token": csrf},
    )
    assert login_resp.status_code == 200

    # Client now holds a valid session cookie, but sends an INVALID Bearer token
    headers = {"Authorization": "Bearer WRONG_TOKEN_VALUE_0000000000000000"}
    resp = client.get("/api/dashboard", headers=headers)

    # MUST be rejected with 401 and must NOT fall back to the charlie session!
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


# ---------------------------------------------------------------------------
# Test G: Valid Bearer token works and does not leak
# ---------------------------------------------------------------------------
def test_valid_bearer_token_works_and_does_not_leak(tmp_path):
    """Test G: Valid Bearer token grants administrative operator access and does not leak."""
    valid_token = "Z" * 32
    settings = Settings(data_dir=tmp_path, api_token=valid_token, allowed_targets=("127.0.0.1",))
    app = create_app(settings)
    app.config["TESTING"] = True
    client = app.test_client()

    headers = {"Authorization": f"Bearer {valid_token}"}
    resp = client.get("/api/dashboard", headers=headers)
    assert resp.status_code == 200
    data_str = resp.get_data(as_text=True)
    # The secret token must never be reflected in responses
    assert valid_token not in data_str


# ---------------------------------------------------------------------------
# Test H: Startup launcher syntax and token-free support
# ---------------------------------------------------------------------------
def test_startup_launcher_supports_token_free_mode():
    """Test H: Start-Patrolman.ps1 script includes token-free normal website startup path."""
    script_path = PROJECT_ROOT / "Start-Patrolman.ps1"
    content = script_path.read_text(encoding="utf-8")
    assert "Starting PATROLMAN in normal website mode" in content
    assert "RequireApiToken" in content
