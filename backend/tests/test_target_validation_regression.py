"""Regression test suite for authorized target registration and assessment validation.

Covers:
- Registering a bare IPv4 address.
- Registering a canonical IPv4 CIDR where supported.
- Registering a DNS hostname.
- Rejecting malformed hosts, URLs in bare-host/scope fields, and noncanonical CIDRs.
- Accepting a valid web endpoint with an explicit non-default port.
- Matching 127.0.0.1 to an authorized 127.0.0.1/32 scope.
- Preserving port 3000 in web assessment dispatch and tool configuration.
- Preventing a different target profile from being used accidentally (preferred_target_id).
- Rejecting out-of-scope targets on the backend.
- Enforcing prohibited assessment methods and expired authorizations.
- TargetEndpoint parsing and canonical endpoint normalization parity.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, Scan, TargetAuditEvent
from backend.auth import SESSION_COOKIE, AdminSession, _token_hash
from backend.services.target_validation import (
    TargetError,
    normalize_target,
    normalize_scope_asset,
    parse_target_endpoint,
    validate_target,
)
from backend.services.scope_validator import (
    find_authorizing_target,
)
from backend.integrations.nmap import command as nmap_command

TOKEN = 'B' * 32
SESSION_TOKEN = 'test-session-secret-token-32-chars-long'
CSRF_TOKEN = 'test-csrf-secret-token-32-chars-long'


@pytest.fixture
def reg_env(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        api_token=TOKEN,
        allowed_targets=('127.0.0.1', 'example.com'),
        allow_private_targets=True,
    )
    app = create_app(settings)
    app.config['TESTING'] = True

    with Session(app.extensions['database']) as session:
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        session.add(
            AdminSession(
                token_hash=_token_hash(SESSION_TOKEN),
                username='security_admin',
                csrf_token=CSRF_TOKEN,
                created_at=now_dt,
                expires_at=now_dt + timedelta(hours=1),
            )
        )
        session.commit()

    return app, settings


def auth_client(app):
    client = app.test_client()
    client.set_cookie(SESSION_COOKIE, SESSION_TOKEN)
    return client


# ---------------------------------------------------------------------------
# 1. Scope and Target Normalization / Validation Unit Tests
# ---------------------------------------------------------------------------

def test_registering_bare_ipv4_and_hostname():
    """Bare IPv4 and DNS hostnames normalize cleanly."""
    assert normalize_scope_asset("127.0.0.1") == "127.0.0.1"
    assert normalize_scope_asset("192.168.1.100") == "192.168.1.100"
    assert normalize_scope_asset("example.com") == "example.com"
    assert normalize_scope_asset("juice-shop.local") == "juice-shop.local"


def test_registering_canonical_ipv4_cidr():
    """Canonical IPv4 CIDR entries normalize cleanly."""
    assert normalize_scope_asset("127.0.0.1/32") == "127.0.0.1/32"
    assert normalize_scope_asset("10.0.0.0/24") == "10.0.0.0/24"
    assert normalize_scope_asset("::1/128") == "::1/128"


def test_rejecting_urls_and_ports_in_scope_definitions():
    """URLs and host:port strings are strictly rejected in scope registration."""
    with pytest.raises(TargetError, match="Scope entries must be a bare hostname, IP address, or canonical CIDR network"):
        normalize_scope_asset("http://127.0.0.1:3000")

    with pytest.raises(TargetError, match="Scope entries must be a bare hostname, IP address, or canonical CIDR network"):
        normalize_scope_asset("https://example.com/api")

    with pytest.raises(TargetError, match="Scope entries must be a bare hostname, IP address, or canonical CIDR network"):
        normalize_scope_asset("127.0.0.1:3000")


def test_rejecting_noncanonical_cidr_and_wildcards():
    """Noncanonical CIDRs and wildcard entries are rejected."""
    # Host bits set in CIDR
    with pytest.raises(TargetError, match="CIDR scope entries must be canonical IPv4 or IPv6 networks"):
        normalize_scope_asset("192.168.1.5/24")

    # Wildcards
    with pytest.raises(TargetError):
        normalize_scope_asset("*.example.com")


# ---------------------------------------------------------------------------
# 2. Endpoint Parsing and Port Handling Tests
# ---------------------------------------------------------------------------

def test_parse_target_endpoint_variations():
    """Endpoints with URLs, custom ports, and single-host CIDRs are parsed correctly."""
    # Full URL with port
    ep1 = parse_target_endpoint("http://127.0.0.1:3000")
    assert ep1.host == "127.0.0.1"
    assert ep1.port == 3000
    assert ep1.scheme == "http"
    assert ep1.canonical_endpoint == "http://127.0.0.1:3000"

    # Full URL with path
    ep2 = parse_target_endpoint("https://juice-shop.local:8443/rest")
    assert ep2.host == "juice-shop.local"
    assert ep2.port == 8443
    assert ep2.scheme == "https"
    assert ep2.path == "/rest"
    assert ep2.canonical_endpoint == "https://juice-shop.local:8443/rest"

    # Host:Port without scheme
    ep3 = parse_target_endpoint("127.0.0.1:3000")
    assert ep3.host == "127.0.0.1"
    assert ep3.port == 3000
    assert ep3.scheme == "http"
    assert ep3.canonical_endpoint == "http://127.0.0.1:3000"

    # Single-host CIDR
    ep4 = parse_target_endpoint("127.0.0.1/32")
    assert ep4.host == "127.0.0.1"
    assert ep4.port is None
    assert ep4.canonical_endpoint == "127.0.0.1"

    # Bare IP
    ep5 = parse_target_endpoint("127.0.0.1")
    assert ep5.host == "127.0.0.1"
    assert ep5.port is None
    assert ep5.canonical_endpoint == "127.0.0.1"


def test_validate_target_with_allowed_cidr():
    """validate_target matches 127.0.0.1:3000 against allowed_targets containing 127.0.0.1/32."""
    validated = validate_target(
        "http://127.0.0.1:3000",
        allowed_targets=["127.0.0.1/32"],
        allow_private=True,
    )
    assert validated.host == "127.0.0.1"
    assert validated.port == 3000
    assert validated.scheme == "http"
    assert validated.canonical_endpoint == "http://127.0.0.1:3000"


def test_reject_out_of_scope_target():
    """validate_target rejects genuinely out-of-scope targets."""
    with pytest.raises(TargetError, match="not in the administrator-configured exact-host allowlist"):
        validate_target("192.168.100.50", allowed_targets=["127.0.0.1/32"])


def test_nmap_command_preserves_custom_port():
    """Nmap command appends target_port to port specification if not present."""
    cmd = nmap_command(Path("nmap"), "127.0.0.1", "quick", Path("out.xml"), target_port=3000)
    assert "-p" in cmd
    port_idx = cmd.index("-p") + 1
    ports = cmd[port_idx]
    assert "3000" in ports.split(",")


# ---------------------------------------------------------------------------
# 3. Integration Tests via Flask Endpoints
# ---------------------------------------------------------------------------

def test_api_target_registration_success(reg_env):
    """API accepts registration with bare IP, canonical CIDR, and hostname."""
    app, _ = reg_env
    client = auth_client(app)

    now = datetime.now(timezone.utc)
    res = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "OWASP Juice Shop Lab",
            "target_type": "lab",
            "owner_organization": "OWASP Foundation",
            "scope_domains": ["127.0.0.1/32", "juice-shop.local"],
            "permitted_methods": ["port_scan", "web_service_discovery", "vulnerability_check"],
            "prohibited_methods": ["dos", "exploit"],
            "rate_limit_rps": 10,
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "evidence_reference": "Local Lab Policy Ref #001",
        },
    )
    assert res.status_code == 201
    data = res.get_json()["data"]
    assert "127.0.0.1/32" in data["scope_domains"]
    assert "juice-shop.local" in data["scope_domains"]


def test_api_target_registration_rejects_url_in_scope(reg_env):
    """API rejects URLs entered into scope_domains with a clear error."""
    app, _ = reg_env
    client = auth_client(app)

    now = datetime.now(timezone.utc)
    res = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "Invalid Target",
            "target_type": "lab",
            "owner_organization": "OWASP Foundation",
            "scope_domains": ["http://127.0.0.1:3000"],
            "permitted_methods": ["port_scan"],
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "evidence_reference": "Ref #002",
        },
    )
    assert res.status_code == 400
    err = res.get_json()["error"]
    assert "Scope entries must be a bare hostname, IP address, or canonical CIDR network" in err["message"]


def test_api_targets_check_with_preferred_target_id(reg_env):
    """Check target endpoint returns the preferred target rather than accidental fallback."""
    app, _ = reg_env
    client = auth_client(app)
    now = datetime.now(timezone.utc)

    # Register Target A (Waniti Loopback Lab)
    res_a = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "Waniti Loopback Lab",
            "target_type": "lab",
            "owner_organization": "Lab Org A",
            "scope_domains": ["127.0.0.1"],
            "permitted_methods": ["port_scan"],
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "evidence_reference": "Lab A Ref",
        },
    )
    assert res_a.status_code == 201
    id_a = res_a.get_json()["data"]["id"]

    # Register Target B (OWASP Juice Shop) with 127.0.0.1/32
    res_b = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "OWASP Juice Shop",
            "target_type": "lab",
            "owner_organization": "OWASP",
            "scope_domains": ["127.0.0.1/32"],
            "permitted_methods": ["port_scan", "web_service_discovery", "vulnerability_check"],
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "evidence_reference": "Lab B Ref",
        },
    )
    assert res_b.status_code == 201
    id_b = res_b.get_json()["data"]["id"]

    # Check without target_id: both cover 127.0.0.1, returns covered=True
    res_check = client.get("/api/targets/check?host=127.0.0.1")
    assert res_check.status_code == 200
    assert res_check.get_json()["data"]["covered"] is True

    # Check with preferred target_id=id_b: MUST return OWASP Juice Shop
    res_check_b = client.get(f"/api/targets/check?host=http://127.0.0.1:3000&target_id={id_b}")
    assert res_check_b.status_code == 200
    data_b = res_check_b.get_json()["data"]
    assert data_b["covered"] is True
    assert data_b["matched_target"]["id"] == id_b
    assert data_b["matched_target"]["name"] == "OWASP Juice Shop"
    assert data_b["canonical_endpoint"] == "http://127.0.0.1:3000"


def test_api_scan_creation_preserves_port_and_scheme(reg_env):
    """Creating a scan with http://127.0.0.1:3000 preserves target_port and target_scheme in configuration."""
    app, _ = reg_env
    client = auth_client(app)
    now = datetime.now(timezone.utc)

    # Register OWASP Juice Shop
    res_b = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "OWASP Juice Shop",
            "target_type": "lab",
            "owner_organization": "OWASP",
            "scope_domains": ["127.0.0.1/32"],
            "permitted_methods": ["port_scan", "web_service_discovery", "vulnerability_check"],
            "prohibited_methods": ["dos"],
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "evidence_reference": "Juice Shop SOW",
        },
    )
    assert res_b.status_code == 201
    target_id = res_b.get_json()["data"]["id"]

    # Create scan for http://127.0.0.1:3000
    res_scan = client.post(
        "/api/scans",
        headers={
            "X-CSRF-Token": CSRF_TOKEN,
            "Idempotency-Key": "test-idempotency-key-001",
        },
        json={
            "target": "http://127.0.0.1:3000",
            "profile": "quick",
            "tools": ["nmap", "httpx"],
            "authorized": True,
            "target_id": target_id,
        },
    )
    assert res_scan.status_code == 202
    scan_data = res_scan.get_json()["data"]
    assert scan_data["target"] == "http://127.0.0.1:3000"
    config = scan_data["configuration"]
    assert config["target_port"] == 3000
    assert config["target_scheme"] == "http"
    assert config["authorized_target_id"] == target_id
    assert config["authorized_target_name"] == "OWASP Juice Shop"


def test_api_scan_rejection_for_expired_target(reg_env):
    """A scan cannot be dispatched against an expired target authorization."""
    app, _ = reg_env
    client = auth_client(app)
    past = datetime.now(timezone.utc) - timedelta(days=5)

    res_target = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "Expired Target",
            "target_type": "lab",
            "owner_organization": "Past Corp",
            "scope_domains": ["127.0.0.1/32"],
            "permitted_methods": ["port_scan"],
            "valid_from": (past - timedelta(days=30)).isoformat(),
            "valid_to": past.isoformat(),
            "evidence_reference": "Old Ref",
        },
    )
    assert res_target.status_code == 201
    target_id = res_target.get_json()["data"]["id"]

    res_scan = client.post(
        "/api/scans",
        headers={
            "X-CSRF-Token": CSRF_TOKEN,
            "Idempotency-Key": "test-idempotency-key-002",
        },
        json={
            "target": "127.0.0.1",
            "profile": "quick",
            "tools": ["nmap"],
            "authorized": True,
            "target_id": target_id,
        },
    )
    assert res_scan.status_code == 403
    assert "expired" in res_scan.get_json()["error"]["message"]


def test_api_scan_rejection_for_prohibited_methods(reg_env):
    """Tools requiring prohibited methods are rejected at scan dispatch."""
    app, _ = reg_env
    client = auth_client(app)
    now = datetime.now(timezone.utc)

    res_target = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "Restricted Target",
            "target_type": "lab",
            "owner_organization": "Restricted Corp",
            "scope_domains": ["127.0.0.1/32"],
            "permitted_methods": ["port_scan", "web_service_discovery"],
            "prohibited_methods": ["vulnerability_check"],
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "evidence_reference": "Restricted Ref",
        },
    )
    assert res_target.status_code == 201
    target_id = res_target.get_json()["data"]["id"]

    # Try running nuclei (which maps to vulnerability_check) under standard profile
    res_scan = client.post(
        "/api/scans",
        headers={
            "X-CSRF-Token": CSRF_TOKEN,
            "Idempotency-Key": "test-idempotency-key-003",
        },
        json={
            "target": "127.0.0.1",
            "profile": "standard",
            "tools": ["nmap", "httpx", "nuclei"],
            "authorized": True,
            "target_id": target_id,
        },
    )
    assert res_scan.status_code == 403
    assert "explicitly prohibited" in res_scan.get_json()["error"]["message"]
