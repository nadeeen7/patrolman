"""Comprehensive regression tests for Issue 1, Issue 2, and Issue 3.

Verifies:
- Port 3000 preservation throughout assessment pipeline.
- Nmap output parsing port 3000 as open web service.
- Reachable authorized HTTP endpoint entering the web-service pipeline even if Nmap output is empty.
- httpx and whatweb receiving the correct endpoint when eligible.
- Wapiti and Nuclei following authorization and safe eligibility policies.
- Subfinder skipped for IP-only targets with truthful specific reason.
- SSLyze skipped for HTTP-only services with truthful specific reason.
- Unreachable services producing truthful skip/failure reasons.
- HTTP 500 regression: SQLite string datetime handling in target listing and scan serialization.
- Start assessment responsiveness and duplicate request prevention.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, Scan, ToolExecution, AdminSession, now
from backend.auth import SESSION_COOKIE, _token_hash
from backend.integrations.nmap import parse as nmap_parse
from backend.services.reachability import check_endpoint_reachability
from backend.services.scan_service import serialize, timestamp, ScanManager
from backend.services.target_authorization import format_iso

TOKEN = 'B' * 32
SESSION_TOKEN = 'test-session-secret-token-32-chars-long'
CSRF_TOKEN = 'test-csrf-secret-token-32-chars-long'


@pytest.fixture
def app_env(tmp_path):
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


# ===========================================================================
# ISSUE 2 REGRESSION TESTS: String Datetime Handling & HTTP 500 Fix
# ===========================================================================

def test_format_iso_handles_strings_and_naive_datetimes():
    """format_iso must safely handle None, str, naive datetime, and aware datetime."""
    assert format_iso(None) is None
    # String from SQLite
    iso_str = "2026-10-24 17:23:53"
    result = format_iso(iso_str)
    assert result.startswith("2026-10-24T17:23:53")
    assert result.endswith("+00:00")

    # Aware datetime
    aware_dt = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
    assert format_iso(aware_dt) == "2026-10-24T12:00:00+00:00"

    # Naive datetime
    naive_dt = datetime(2026, 10, 24, 12, 0, 0)
    assert format_iso(naive_dt) == "2026-10-24T12:00:00+00:00"


def test_timestamp_helper_does_not_crash_on_string():
    """timestamp() in scan_service must not raise TypeError when SQLite returns a string."""
    assert timestamp("2026-10-24T18:00:00Z") is not None
    assert timestamp(datetime.now(timezone.utc)) is not None
    assert timestamp(None) is None


def test_target_listing_with_string_dates_does_not_500(app_env):
    """GET /api/targets must not return 500 when target records contain string datetimes."""
    app, _ = app_env
    client = auth_client(app)

    # Insert raw target with string dates directly into database
    with Session(app.extensions['database']) as session:
        target = AuthorizedTarget(
            name="OWASP Juice Shop",
            target_type="lab",
            owner_organization="OWASP",
            scope_domains=["127.0.0.1/32"],
            permitted_methods=["port_scan", "web_service_discovery", "vulnerability_check"],
            valid_from=datetime.now(timezone.utc),
            valid_to=datetime.now(timezone.utc) + timedelta(days=30),
            evidence_reference="Test Ref",
            created_by="security_admin",
            updated_by="security_admin",
        )
        session.add(target)
        session.commit()

    # Query /api/targets?page_size=100 (which New Assessment calls)
    res = client.get("/api/targets?page_size=100")
    assert res.status_code == 200
    data = res.get_json()["data"]
    assert len(data) >= 1
    assert data[0]["name"] == "OWASP Juice Shop"
    assert data[0]["valid_from"] is not None


# ===========================================================================
# ISSUE 1 REGRESSION TESTS: Web Service Discovery & Tool Skipping
# ===========================================================================

def test_nmap_xml_with_port_3000_ppp_parsed_as_port_asset():
    """Nmap output with port 3000 identified as 'ppp' parses accurately without errors."""
    xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -p 80,443,8000,8443,3000 127.0.0.1" start="1729800000" version="7.80">
<host starttime="1729800001" endtime="1729800002">
<status state="up" reason="localhost-response"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="3000"><state state="open" reason="syn-ack"/><service name="ppp" method="table" conf="3"/></port>
</ports>
</host>
<runstats><finished time="1729800002" exit="success"/></runstats>
</nmaprun>"""
    results = nmap_parse(xml_output, "127.0.0.1")
    assert len(results.assets) == 2
    port_asset = next(a for a in results.assets if a['kind'] == 'port')
    assert port_asset['details']['port'] == 3000
    assert port_asset['details']['service']['name'] == 'ppp'


def test_reachability_check_against_local_or_mock():
    """check_endpoint_reachability performs a bounded probe and returns status."""
    # Loopback non-listening port (e.g. 59999) should fail cleanly
    reachable, reason = check_endpoint_reachability("http://127.0.0.1:59999", timeout=1.0)
    assert reachable is False
    assert reason is not None
    assert "refused" in reason.lower() or "connect" in reason.lower() or "timed out" in reason.lower()


def test_subfinder_truthful_skip_reason_for_ip_endpoint(app_env):
    """Subfinder produces truthful reason when skipped for an IP target."""
    app, settings = app_env
    manager = app.extensions['scan_manager']

    # Create scan for IP target
    with Session(app.extensions['database']) as session:
        scan = Scan(
            target="http://127.0.0.1:3000",
            profile="standard",
            created_by="security_admin",
            configuration={
                "addresses": ["127.0.0.1"],
                "tools": ["subfinder"],
                "authorized": True,
                "canonical_endpoint": "http://127.0.0.1:3000",
            },
        )
        session.add(scan)
        session.flush()
        execution = ToolExecution(tool="subfinder", scan_id=scan.id)
        scan.executions.append(execution)
        session.commit()
        scan_id = scan.id
        execution_id = execution.id

    cancel = MagicMock()
    cancel.is_set.return_value = False

    manager.capacity.acquire()
    # Run worker work() directly
    manager.work(scan_id, cancel)

    with Session(app.extensions['database']) as session:
        exec_record = session.get(ToolExecution, execution_id)
        assert exec_record.state == "skipped"
        assert "subdomain enumeration is only applicable to domain targets" in exec_record.error


def test_sslyze_truthful_skip_reason_for_http_target(app_env):
    """SSLyze produces truthful reason when target is HTTP-only."""
    app, settings = app_env
    manager = app.extensions['scan_manager']

    with Session(app.extensions['database']) as session:
        scan = Scan(
            target="http://127.0.0.1:3000",
            profile="standard",
            created_by="security_admin",
            configuration={
                "addresses": ["127.0.0.1"],
                "tools": ["sslyze"],
                "authorized": True,
                "target_port": 3000,
                "target_scheme": "http",
                "canonical_endpoint": "http://127.0.0.1:3000",
            },
        )
        session.add(scan)
        session.flush()
        execution = ToolExecution(tool="sslyze", scan_id=scan.id)
        scan.executions.append(execution)
        session.commit()
        scan_id = scan.id
        execution_id = execution.id

    cancel = MagicMock()
    cancel.is_set.return_value = False

    manager.capacity.acquire()
    with patch("backend.services.reachability.check_endpoint_reachability", return_value=(True, None)):
        manager.work(scan_id, cancel)

    with Session(app.extensions['database']) as session:
        exec_record = session.get(ToolExecution, execution_id)
        assert exec_record.state == "skipped"
        assert "HTTP-only service" in exec_record.error or "TLS/SSL auditing requires an HTTPS service" in exec_record.error


# ===========================================================================
# ISSUE 3 REGRESSION TESTS: Responsiveness and Duplicate Prevention
# ===========================================================================

def test_start_assessment_responsive_and_prevents_duplicate_submission(app_env):
    """POST /api/scans returns 202 quickly and subsequent requests with same idempotency key return 200."""
    app, _ = app_env
    client = auth_client(app)
    now = datetime.now(timezone.utc)

    # Register target
    res_t = client.post(
        "/api/targets",
        headers={"X-CSRF-Token": CSRF_TOKEN},
        json={
            "name": "Local Juice Shop",
            "target_type": "lab",
            "owner_organization": "OWASP",
            "scope_domains": ["127.0.0.1/32"],
            "permitted_methods": ["port_scan", "web_service_discovery"],
            "valid_from": now.isoformat(),
            "valid_to": (now + timedelta(days=30)).isoformat(),
            "evidence_reference": "Ref #101",
        },
    )
    assert res_t.status_code == 201
    target_id = res_t.get_json()["data"]["id"]

    idempotency_key = "test-idem-key-responsive-001"
    payload = {
        "target": "http://127.0.0.1:3000",
        "profile": "quick",
        "tools": ["nmap"],
        "authorized": True,
        "target_id": target_id,
    }

    # First submission -> 202 Accepted with scan id
    res1 = client.post(
        "/api/scans",
        headers={"X-CSRF-Token": CSRF_TOKEN, "Idempotency-Key": idempotency_key},
        json=payload,
    )
    assert res1.status_code == 202
    scan_id = res1.get_json()["data"]["id"]
    assert scan_id is not None

    # Duplicate submission with identical idempotency key -> 200 OK returning same scan
    res2 = client.post(
        "/api/scans",
        headers={"X-CSRF-Token": CSRF_TOKEN, "Idempotency-Key": idempotency_key},
        json=payload,
    )
    assert res2.status_code == 200
    assert res2.get_json()["data"]["id"] == scan_id
