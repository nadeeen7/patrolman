"""Comprehensive tests for Phase 1: Authorized Target and Scope Manager."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, TargetAuditEvent
from backend.auth import SESSION_COOKIE, AdminSession, _token_hash

TOKEN = 'A' * 32
SESSION_TOKEN = 'test-session-secret-token-32-chars-long'
CSRF_TOKEN = 'test-csrf-secret-token-32-chars-long'


@pytest.fixture
def test_env(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token=TOKEN, allowed_targets=('127.0.0.1', 'example.com'))
    app = create_app(settings)
    app.config['TESTING'] = True

    # Seed an admin session for authenticated web requests
    with Session(app.extensions['database']) as session:
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        session.add(AdminSession(
            token_hash=_token_hash(SESSION_TOKEN),
            username='security_admin',
            csrf_token=CSRF_TOKEN,
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=1),
        ))
        session.commit()

    return app, settings


def bearer_client(app):
    client = app.test_client()
    return client


def session_client(app):
    client = app.test_client()
    client.set_cookie(SESSION_COOKIE, SESSION_TOKEN)
    return client


def test_unauthenticated_requests_rejected(test_env):
    app, _ = test_env
    client = app.test_client()

    # GET targets
    res = client.get('/api/targets')
    assert res.status_code == 401

    # POST targets
    res = client.post('/api/targets', json={'name': 'Test'})
    assert res.status_code == 401


def test_csrf_protection_on_target_state_changes(test_env):
    app, _ = test_env
    client = session_client(app)

    now = datetime.now(timezone.utc)
    valid_from = now.isoformat()
    valid_to = (now + timedelta(days=30)).isoformat()

    payload = {
        'name': 'Corp Website',
        'target_type': 'organization',
        'owner_organization': 'ACME Corp',
        'scope_domains': ['example.com'],
        'valid_from': valid_from,
        'valid_to': valid_to,
        'evidence_reference': 'Board Authorization 2026-Q1',
    }

    # State-changing POST without CSRF header must fail with 403
    res = client.post('/api/targets', json=payload)
    assert res.status_code == 403

    # With CSRF token, it succeeds
    res = client.post('/api/targets', json=payload, headers={'X-CSRF-Token': CSRF_TOKEN})
    assert res.status_code == 201
    assert res.get_json()['data']['name'] == 'Corp Website'


def test_target_registration_all_authorization_types(test_env):
    app, _ = test_env
    client = bearer_client(app)
    headers = {'Authorization': f'Bearer {TOKEN}'}

    now = datetime.now(timezone.utc)
    valid_from = now.isoformat()
    valid_to = (now + timedelta(days=60)).isoformat()

    types = [
        ('Internal Infrastructure', 'organization', 'Enterprise IT', ['127.0.0.1'], ['api.internal.local'], 'IT Charter 2026'),
        ('Client Penetration Test', 'client', 'Globex Corp', ['example.com'], ['auth.example.com'], 'Signed SOW #GLX-2026-99'),
        ('HackerOne Bug Bounty', 'bug_bounty', 'CyberSecurity Labs', ['example.com'], [], 'https://hackerone.com/cybersec'),
        ('Training CTF Environment', 'lab', 'InfoSec Institute', ['127.0.0.1'], [], 'Course Lab Permission Doc 44'),
    ]

    for name, t_type, owner, domains, subdomains, evidence in types:
        payload = {
            'name': name,
            'target_type': t_type,
            'owner_organization': owner,
            'scope_domains': domains,
            'explicit_subdomains': subdomains,
            'excluded_scope': ['/admin/billing', '127.0.0.99'],
            'permitted_methods': ['port_scan', 'tls_audit'],
            'prohibited_methods': ['dos', 'bruteforce'],
            'rate_limit_rps': 5,
            'valid_from': valid_from,
            'valid_to': valid_to,
            'evidence_reference': evidence,
        }
        res = client.post('/api/targets', json=payload, headers=headers)
        assert res.status_code == 201, res.get_json()
        data = res.get_json()['data']
        assert data['target_type'] == t_type
        assert data['owner_organization'] == owner
        assert data['effective_status'] == 'active'
        assert data['created_by'] == 'api_operator'
        assert len(data['audit_events']) == 1
        assert data['audit_events'][0]['event_type'] == 'created'


def test_rejection_of_invalid_dates(test_env):
    app, _ = test_env
    client = bearer_client(app)
    headers = {'Authorization': f'Bearer {TOKEN}'}

    now = datetime.now(timezone.utc)

    # valid_to <= valid_from
    res = client.post('/api/targets', json={
        'name': 'Test Date',
        'target_type': 'organization',
        'owner_organization': 'ACME Corp',
        'scope_domains': ['example.com'],
        'valid_from': (now + timedelta(days=10)).isoformat(),
        'valid_to': now.isoformat(),
        'evidence_reference': 'Ref #1',
    }, headers=headers)
    assert res.status_code == 400
    assert 'valid_to) must be after' in res.get_json()['error']['message']

    # Malformed date
    res = client.post('/api/targets', json={
        'name': 'Test Date',
        'target_type': 'organization',
        'owner_organization': 'ACME Corp',
        'scope_domains': ['example.com'],
        'valid_from': 'not-a-date',
        'valid_to': now.isoformat(),
        'evidence_reference': 'Ref #1',
    }, headers=headers)
    assert res.status_code == 400


def test_rejection_of_malformed_targets_and_wildcards(test_env):
    app, _ = test_env
    client = bearer_client(app)
    headers = {'Authorization': f'Bearer {TOKEN}'}

    now = datetime.now(timezone.utc)
    base_payload = {
        'name': 'Scope Test',
        'target_type': 'client',
        'owner_organization': 'Acme',
        'valid_from': now.isoformat(),
        'valid_to': (now + timedelta(days=30)).isoformat(),
        'evidence_reference': 'Signed letter',
    }

    # URL with protocol and path
    res = client.post('/api/targets', json={
        **base_payload,
        'scope_domains': ['https://example.com/api'],
    }, headers=headers)
    assert res.status_code == 400

    # Wildcard domain
    res = client.post('/api/targets', json={
        **base_payload,
        'scope_domains': ['*.example.com'],
    }, headers=headers)
    assert res.status_code == 400
    assert 'Wildcard' in res.get_json()['error']['message'] or 'hostname' in res.get_json()['error']['message']

    # Subdomain wildcard
    res = client.post('/api/targets', json={
        **base_payload,
        'scope_domains': ['example.com'],
        'explicit_subdomains': ['*.sub.example.com'],
    }, headers=headers)
    assert res.status_code == 400

    # Empty scope
    res = client.post('/api/targets', json={
        **base_payload,
        'scope_domains': [],
    }, headers=headers)
    assert res.status_code == 400

    # Embedded credentials in evidence reference
    res = client.post('/api/targets', json={
        **base_payload,
        'scope_domains': ['example.com'],
        'evidence_reference': 'Token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret',
    }, headers=headers)
    assert res.status_code == 400
    assert 'credentials' in res.get_json()['error']['message']


def test_target_listing_filtering_and_search(test_env):
    app, _ = test_env
    client = bearer_client(app)
    headers = {'Authorization': f'Bearer {TOKEN}'}

    now = datetime.now(timezone.utc)

    # Create 3 distinct targets
    targets_data = [
        ('Alpha Org', 'organization', 'Alpha Inc', ['alpha.com']),
        ('Beta Bounty', 'bug_bounty', 'Beta Security', ['beta.org']),
        ('Gamma Client', 'client', 'Gamma LLC', ['gamma.net']),
    ]
    for name, t_type, owner, domains in targets_data:
        client.post('/api/targets', json={
            'name': name,
            'target_type': t_type,
            'owner_organization': owner,
            'scope_domains': domains,
            'valid_from': now.isoformat(),
            'valid_to': (now + timedelta(days=30)).isoformat(),
            'evidence_reference': f'Ref-{name}',
        }, headers=headers)

    # Filter by type
    res = client.get('/api/targets?type=bug_bounty', headers=headers)
    assert res.status_code == 200
    data = res.get_json()['data']
    assert len(data) == 1
    assert data[0]['name'] == 'Beta Bounty'

    # Search by domain
    res = client.get('/api/targets?search=gamma.net', headers=headers)
    assert res.status_code == 200
    data = res.get_json()['data']
    assert len(data) == 1
    assert data[0]['name'] == 'Gamma Client'

    # Metrics returned in meta
    meta = res.get_json()['meta']
    assert meta['metrics']['total'] == 3
    assert meta['metrics']['active'] == 3


def test_target_update_and_audit_trail(test_env):
    app, _ = test_env
    client = session_client(app)
    headers = {'X-CSRF-Token': CSRF_TOKEN}

    now = datetime.now(timezone.utc)
    created = client.post('/api/targets', json={
        'name': 'Initial Target',
        'target_type': 'organization',
        'owner_organization': 'IT Dept',
        'scope_domains': ['example.com'],
        'valid_from': now.isoformat(),
        'valid_to': (now + timedelta(days=10)).isoformat(),
        'evidence_reference': 'Initial approval letter',
    }, headers=headers).get_json()['data']

    target_id = created['id']

    # Update scope and rate limit
    res = client.put(f'/api/targets/{target_id}', json={
        'name': 'Updated Target Name',
        'rate_limit_rps': 25,
        'explicit_subdomains': ['sub.example.com'],
    }, headers=headers)
    assert res.status_code == 200
    updated = res.get_json()['data']
    assert updated['name'] == 'Updated Target Name'
    assert updated['rate_limit_rps'] == 25
    assert updated['explicit_subdomains'] == ['sub.example.com']
    assert updated['updated_by'] == 'security_admin'

    # Verify audit events
    audit_events = updated['audit_events']
    assert len(audit_events) == 2
    event_types = [e['event_type'] for e in audit_events]
    assert 'created' in event_types
    assert 'updated' in event_types


def test_target_deactivation_and_revocation(test_env):
    app, _ = test_env
    client = session_client(app)
    headers = {'X-CSRF-Token': CSRF_TOKEN}

    now = datetime.now(timezone.utc)
    target = client.post('/api/targets', json={
        'name': 'To Be Revoked',
        'target_type': 'client',
        'owner_organization': 'Partner Corp',
        'scope_domains': ['example.com'],
        'valid_from': now.isoformat(),
        'valid_to': (now + timedelta(days=10)).isoformat(),
        'evidence_reference': 'Engagement agreement #12',
    }, headers=headers).get_json()['data']

    target_id = target['id']

    # Deactivate
    res = client.post(f'/api/targets/{target_id}/deactivate', json={
        'status': 'revoked',
        'reason': 'Client cancelled assessment scope.',
    }, headers=headers)
    assert res.status_code == 200
    revoked = res.get_json()['data']
    assert revoked['status'] == 'revoked'
    assert revoked['effective_status'] == 'revoked'
    assert revoked['audit_events'][0]['event_type'] == 'revoked'


def test_expired_authorization_status_calculation(test_env):
    app, _ = test_env
    client = session_client(app)
    headers = {'X-CSRF-Token': CSRF_TOKEN}

    now = datetime.now(timezone.utc)
    past_start = now - timedelta(days=60)
    past_end = now - timedelta(days=1)

    target = client.post('/api/targets', json={
        'name': 'Past Assessment',
        'target_type': 'organization',
        'owner_organization': 'Old Department',
        'scope_domains': ['example.com'],
        'valid_from': past_start.isoformat(),
        'valid_to': past_end.isoformat(),
        'evidence_reference': 'Expired policy #2025',
    }, headers=headers).get_json()['data']

    # The target status stored is active, but effective_status is expired
    assert target['effective_status'] == 'expired'

    # Target retrieval reflects effective_status
    res = client.get(f"/api/targets/{target['id']}")
    assert res.status_code == 200
    assert res.get_json()['data']['effective_status'] == 'expired'


def test_target_database_persistence_and_relationships(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token=TOKEN)
    app1 = create_app(settings)

    now = datetime.now(timezone.utc)
    with Session(app1.extensions['database']) as session:
        target = AuthorizedTarget(
            name='Persistent Lab',
            target_type='lab',
            owner_organization='Security Academy',
            scope_domains=['127.0.0.1'],
            explicit_subdomains=[],
            excluded_scope=[],
            permitted_methods=['port_scan'],
            prohibited_methods=['dos'],
            valid_from=now,
            valid_to=now + timedelta(days=365),
            evidence_reference='Lab Handbook 2026',
            status='active',
            created_by='tester',
            updated_by='tester',
        )
        session.add(target)
        session.commit()
        target_id = target.id

    app1.extensions['database'].dispose()

    # Reopen database in a new app instance
    app2 = create_app(settings)
    with Session(app2.extensions['database']) as session:
        t = session.get(AuthorizedTarget, target_id)
        assert t is not None
        assert t.name == 'Persistent Lab'
        assert t.scope_domains == ['127.0.0.1']
    app2.extensions['database'].dispose()


def test_check_scope_endpoint(test_env):
    app, _ = test_env
    client = session_client(app)
    headers = {'X-CSRF-Token': CSRF_TOKEN}

    # Missing host parameter returns 400
    res = client.get('/api/targets/check', headers=headers)
    assert res.status_code == 400

    # No targets registered returns 200 with covered: false
    res = client.get('/api/targets/check?host=127.0.0.1', headers=headers)
    assert res.status_code == 200
    data = res.get_json()['data']
    assert data['covered'] is False
    assert 'No authorized' in data['reason']

    # Register an active target
    now = datetime.now(timezone.utc)
    res_post = client.post('/api/targets', headers=headers, json={
        'name': 'API Check Target',
        'target_type': 'organization',
        'owner_organization': 'Acme Corp',
        'scope_domains': ['example.com'],
        'explicit_subdomains': ['api.example.com'],
        'prohibited_methods': ['active_crawl'],
        'valid_from': now.isoformat(),
        'valid_to': (now + timedelta(days=30)).isoformat(),
        'evidence_reference': 'SEC-999',
    })
    assert res_post.status_code == 201, res_post.get_json()

    # Covered host
    res = client.get('/api/targets/check?host=api.example.com', headers=headers)
    assert res.status_code == 200
    data = res.get_json()['data']
    assert data['covered'] is True
    assert data['match_source'] == 'explicit_subdomains'
    assert data['matched_target']['name'] == 'API Check Target'

    # Uncovered host returns 403
    res = client.get('/api/targets/check?host=evil.com', headers=headers)
    assert res.status_code == 403
    err = res.get_json()['error']
    assert err['code'] == 'scope_not_authorized'


# ---------------------------------------------------------------------------
# effective_status() new Phase-2 cases
# ---------------------------------------------------------------------------

def test_effective_status_not_yet_valid(test_env):
    """A target whose valid_from is in the future must report effective_status='not_yet_valid'."""
    app, _ = test_env
    client = session_client(app)
    headers = {'X-CSRF-Token': CSRF_TOKEN}

    now = datetime.now(timezone.utc)
    res = client.post('/api/targets', json={
        'name': 'Future Target',
        'target_type': 'organization',
        'owner_organization': 'Acme Corp',
        'scope_domains': ['example.com'],
        'valid_from': (now + timedelta(days=2)).isoformat(),
        'valid_to': (now + timedelta(days=30)).isoformat(),
        'evidence_reference': 'Pre-authorized scope #F1',
    }, headers=headers)
    assert res.status_code == 201, res.get_json()
    data = res.get_json()['data']
    assert data['effective_status'] == 'not_yet_valid', (
        f"Expected 'not_yet_valid', got '{data['effective_status']}'"
    )

    # Re-fetch via GET and confirm effective_status persists
    target_id = data['id']
    res2 = client.get(f'/api/targets/{target_id}')
    assert res2.status_code == 200
    assert res2.get_json()['data']['effective_status'] == 'not_yet_valid'


def test_effective_status_invalid_dates_via_direct_orm(test_env):
    """effective_status() must return 'invalid_dates' (fail-closed) when dates are None.

    The SQLite schema enforces NOT NULL on valid_from/valid_to, so we cannot persist
    a null-date record via the ORM.  We therefore test the function directly with a
    SimpleNamespace mock that simulates the edge-case (e.g. data loaded from a
    legacy schema, an external migration, or a future schema change).
    """
    import types
    from backend.services.target_authorization import effective_status

    # Simulate a record that somehow has None dates (fail-closed assertion)
    mock_target = types.SimpleNamespace(
        status='active',
        valid_from=None,
        valid_to=None,
    )
    result = effective_status(mock_target)
    assert result == 'invalid_dates', (
        f"Expected 'invalid_dates' for None dates, got '{result}'"
    )

    # Also verify that a parseable-but-garbage string triggers the except branch
    mock_target_bad_str = types.SimpleNamespace(
        status='active',
        valid_from='not-a-datetime',
        valid_to='also-not-a-datetime',
    )
    result2 = effective_status(mock_target_bad_str)
    assert result2 == 'invalid_dates', (
        f"Expected 'invalid_dates' for unparseable date strings, got '{result2}'"
    )
