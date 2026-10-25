import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, ScopeImportSnapshot
from backend.services.scope_import import parse_offline_scope
from backend.services.scope_validator import ScopeAuthorizationError, recheck_authorized_target

TOKEN = 'phase5-scope-import-test-' + 'x' * 32
HEADERS = {'Authorization': f'Bearer {TOKEN}'}
FIXTURE = Path(__file__).parent / 'fixtures' / 'offline_bug_bounty_scope.json'


def _payload():
    return json.loads(FIXTURE.read_text(encoding='utf-8'))


def _app(tmp_path):
    app = create_app(Settings(
        data_dir=tmp_path,
        api_token=TOKEN,
        allowed_targets=('127.0.0.1',),
        require_authorized_target=True,
    ))
    app.config['TESTING'] = True
    return app


def _target(client):
    now = datetime.now(timezone.utc)
    response = client.post('/api/targets', headers=HEADERS, json={
        'name': 'Synthetic bounty',
        'target_type': 'bug_bounty',
        'owner_organization': 'Synthetic program',
        'scope_domains': ['existing.example.test'],
        'permitted_methods': ['web_service_discovery'],
        'prohibited_methods': ['dos', 'exploit'],
        'valid_from': now.isoformat(),
        'valid_to': (now + timedelta(days=45)).isoformat(),
        'evidence_reference': 'Synthetic fixture authorization',
    })
    assert response.status_code == 201
    return response.json['data']


class TestOfflineScopeParser:
    def test_parses_deterministically_and_normalizes_networks(self):
        payload = _payload()
        parsed = parse_offline_scope(payload)
        assert parsed['import_status'] == 'valid'
        assert parsed['digest'] == parse_offline_scope(payload)['digest']
        assert {'asset_type': 'cidr', 'value': '192.0.2.0/24', 'scope': 'included'} in parsed['included_assets']
        assert parsed['excluded_assets'][0]['scope'] == 'excluded'

    def test_records_malformed_entries_and_rejects_empty_scope(self):
        payload = _payload()
        payload['fixture']['assets'].extend([
            {'asset_type': 'cidr', 'value': '192.0.2.4/24', 'scope': 'included'},
            {'asset_type': 'wildcard', 'value': '*.example.test', 'scope': 'included'},
        ])
        parsed = parse_offline_scope(payload)
        assert parsed['import_status'] == 'invalid'
        assert [entry['index'] for entry in parsed['invalid_entries']] == [5, 6]

        payload['fixture']['assets'] = [
            {'asset_type': 'domain', 'value': 'outside.example.test', 'scope': 'excluded'}
        ]
        assert any(entry['index'] == 'assets' for entry in parse_offline_scope(payload)['invalid_entries'])

    @pytest.mark.parametrize('source_url', [
        'https://user:secret@program.example.test/scope',
        'https://program.example.test/scope?token=secret',
        'file:///scope.json',
    ])
    def test_rejects_credentialed_or_non_http_source_url(self, source_url):
        payload = _payload()
        payload['source_url'] = source_url
        with pytest.raises(ValueError):
            parse_offline_scope(payload)


def test_preview_requires_explicit_approval_and_audits_diff(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    target = _target(client)
    payload = _payload()

    response = client.post(
        f"/api/targets/{target['id']}/scope-imports/preview",
        headers=HEADERS,
        json=payload,
    )
    assert response.status_code == 201
    snapshot = response.json['data']
    assert snapshot['approval_status'] == 'pending_review'
    assert snapshot['scope_diff']['newly_included']
    unchanged = client.get(f"/api/targets/{target['id']}", headers=HEADERS).json['data']
    assert unchanged['scope_domains'] == ['existing.example.test']

    approved = client.post(
        f"/api/targets/{target['id']}/scope-imports/{snapshot['id']}/approve",
        headers=HEADERS,
        json={},
    )
    assert approved.status_code == 200
    assert approved.json['data']['snapshot']['approval_status'] == 'approved'
    current = approved.json['data']['target']
    assert '192.0.2.0/24' in current['scope_domains']
    assert '/admin' in current['excluded_scope']
    assert current['permitted_methods'] == ['web_service_discovery']
    with Session(app.extensions['database']) as session:
        stored = session.get(ScopeImportSnapshot, snapshot['id'])
        assert stored.approved_by == 'api_operator'
        assert stored.approved_target_state['scope_domains'] == current['scope_domains']


def test_invalid_and_pending_imports_cannot_be_approved(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    target = _target(client)
    payload = _payload()
    payload['fixture']['assets'].append({
        'asset_type': 'cidr',
        'value': '198.51.100.8/24',
        'scope': 'included',
    })
    response = client.post(
        f"/api/targets/{target['id']}/scope-imports/preview",
        headers=HEADERS,
        json=payload,
    )
    snapshot = response.json['data']
    assert snapshot['import_status'] == 'invalid'
    rejected = client.post(
        f"/api/targets/{target['id']}/scope-imports/{snapshot['id']}/approve",
        headers=HEADERS,
        json={},
    )
    assert rejected.status_code == 400


def test_latest_pending_or_stale_import_fails_closed(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    target = _target(client)
    payload = _payload()
    response = client.post(
        f"/api/targets/{target['id']}/scope-imports/preview",
        headers=HEADERS,
        json=payload,
    )
    assert response.status_code == 201
    with Session(app.extensions['database']) as session:
        imported = session.get(ScopeImportSnapshot, response.json['data']['id'])
        with pytest.raises(ScopeAuthorizationError, match='pending review'):
            recheck_authorized_target(
                target['id'], session, 'existing.example.test', ['httpx']
            )

    approved = client.post(
        f"/api/targets/{target['id']}/scope-imports/{response.json['data']['id']}/approve",
        headers=HEADERS,
        json={},
    )
    assert approved.status_code == 200
    with Session(app.extensions['database']) as session:
        imported = session.get(ScopeImportSnapshot, response.json['data']['id'])
        imported.last_successful_validation_at = datetime.now(timezone.utc) - timedelta(days=31)
        session.commit()
    with Session(app.extensions['database']) as session:
        with pytest.raises(ScopeAuthorizationError, match='stale'):
            recheck_authorized_target(
                target['id'], session, '192.0.2.12', ['httpx']
            )


def test_audit_failure_prevents_target_creation(tmp_path, monkeypatch):
    app = _app(tmp_path)

    def fail_audit(*_args, **_kwargs):
        raise RuntimeError('synthetic audit failure')

    monkeypatch.setattr('backend.target_routes.log_event', fail_audit)
    now = datetime.now(timezone.utc)
    with pytest.raises(RuntimeError, match='synthetic audit failure'):
        app.test_client().post('/api/targets', headers=HEADERS, json={
            'name': 'Must not persist',
            'target_type': 'bug_bounty',
            'owner_organization': 'Synthetic program',
            'scope_domains': ['example.test'],
            'valid_from': now.isoformat(),
            'valid_to': (now + timedelta(days=1)).isoformat(),
            'evidence_reference': 'Synthetic authorization',
        })
    with Session(app.extensions['database']) as session:
        assert session.scalar(select(AuthorizedTarget).where(
            AuthorizedTarget.name == 'Must not persist'
        )) is None


def test_approve_scope_import_rejected_when_target_deactivated(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    target = _target(client)
    payload = _payload()

    # Create preview snapshot (status: pending_review)
    preview = client.post(
        f"/api/targets/{target['id']}/scope-imports/preview",
        headers=HEADERS,
        json=payload,
    )
    assert preview.status_code == 201
    snapshot_id = preview.json['data']['id']

    # Deactivate the target
    deact = client.post(
        f"/api/targets/{target['id']}/deactivate",
        headers=HEADERS,
        json={'status': 'inactive', 'reason': 'Testing deactivation guard'},
    )
    assert deact.status_code == 200
    assert deact.json['data']['status'] == 'inactive'

    # Attempt to approve the pending snapshot -> must be rejected with 409
    approve_resp = client.post(
        f"/api/targets/{target['id']}/scope-imports/{snapshot_id}/approve",
        headers=HEADERS,
        json={},
    )
    assert approve_resp.status_code == 409
    assert 'Target authorization must be active' in approve_resp.json['error']['message']


def test_reject_scope_import_route_and_authorization(tmp_path):
    app = _app(tmp_path)
    client = app.test_client()
    target = _target(client)
    payload = _payload()

    # Create preview snapshot
    preview = client.post(
        f"/api/targets/{target['id']}/scope-imports/preview",
        headers=HEADERS,
        json=payload,
    )
    assert preview.status_code == 201
    snapshot_id = preview.json['data']['id']
    assert preview.json['data']['approval_status'] == 'pending_review'

    # Unauthenticated reject -> 401
    unauth = client.post(f"/api/targets/{target['id']}/scope-imports/{snapshot_id}/reject", json={})
    assert unauth.status_code == 401

    # Authenticated reject -> 200
    reject_resp = client.post(
        f"/api/targets/{target['id']}/scope-imports/{snapshot_id}/reject",
        headers=HEADERS,
        json={},
    )
    assert reject_resp.status_code == 200
    data = reject_resp.json['data']
    assert data['id'] == snapshot_id
    assert data['approval_status'] == 'rejected'

    # Verify state in database and audit log
    with Session(app.extensions['database']) as session:
        snapshot = session.get(ScopeImportSnapshot, snapshot_id)
        assert snapshot.approval_status == 'rejected'
        t = session.get(AuthorizedTarget, target['id'])
        audit_types = [a.event_type for a in t.audit_events]
        assert 'scope_import_rejected' in audit_types

    # Second rejection -> 409 Conflict (no longer pending review)
    second_reject = client.post(
        f"/api/targets/{target['id']}/scope-imports/{snapshot_id}/reject",
        headers=HEADERS,
        json={},
    )
    assert second_reject.status_code == 409
    assert 'no longer pending review' in second_reject.json['error']['message']

    # Approving a rejected snapshot -> 409 Conflict
    approve_rejected = client.post(
        f"/api/targets/{target['id']}/scope-imports/{snapshot_id}/approve",
        headers=HEADERS,
        json={},
    )
    assert approve_rejected.status_code == 409

