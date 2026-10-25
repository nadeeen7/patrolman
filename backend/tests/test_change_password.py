"""Security and regression tests for Phase 9: Secure Change Password Functionality."""
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

from backend.app import create_app
from backend.config import Settings
from backend.models import AdminAccount, AdminSession, AuditEvent
from backend.auth import CSRF_COOKIE, SESSION_COOKIE, _token_hash

SESSION_TOKEN_1 = 'session-token-primary-32-chars-long'
SESSION_TOKEN_2 = 'session-token-secondary-32-char-long'
CSRF_TOKEN = 'csrf-token-secret-32-chars-long'


@pytest.fixture
def auth_app(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token='K' * 32, allowed_targets=('127.0.0.1',))
    app = create_app(settings)
    app.config['TESTING'] = True

    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)

    with Session(engine) as session:
        # Create test admin user
        session.add(AdminAccount(
            username='admin_operator',
            password_hash=generate_password_hash('OldPassword123!'),
        ))
        # Session 1 (active)
        session.add(AdminSession(
            token_hash=_token_hash(SESSION_TOKEN_1),
            username='admin_operator',
            csrf_token=CSRF_TOKEN,
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=2),
        ))
        # Session 2 (other device)
        session.add(AdminSession(
            token_hash=_token_hash(SESSION_TOKEN_2),
            username='admin_operator',
            csrf_token='other-csrf-token',
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=2),
        ))
        session.commit()

    return app, settings


def auth_client(app, token=SESSION_TOKEN_1):
    client = app.test_client()
    client.set_cookie(SESSION_COOKIE, token)
    return client


def test_successful_password_change(auth_app):
    app, _ = auth_app
    client = auth_client(app)

    res = client.post(
        '/api/auth/change-password',
        json={
            'current_password': 'OldPassword123!',
            'new_password': 'NewSecurePassword456#',
            'confirm_password': 'NewSecurePassword456#',
        },
        headers={'X-CSRF-Token': CSRF_TOKEN},
    )
    assert res.status_code == 200
    assert res.get_json()['data']['message'] == 'Password changed successfully.'

    # Verify password was updated and hashed in DB
    engine = app.extensions['database']
    with Session(engine) as session:
        account = session.scalar(select(AdminAccount).where(AdminAccount.username == 'admin_operator'))
        assert account is not None
        assert account.password_hash != 'NewSecurePassword456#'
        assert check_password_hash(account.password_hash, 'NewSecurePassword456#')

        # Primary session is preserved
        sess1 = session.get(AdminSession, _token_hash(SESSION_TOKEN_1))
        assert sess1 is not None

        # Secondary session was invalidated
        sess2 = session.get(AdminSession, _token_hash(SESSION_TOKEN_2))
        assert sess2 is None

        # Audit trail recorded without secrets
        audit_records = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == 'auth_password_changed')
        ).all()
        assert len(audit_records) == 1
        rec = audit_records[0]
        assert rec.actor == 'admin_operator'
        # Crucial: check that passwords are not in details or anywhere in the record
        assert 'OldPassword123!' not in str(rec.details)
        assert 'NewSecurePassword456#' not in str(rec.details)


def test_change_password_incorrect_current_password_rejected(auth_app):
    app, _ = auth_app
    client = auth_client(app)

    res = client.post(
        '/api/auth/change-password',
        json={
            'current_password': 'WrongCurrentPassword!',
            'new_password': 'NewSecurePassword456#',
            'confirm_password': 'NewSecurePassword456#',
        },
        headers={'X-CSRF-Token': CSRF_TOKEN},
    )
    assert res.status_code == 401
    assert 'Current password is incorrect' in res.get_json()['error']['message']


def test_change_password_mismatched_confirmation_rejected(auth_app):
    app, _ = auth_app
    client = auth_client(app)

    res = client.post(
        '/api/auth/change-password',
        json={
            'current_password': 'OldPassword123!',
            'new_password': 'NewSecurePassword456#',
            'confirm_password': 'DifferentPassword789$',
        },
        headers={'X-CSRF-Token': CSRF_TOKEN},
    )
    assert res.status_code == 400
    assert 'Passwords do not match' in res.get_json()['error']['message']


def test_change_password_policy_violation_short_password(auth_app):
    app, _ = auth_app
    client = auth_client(app)

    res = client.post(
        '/api/auth/change-password',
        json={
            'current_password': 'OldPassword123!',
            'new_password': 'short',
            'confirm_password': 'short',
        },
        headers={'X-CSRF-Token': CSRF_TOKEN},
    )
    assert res.status_code == 400
    assert 'Password must contain between' in res.get_json()['error']['message']


def test_change_password_unauthenticated_rejected(auth_app):
    app, _ = auth_app
    client = app.test_client()  # No session cookie

    res = client.post(
        '/api/auth/change-password',
        json={
            'current_password': 'OldPassword123!',
            'new_password': 'NewSecurePassword456#',
            'confirm_password': 'NewSecurePassword456#',
        },
    )
    assert res.status_code == 401


def test_change_password_foreign_user_id_rejected(auth_app):
    app, _ = auth_app
    client = auth_client(app)

    # Attempting to supply a user_id or target_username field is rejected as unsupported input
    res = client.post(
        '/api/auth/change-password',
        json={
            'current_password': 'OldPassword123!',
            'new_password': 'NewSecurePassword456#',
            'confirm_password': 'NewSecurePassword456#',
            'username': 'victim_admin',
        },
        headers={'X-CSRF-Token': CSRF_TOKEN},
    )
    assert res.status_code == 400
