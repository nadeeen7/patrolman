import json
import threading
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash

from backend import admin
from backend.app import create_app
from backend.auth import (
    initialize_admin,
    normalize_username,
    recover_admin_password,
    utcnow,
    validate_password,
)
from backend.config import Settings
from backend.models import AdminAccount, AdminSession, AuditEvent, LoginThrottle


API_TOKEN = 'auth-test-api-token-' + 'x' * 32
USERNAME = 'local-admin'
PASSWORD = 'synthetic-password-123'


@pytest.fixture
def app(tmp_path):
    application = create_app(Settings(tmp_path, API_TOKEN))
    application.config['TESTING'] = True
    yield application
    application.extensions['database'].dispose()


def initialize(app, username=USERNAME, password=PASSWORD):
    return initialize_admin(app.extensions['database'], username, password, password)


def csrf_headers(client, **overrides):
    """Fetch the pre-session token the browser would obtain before login."""
    token = client.get('/api/auth/csrf').json['data']['csrf_token']
    headers = {'X-CSRF-Token': token}
    headers.update(overrides)
    return headers


def sign_in(client, username=USERNAME, password=PASSWORD, **kwargs):
    kwargs['headers'] = csrf_headers(client, **(kwargs.pop('headers', None) or {}))
    return client.post('/api/auth/login', json={'username': username, 'password': password}, **kwargs)


def register(client, username, password=PASSWORD, **kwargs):
    kwargs['headers'] = csrf_headers(client, **(kwargs.pop('headers', None) or {}))
    return client.post(
        '/api/auth/signup',
        json={'username': username, 'password': password, 'confirm_password': password},
        **kwargs,
    )


def csrf_of(response):
    return response.json['data']['csrf_token']


def session_cookie(response):
    return next(
        value for value in response.headers.getlist('Set-Cookie')
        if value.startswith('patrolman_session=')
    )


# --- password policy -------------------------------------------------------

def test_password_policy_accepts_eight_and_rejects_shorter():
    validate_password('a' * 8, 'a' * 8)
    with pytest.raises(ValueError, match='between 8 and 1024'):
        validate_password('a' * 7, 'a' * 7)
    with pytest.raises(ValueError, match='between 8 and 1024'):
        validate_password('a' * 1025, 'a' * 1025)
    with pytest.raises(ValueError, match='do not match'):
        validate_password('a' * 8, 'b' * 8)


def test_signup_accepts_eight_character_password_and_hashes_it(app):
    client = app.test_client()
    response = register(client, 'eight-pass', 'abcdefgh')
    assert response.status_code == 200, response.json
    with Session(app.extensions['database']) as session:
        account = session.scalar(select(AdminAccount).where(AdminAccount.username == 'eight-pass'))
        assert account is not None
        assert account.password_hash != 'abcdefgh'
        assert check_password_hash(account.password_hash, 'abcdefgh')
    assert sign_in(app.test_client(), 'eight-pass', 'abcdefgh').status_code == 200


def test_signup_rejects_seven_character_password_when_frontend_is_bypassed(app):
    client = app.test_client()
    short = register(client, 'short-pass', 'abcdefg')
    assert short.status_code == 400
    assert short.json['error']['code'] == 'invalid_input'
    assert 'between 8 and 1024' in short.json['error']['message']
    with Session(app.extensions['database']) as session:
        assert session.scalar(select(AdminAccount.id).limit(1)) is None


# --- multiple administrators ----------------------------------------------

def test_multiple_distinct_administrators_can_register_and_sign_in(app):
    first = app.test_client()
    second = app.test_client()
    assert register(first, 'admin-one').status_code == 200
    assert register(second, 'admin-two', 'second-password-123').status_code == 200

    with Session(app.extensions['database']) as session:
        accounts = session.scalars(select(AdminAccount).order_by(AdminAccount.username)).all()
        assert [account.username for account in accounts] == ['admin-one', 'admin-two']

    assert sign_in(app.test_client(), 'admin-one').status_code == 200
    assert sign_in(app.test_client(), 'admin-two', 'second-password-123').status_code == 200
    assert app.test_client().get('/api/auth/status').json['data'] == {
        'administrator_initialized': True,
        'registration_enabled': True,
    }


def test_duplicate_username_is_rejected_case_insensitively(app):
    client = app.test_client()
    assert register(client, 'Admin-One').status_code == 200
    duplicate = register(app.test_client(), 'admin-one', 'another-password-123')
    assert duplicate.status_code == 409
    assert duplicate.json['error']['code'] == 'registration_failed'
    assert 'Choose a different username' in duplicate.json['error']['message']
    with Session(app.extensions['database']) as session:
        accounts = session.scalars(select(AdminAccount)).all()
        assert len(accounts) == 1
        assert accounts[0].username == 'admin-one'


def test_concurrent_duplicate_registration_creates_one_account(app):
    barrier = threading.Barrier(2)
    results = []

    def attempt():
        client = app.test_client()
        barrier.wait(timeout=10)
        response = register(client, 'race-admin', 'race-password-123')
        results.append(response.status_code)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(results) == [200, 409], results
    with Session(app.extensions['database']) as session:
        accounts = session.scalars(
            select(AdminAccount).where(AdminAccount.username == 'race-admin')
        ).all()
        assert len(accounts) == 1


def test_registration_disabled_configuration_blocks_signup(tmp_path):
    application = create_app(Settings(tmp_path, API_TOKEN, registration_enabled=False))
    application.config['TESTING'] = True
    try:
        client = application.test_client()
        response = register(client, 'blocked-admin')
        assert response.status_code == 403
        assert response.json['error']['code'] == 'registration_disabled'
        assert client.get('/api/auth/status').json['data']['registration_enabled'] is False
        with Session(application.extensions['database']) as session:
            assert session.scalar(select(AdminAccount.id).limit(1)) is None
    finally:
        application.extensions['database'].dispose()


def test_signup_rejects_extra_fields_and_roles(app):
    client = app.test_client()
    response = client.post('/api/auth/signup', json={
        'username': 'role-admin',
        'password': PASSWORD,
        'confirm_password': PASSWORD,
        'role': 'superuser',
    }, headers=csrf_headers(client))
    assert response.status_code == 400
    with Session(app.extensions['database']) as session:
        assert session.scalar(select(AdminAccount.id).limit(1)) is None


# --- origin / CSRF ---------------------------------------------------------

def test_login_and_signup_reject_missing_or_invalid_presession_csrf(app):
    initialize(app)
    client = app.test_client()
    credentials = {'username': USERNAME, 'password': PASSWORD}

    missing = client.post('/api/auth/login', json=credentials)
    assert missing.status_code == 403
    assert missing.json['error']['code'] == 'csrf_failed'

    # Cookie present but no header: rejected.
    token = client.get('/api/auth/csrf').json['data']['csrf_token']
    assert client.post('/api/auth/login', json=credentials).status_code == 403
    # Header present but cookie missing: rejected (not a plain double-submit bypass).
    client.delete_cookie('patrolman_csrf')
    assert client.post(
        '/api/auth/login', json=credentials, headers={'X-CSRF-Token': token},
    ).status_code == 403
    # Mismatched header and cookie: rejected.
    token = client.get('/api/auth/csrf').json['data']['csrf_token']
    assert client.post(
        '/api/auth/login', json=credentials, headers={'X-CSRF-Token': token + 'x'},
    ).status_code == 403
    # Matching pair: accepted.
    assert client.post(
        '/api/auth/login', json=credentials, headers={'X-CSRF-Token': token},
    ).status_code == 200

    signup_client = app.test_client()
    payload = {'username': 'csrf-admin', 'password': PASSWORD, 'confirm_password': PASSWORD}
    assert signup_client.post('/api/auth/signup', json=payload).status_code == 403
    token = signup_client.get('/api/auth/csrf').json['data']['csrf_token']
    assert signup_client.post(
        '/api/auth/signup', json=payload, headers={'X-CSRF-Token': token},
    ).status_code == 200


def test_presession_csrf_cookie_is_http_only_strict_and_rotated_after_login(app):
    initialize(app)
    client = app.test_client()
    bootstrap = client.get('/api/auth/csrf')
    assert bootstrap.status_code == 200
    cookie = bootstrap.headers['Set-Cookie']
    assert cookie.startswith('patrolman_csrf=')
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    assert 'Secure' not in cookie
    assert bootstrap.headers['Cache-Control'] == 'no-store'
    presession = bootstrap.json['data']['csrf_token']

    login = sign_in(client)
    assert login.status_code == 200
    assert csrf_of(login) != presession
    # The pre-session value is discarded once a session exists.
    headers = '; '.join(login.headers.getlist('Set-Cookie'))
    assert 'patrolman_csrf=;' in headers


def test_https_presession_csrf_cookie_is_secure(app):
    response = app.test_client().get('/api/auth/csrf', base_url='https://localhost')
    cookie = response.headers['Set-Cookie']
    assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=Strict' in cookie

def test_signup_and_login_validate_origin_exactly(tmp_path):
    application = create_app(Settings(
        tmp_path,
        API_TOKEN,
        trusted_origins=('http://127.0.0.1:5173',),
    ))
    application.config['TESTING'] = True
    try:
        client = application.test_client()
        rejected = register(client, 'origin-admin', headers={'Origin': 'https://attacker.example'})
        assert rejected.status_code == 403
        assert rejected.json['error']['code'] == 'csrf_failed'
        assert register(client, 'origin-admin', headers={'Origin': 'http://127.0.0.1:5173'}).status_code == 200

        # Same-origin (host as seen by the backend) is accepted.
        assert sign_in(application.test_client(), 'origin-admin',
                       headers={'Origin': 'http://localhost'}).status_code == 200
        # The explicitly trusted development origin is accepted.
        assert sign_in(application.test_client(), 'origin-admin',
                       headers={'Origin': 'http://127.0.0.1:5173'}).status_code == 200
        # Referer is validated when Origin is absent.
        assert sign_in(application.test_client(), 'origin-admin',
                       headers={'Referer': 'https://attacker.example/page'}).status_code == 403
        assert sign_in(application.test_client(), 'origin-admin',
                       headers={'Referer': 'http://localhost/login'}).status_code == 200
    finally:
        application.extensions['database'].dispose()


def test_proxied_dev_request_keeps_frontend_host_and_origin(app):
    """Regression for the 403: the Vite proxy must not rewrite Host.

    With ``changeOrigin: false`` the backend sees the browser's Host, so the
    computed origin equals the browser Origin and the request is accepted.
    """
    initialize(app)
    client = app.test_client()
    host = {'Host': '127.0.0.1:5173'}
    token = client.get('/api/auth/csrf', headers=host).json['data']['csrf_token']
    response = client.post(
        '/api/auth/login',
        json={'username': USERNAME, 'password': PASSWORD},
        headers={**host, 'Origin': 'http://127.0.0.1:5173', 'X-CSRF-Token': token},
    )
    assert response.status_code == 200, response.json


def test_untrusted_origin_is_rejected_by_default(app):
    initialize(app)
    response = sign_in(app.test_client(), headers={'Origin': 'http://127.0.0.1:5173'})
    assert response.status_code == 403
    assert response.json['error']['code'] == 'csrf_failed'


def test_csrf_token_required_for_state_changes_and_logout_revokes_session(app):
    initialize(app)
    client = app.test_client()
    login = sign_in(client)
    assert login.status_code == 200
    csrf = csrf_of(login)
    assert len(csrf) >= 32

    assert client.post('/api/auth/logout').status_code == 403
    assert client.post('/api/auth/logout', headers={'X-CSRF-Token': 'wrong-token'}).status_code == 403

    headers = {'X-CSRF-Token': csrf, 'Origin': 'http://localhost'}
    assert client.post('/api/auth/logout', headers=headers).status_code == 204
    assert client.get('/api/auth/session').status_code == 401
    assert client.get('/api/dashboard').status_code == 401
    with Session(app.extensions['database']) as session:
        assert session.scalar(select(AdminSession.token_hash).limit(1)) is None


def test_cross_origin_state_change_is_rejected_without_destroying_session(app):
    initialize(app)
    client = app.test_client()
    login = sign_in(client)
    response = client.post('/api/auth/logout', headers={
        'X-CSRF-Token': csrf_of(login),
        'Origin': 'https://attacker.example',
    })
    assert response.status_code == 403
    assert client.get('/api/auth/session').status_code == 200


# --- login / brute force ---------------------------------------------------

def test_login_failures_are_generic_rate_limited_and_do_not_echo_secrets(app):
    initialize(app)
    client = app.test_client()
    wrong = 'incorrect-password'
    first = sign_in(client, password=wrong)
    unknown = sign_in(client, username='other-admin', password=wrong)
    assert first.status_code == unknown.status_code == 401
    assert first.json == unknown.json
    assert wrong not in json.dumps(first.json)
    for _ in range(3):
        response = sign_in(client, password=wrong)
    assert response.status_code == 429
    assert sign_in(client).status_code == 429


def test_registration_rate_limit_blocks_repeated_invalid_attempts(app):
    client = app.test_client()
    responses = [register(client, f'bad-{index}', 'short') for index in range(5)]
    assert [response.status_code for response in responses] == [400, 400, 400, 400, 429]
    assert register(client, 'valid-later', 'valid-password-123').status_code == 429
    with Session(app.extensions['database']) as session:
        assert session.scalar(select(AdminAccount.id).limit(1)) is None
        assert session.scalar(select(LoginThrottle.client_key).limit(1)) is not None


# --- sessions --------------------------------------------------------------

def test_session_has_http_only_strict_cookie_and_rotates_on_login(app):
    initialize(app)
    client = app.test_client()
    first = sign_in(client)
    assert first.status_code == 200
    cookie = session_cookie(first)
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    assert 'Secure' not in cookie  # plain-HTTP test request
    assert PASSWORD not in cookie
    assert API_TOKEN not in cookie
    first_csrf = csrf_of(first)

    second = sign_in(app.test_client())
    assert csrf_of(second) != first_csrf
    with Session(app.extensions['database']) as session:
        assert len(session.scalars(select(AdminSession)).all()) == 2
        stored = session.scalars(select(AdminSession)).all()[0]
        assert stored.token_hash not in cookie
        assert PASSWORD not in stored.token_hash


def test_idle_and_absolute_session_expiration(app):
    initialize(app)
    engine = app.extensions['database']

    idle_client = app.test_client()
    assert sign_in(idle_client).status_code == 200
    with Session(engine) as session:
        row = session.scalar(select(AdminSession))
        row.last_seen_at = utcnow() - timedelta(minutes=31)
        session.commit()
    assert idle_client.get('/api/auth/session').status_code == 401
    with Session(engine) as session:
        assert session.scalar(select(AdminSession.token_hash).limit(1)) is None

    expired_client = app.test_client()
    assert sign_in(expired_client).status_code == 200
    with Session(engine) as session:
        row = session.scalar(select(AdminSession))
        row.expires_at = utcnow() - timedelta(seconds=1)
        session.commit()
    assert expired_client.get('/api/auth/session').status_code == 401


def test_https_requests_set_secure_cookie_and_hsts(app):
    initialize(app)
    client = app.test_client()
    token = client.get('/api/auth/csrf', base_url='https://localhost').json['data']['csrf_token']
    response = client.post(
        '/api/auth/login',
        json={'username': USERNAME, 'password': PASSWORD},
        headers={'X-CSRF-Token': token},
        base_url='https://localhost',
    )
    assert response.status_code == 200, response.json
    assert 'Secure' in session_cookie(response)
    assert 'Strict-Transport-Security' in response.headers

    # Deleting a Secure cookie must itself carry Secure, otherwise an HTTPS
    # response cannot overwrite the cookie that was set over HTTPS.
    logout = client.post(
        '/api/auth/logout',
        headers={'X-CSRF-Token': csrf_of(response)},
        base_url='https://localhost',
    )
    assert logout.status_code == 204
    deletion = next(
        value for value in logout.headers.getlist('Set-Cookie')
        if value.startswith('patrolman_session=')
    )
    assert 'Secure' in deletion and 'Max-Age=0' in deletion


# --- headers / errors / bearer --------------------------------------------

def test_security_headers_on_http_responses(app):
    response = app.test_client().get('/api/health')
    assert response.status_code == 200
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Referrer-Policy'] == 'no-referrer'
    assert response.headers['X-Frame-Options'] == 'DENY'
    policy = response.headers['Content-Security-Policy']
    assert "default-src 'self'" in policy
    assert "script-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "object-src 'none'" in policy
    assert 'unsafe-eval' not in policy
    assert 'Strict-Transport-Security' not in response.headers


def test_authentication_required_and_bearer_token_compatibility(app):
    client = app.test_client()
    assert client.get('/api/dashboard').status_code == 401
    assert client.post('/api/scans', json={}).status_code == 401
    assert client.get('/api/health').status_code == 200
    assert client.get('/api/dashboard', headers={'Authorization': f'Bearer {API_TOKEN}'}).status_code == 200
    # Bearer clients are not subject to the cookie CSRF token.
    assert client.post('/api/scans', json={}, headers={'Authorization': f'Bearer {API_TOKEN}'}).status_code != 401


def test_authenticated_administrator_can_read_protected_data(app):
    initialize(app)
    client = app.test_client()
    assert sign_in(client).status_code == 200
    assert client.get('/api/dashboard').status_code == 200
    assert client.get('/api/auth/session').json['data']['username'] == USERNAME


def test_responses_and_audit_records_contain_no_secrets(app, caplog):
    caplog.set_level('INFO')
    initialize(app)
    client = app.test_client()
    login = sign_in(client)
    assert login.status_code == 200
    assert PASSWORD not in json.dumps(login.json)
    with Session(app.extensions['database']) as session:
        account = session.scalar(select(AdminAccount))
        assert account.password_hash not in json.dumps(login.json)
        events = session.scalars(select(AuditEvent)).all()
        stored_text = json.dumps([{'actor': event.actor, 'details': event.details} for event in events])
        assert PASSWORD not in stored_text
        assert csrf_of(login) not in stored_text
    assert PASSWORD not in caplog.text


# --- username handling / CLI ----------------------------------------------

def test_username_normalization_and_creation_limits(app):
    assert normalize_username('  Local-Admin  ') == 'local-admin'
    for invalid in ('ab', 'has space', '-leading', 'x' * 65, None):
        with pytest.raises(ValueError):
            normalize_username(invalid)


def test_admin_cli_setup_and_recovery_use_existing_database(tmp_path, monkeypatch, capsys):
    data_dir = tmp_path / 'existing-data'
    data_dir.mkdir()
    (data_dir / 'assessment.sqlite3').touch()
    monkeypatch.setenv('AVA_DATA_DIR', str(data_dir))
    short_password = 'abcdefgh'
    answers = iter([USERNAME, USERNAME])
    passwords = iter([short_password, short_password])
    monkeypatch.setattr('builtins.input', lambda _prompt: next(answers))
    monkeypatch.setattr(admin.getpass, 'getpass', lambda _prompt: next(passwords))
    assert admin.main(['setup']) == 0
    assert short_password not in capsys.readouterr().out
    assert admin.main(['setup']) == 1
    assert 'already exists' in capsys.readouterr().err

    new_password = 'recovered-password-789'
    answers = iter([USERNAME])
    passwords = iter([new_password, new_password])
    monkeypatch.setattr('builtins.input', lambda _prompt: next(answers))
    monkeypatch.setattr(admin.getpass, 'getpass', lambda _prompt: next(passwords))
    assert admin.main(['recover']) == 0
    assert new_password not in capsys.readouterr().out


def test_password_recovery_revokes_only_that_accounts_sessions(app):
    initialize(app)
    other = app.test_client()
    assert register(other, 'second-admin', 'second-password-123').status_code == 200
    first = app.test_client()
    assert sign_in(first).status_code == 200
    assert other.get('/api/auth/session').status_code == 200

    recover_admin_password(app.extensions['database'], USERNAME, 'new-password-456', 'new-password-456')
    assert first.get('/api/auth/session').status_code == 401
    assert other.get('/api/auth/session').status_code == 200
