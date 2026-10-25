"""Local administrator authentication with server-side sessions.

Multiple administrator accounts are supported. Registration is controlled by
``AVA_REGISTRATION_ENABLED`` (default enabled) and can be disabled for
single-administrator installations. Every state-changing cookie-authenticated
request still requires a matching CSRF token and an accepted request origin.
"""
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlsplit

from flask import Blueprint, g, jsonify, make_response, request
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

from .models import AdminAccount, AdminSession, LoginThrottle
from .services.audit_service import log_event

SESSION_COOKIE = 'patrolman_session'
CSRF_COOKIE = 'patrolman_csrf'
SESSION_LIFETIME = timedelta(hours=8)          # absolute lifetime
SESSION_IDLE = timedelta(minutes=30)            # inactivity lifetime
SESSION_TOUCH_INTERVAL = timedelta(seconds=60)  # limit idle-marker writes
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT = timedelta(minutes=15)
REGISTER_WINDOW = timedelta(minutes=15)
REGISTER_MAX_ATTEMPTS = 5
REGISTER_LOCKOUT = timedelta(minutes=15)
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 1024
USERNAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]{2,63}$')
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def create_auth_tables(engine):
    """Create only additive auth tables/columns; never rewrite assessment data."""
    with engine.begin() as connection:
        for model in (AdminAccount, AdminSession, LoginThrottle):
            model.__table__.create(connection, checkfirst=True)
        columns = {row[1] for row in connection.execute(text('PRAGMA table_info(admin_sessions)'))}
        if 'last_seen_at' not in columns:
            connection.execute(text('ALTER TABLE admin_sessions ADD COLUMN last_seen_at DATETIME'))


def normalize_username(value):
    if not isinstance(value, str):
        raise ValueError('Username must contain 3 to 64 letters, digits, dots, underscores or hyphens.')
    username = value.strip().lower()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError('Username must contain 3 to 64 letters, digits, dots, underscores or hyphens.')
    return username


def validate_password(password, confirmation=None):
    if (not isinstance(password, str)
            or len(password) < PASSWORD_MIN_LENGTH
            or len(password) > PASSWORD_MAX_LENGTH):
        raise ValueError(
            'Password must contain between '
            f'{PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters.'
        )
    if confirmation is not None and not hmac.compare_digest(password, confirmation):
        raise ValueError('Passwords do not match.')


def initialize_admin(engine, username, password, confirmation):
    """Create one administrator from the offline CLI; refuses when any exists."""
    username = normalize_username(username)
    validate_password(password, confirmation)
    password_hash = generate_password_hash(password)
    try:
        with Session(engine) as session, session.begin():
            if session.scalar(select(AdminAccount.id).limit(1)) is not None:
                raise RuntimeError(
                    'An administrator account already exists. '
                    'Use the Admin Sign Up page to add another administrator.'
                )
            session.add(AdminAccount(username=username, password_hash=password_hash))
    except IntegrityError as error:
        raise RuntimeError('An administrator account already exists.') from error
    return username


def recover_admin_password(engine, username, password, confirmation):
    username = normalize_username(username)
    validate_password(password, confirmation)
    password_hash = generate_password_hash(password)
    with Session(engine) as session, session.begin():
        account = session.scalar(select(AdminAccount).where(AdminAccount.username == username))
        if account is None:
            raise RuntimeError('The specified PATROLMAN administrator was not found.')
        account.password_hash = password_hash
        session.execute(delete(AdminSession).where(AdminSession.username == username))
        session.execute(delete(LoginThrottle))
    return username


def _token_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _throttle_key(kind, value):
    return hashlib.sha256((kind + ':' + value).encode('utf-8')).hexdigest()


def _client_key():
    return _throttle_key('client', request.remote_addr or 'unknown')


def _throttled(session, key, now, window=LOGIN_WINDOW):
    throttle = session.get(LoginThrottle, key)
    if throttle is None:
        return False
    if throttle.locked_until and throttle.locked_until > now:
        session.rollback()
        return True
    if now - throttle.window_started_at >= window:
        session.delete(throttle)
        session.commit()
    return False


def _record_failure(session, key, now, *, window=LOGIN_WINDOW,
                    limit=LOGIN_MAX_ATTEMPTS, lockout=LOGIN_LOCKOUT):
    throttle = session.get(LoginThrottle, key)
    if throttle is not None and now - throttle.window_started_at >= window:
        throttle.attempts = 0
        throttle.window_started_at = now
        throttle.locked_until = None
    if throttle is None:
        throttle = LoginThrottle(client_key=key, attempts=0, window_started_at=now)
        session.add(throttle)
    throttle.attempts += 1
    if throttle.attempts >= limit:
        throttle.locked_until = now + lockout
    session.commit()
    return bool(throttle.locked_until)


def _clear_throttles(session, keys):
    keys = [key for key in keys if key]
    if keys:
        session.execute(delete(LoginThrottle).where(LoginThrottle.client_key.in_(keys)))


def _normalized_origin(value, allow_path=False):
    """Return a canonical scheme://host:port origin, or None when malformed.

    ``Origin`` headers must be bare origins; a ``Referer`` legitimately carries
    a path and query, but only its origin is compared.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme not in {'http', 'https'} or not parts.netloc:
        return None
    if parts.username or parts.password:
        return None
    if not allow_path and (parts.path not in {'', '/'} or parts.query or parts.fragment):
        return None
    return f'{parts.scheme}://{parts.netloc}'


def _valid_origin(trusted_origins=()):
    """Same-origin (or explicitly trusted-origin) check for browser requests.

    ``Origin`` is authoritative when present. A ``Referer`` is validated when
    no ``Origin`` is supplied. Requests with neither header (non-browser API
    clients) are allowed; cookie-authenticated state changes still require a
    valid CSRF token.
    """
    expected = f'{request.scheme}://{request.host}'
    for header in ('Origin', 'Referer'):
        value = request.headers.get(header)
        if value is None:
            continue
        normalized = _normalized_origin(value, allow_path=(header == 'Referer'))
        if normalized is None:
            return False
        return normalized == expected or normalized in trusted_origins
    return True


def _preauth_csrf(trusted_origins=()):
    """Validate the CSRF token issued before a session exists.

    Login and signup cannot use the per-session token because no session has
    been created yet. The browser instead fetches a random value that is stored
    in a SameSite=Strict cookie and echoed in ``X-CSRF-Token``; both must match,
    and the strict origin check is applied as well.
    """
    supplied = request.headers.get('X-CSRF-Token', '')
    cookie = request.cookies.get(CSRF_COOKIE, '')
    if not supplied or not cookie or len(supplied) > 128:
        return False
    return hmac.compare_digest(supplied, cookie) and _valid_origin(trusted_origins)


def _session_for_request(engine):
    token = request.cookies.get(SESSION_COOKIE, '')
    if not token or len(token) > 128:
        return None
    key = _token_hash(token)
    now = utcnow()
    with Session(engine) as session:
        row = session.get(AdminSession, key)
        if row is None:
            return None
        if row.expires_at <= now:
            session.delete(row)
            session.commit()
            return None
        last_seen = row.last_seen_at or row.created_at
        if last_seen is not None and now - last_seen > SESSION_IDLE:
            session.delete(row)
            session.commit()
            return None
        if row.last_seen_at is None or now - row.last_seen_at > SESSION_TOUCH_INTERVAL:
            row.last_seen_at = now
            session.commit()
        return key, row.username, row.csrf_token


def _audit(engine, event, actor, *, details=None, resource_type='user', resource_id=None):
    """Record a security event without ever accepting secret material."""
    try:
        log_event(
            engine,
            event,
            actor=actor or 'unknown',
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=request.remote_addr,
        )
    except Exception:
        pass


def _audit_actor(value):
    clean = re.sub(r'[\x00-\x1f\x7f]', '', str(value or '')).strip()
    return clean[:64] or 'unknown'


def install_auth(app, engine, settings):
    create_auth_tables(engine)
    api = Blueprint('authentication', __name__)
    trusted_origins = tuple(settings.trusted_origins)

    def issue_session(session, username, now):
        raw_session = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        session.add(AdminSession(
            token_hash=_token_hash(raw_session),
            username=username,
            csrf_token=csrf_token,
            created_at=now,
            expires_at=now + SESSION_LIFETIME,
            last_seen_at=now,
        ))
        return raw_session, csrf_token

    def session_response(raw_session, username, csrf_token):
        response = make_response(jsonify(data={'username': username, 'csrf_token': csrf_token}))
        # The pre-authentication token is not reused once a session exists.
        response.delete_cookie(
            CSRF_COOKIE, path='/', secure=request.is_secure, samesite='Strict',
        )
        response.set_cookie(
            SESSION_COOKIE,
            raw_session,
            max_age=int(SESSION_LIFETIME.total_seconds()),
            httponly=True,
            secure=request.is_secure,
            samesite='Strict',
            path='/',
        )
        return response

    @api.get('/api/auth/status')
    def auth_status():
        with Session(engine) as session:
            initialized = session.scalar(select(AdminAccount.id).limit(1)) is not None
        return jsonify(data={
            'administrator_initialized': initialized,
            'registration_enabled': bool(settings.registration_enabled),
        })

    @api.get('/api/auth/csrf')
    def csrf_bootstrap():
        """Issue the pre-session CSRF token used by login and signup.

        A value already bound to this browser is reused so several tabs can
        submit independently without invalidating each other.
        """
        existing = request.cookies.get(CSRF_COOKIE, '')
        if (not 20 <= len(existing) <= 128
                or not re.fullmatch(r'[A-Za-z0-9_-]+', existing)):
            existing = secrets.token_urlsafe(32)
        response = make_response(jsonify(data={'csrf_token': existing}))
        response.headers['Cache-Control'] = 'no-store'
        response.set_cookie(
            CSRF_COOKIE,
            existing,
            max_age=int(SESSION_LIFETIME.total_seconds()),
            httponly=True,
            secure=request.is_secure,
            samesite='Strict',
            path='/',
        )
        return response

    @api.post('/api/auth/signup')
    def signup():
        if not settings.registration_enabled:
            # Not audited per attempt: this path is unauthenticated and would
            # otherwise allow unauthenticated audit-log flooding.
            return jsonify(error={
                'code': 'registration_disabled',
                'message': 'Registration is disabled for this installation. Sign in instead.',
            }), 403
        if not _preauth_csrf(trusted_origins):
            _audit(engine, 'auth_register_rejected', 'anonymous',
                   details={'reason': 'csrf_or_origin_rejected'})
            return jsonify(error={'code': 'csrf_failed', 'message': 'Request could not be verified.'}), 403

        now = utcnow()
        client_key = _client_key()
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {'username', 'password', 'confirm_password'}:
            with Session(engine) as session:
                locked = _record_failure(
                    session, client_key, now, window=REGISTER_WINDOW,
                    limit=REGISTER_MAX_ATTEMPTS, lockout=REGISTER_LOCKOUT,
                )
            if locked:
                _audit(engine, 'auth_rate_limited', 'anonymous', details={'scope': 'registration'})
            return jsonify(error={
                'code': 'invalid_input',
                'message': 'Registration is temporarily unavailable. Try again later.'
                if locked else 'Enter a username and matching password.',
            }), (429 if locked else 400)

        username = payload.get('username')
        password = payload.get('password')
        confirmation = payload.get('confirm_password')
        try:
            username = normalize_username(username)
            validate_password(password, confirmation)
        except ValueError as error:
            with Session(engine) as session:
                locked = _record_failure(
                    session, client_key, now, window=REGISTER_WINDOW,
                    limit=REGISTER_MAX_ATTEMPTS, lockout=REGISTER_LOCKOUT,
                )
            if locked:
                _audit(engine, 'auth_rate_limited', 'anonymous',
                       details={'scope': 'registration'})
                return jsonify(error={
                    'code': 'login_limited',
                    'message': 'Registration is temporarily unavailable. Try again later.',
                }), 429
            return jsonify(error={'code': 'invalid_input', 'message': str(error)}), 400

        user_key = _throttle_key('register-user', username)
        with Session(engine) as session:
            if _throttled(session, client_key, now, window=REGISTER_WINDOW) or \
                    _throttled(session, user_key, now, window=REGISTER_WINDOW):
                return jsonify(error={
                    'code': 'login_limited',
                    'message': 'Registration is temporarily unavailable. Try again later.',
                }), 429

            password_hash = generate_password_hash(payload['password'])
            raw_session, csrf_token = issue_session(session, username, now)
            session.add(AdminAccount(username=username, password_hash=password_hash))
            try:
                session.flush()
            except IntegrityError:
                session.rollback()
                locked = _record_failure(
                    session, client_key, now, window=REGISTER_WINDOW,
                    limit=REGISTER_MAX_ATTEMPTS, lockout=REGISTER_LOCKOUT,
                )
                _audit(engine, 'auth_register_rejected', _audit_actor(username),
                       details={'reason': 'duplicate_username'})
                if locked:
                    _audit(engine, 'auth_rate_limited', _audit_actor(username),
                           details={'scope': 'registration'})
                return jsonify(error={
                    'code': 'registration_failed',
                    'message': 'Registration could not be completed. '
                               'Choose a different username and try again.',
                }), 409
            _clear_throttles(session, (client_key, user_key))
            session.commit()

        _audit(engine, 'auth_signup', username, resource_id=username,
               details={'registration': 'self_service'})
        return session_response(raw_session, username, csrf_token)

    @api.post('/api/auth/login')
    def login():
        if not _preauth_csrf(trusted_origins):
            _audit(engine, 'auth_login_failed', 'unknown', details={'reason': 'csrf_or_origin_rejected'})
            return jsonify(error={'code': 'csrf_failed', 'message': 'Request could not be verified.'}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {'username', 'password'}:
            return jsonify(error={'code': 'invalid_input', 'message': 'Enter your username and password.'}), 400
        username = payload.get('username')
        password = payload.get('password')
        if (not isinstance(username, str) or not isinstance(password, str)
                or len(username) > 256 or len(password) > PASSWORD_MAX_LENGTH):
            return jsonify(error={'code': 'invalid_input', 'message': 'Enter your username and password.'}), 400
        normalized = username.strip().lower()
        client_key = _client_key()
        account_key = _throttle_key('login-user', normalized)
        now = utcnow()
        with Session(engine) as session:
            account = session.scalar(
                select(AdminAccount).where(AdminAccount.username == normalized)
            )
            if _throttled(session, client_key, now) or (
                    account is not None and _throttled(session, account_key, now)):
                return jsonify(error={
                    'code': 'login_limited',
                    'message': 'Sign-in is temporarily unavailable. Try again later.',
                }), 429
            if session.scalar(select(AdminAccount.id).limit(1)) is None:
                session.rollback()
                return jsonify(error={
                    'code': 'admin_uninitialized',
                    'message': 'Administrator setup is required before sign-in.',
                }), 503
            password_hash = account.password_hash if account else DUMMY_PASSWORD_HASH
            valid_password = check_password_hash(password_hash, password)
            valid_username = bool(account and hmac.compare_digest(account.username, normalized))
            if not (valid_username and valid_password):
                locked = _record_failure(session, client_key, now)
                if account is not None:
                    locked = _record_failure(session, account_key, now) or locked
                _audit(engine, 'auth_login_failed', _audit_actor(normalized),
                       details={'reason': 'invalid_credentials'})
                if locked:
                    _audit(engine, 'auth_rate_limited', _audit_actor(normalized),
                           details={'scope': 'login'})
                    return jsonify(error={
                        'code': 'login_limited',
                        'message': 'Sign-in is temporarily unavailable. Try again later.',
                    }), 429
                return jsonify(error={'code': 'unauthorized', 'message': 'Invalid username or password.'}), 401

            account_username = account.username
            _clear_throttles(session, (client_key, account_key))
            raw_session, csrf_token = issue_session(session, account_username, now)
            session.commit()

        _audit(engine, 'auth_login_success', account_username, resource_id=account_username)
        return session_response(raw_session, account_username, csrf_token)

    @api.get('/api/auth/session')
    def session_status():
        authenticated = _session_for_request(engine)
        if not authenticated:
            return jsonify(error={'code': 'unauthorized', 'message': 'Sign in is required.'}), 401
        _, username, csrf_token = authenticated
        return jsonify(data={'username': username, 'csrf_token': csrf_token})

    app.register_blueprint(api)

    def protected(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            supplied = request.headers.get('Authorization', '').strip()
            if supplied:
                if not settings.api_token:
                    return jsonify(error={'code': 'unauthorized', 'message': 'API token authentication is not configured.'}), 401
                expected = ('Bearer ' + settings.api_token).encode('utf-8')
                if hmac.compare_digest(supplied.encode('utf-8'), expected):
                    g.auth_mode = 'bearer'
                    g.admin_username = 'api_operator'
                    return function(*args, **kwargs)
                return jsonify(error={'code': 'unauthorized', 'message': 'Invalid API token.'}), 401

            authenticated = _session_for_request(engine)
            if not authenticated:
                response = jsonify(error={'code': 'unauthorized', 'message': 'Authentication required.'})
                response.status_code = 401
                response.delete_cookie(
                    SESSION_COOKIE, path='/', secure=request.is_secure, samesite='Strict',
                )
                return response

            token_hash, username, csrf_token = authenticated
            if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
                supplied_csrf = request.headers.get('X-CSRF-Token', '')
                if (not hmac.compare_digest(supplied_csrf, csrf_token)
                        or not _valid_origin(trusted_origins)):
                    return jsonify(error={'code': 'csrf_failed', 'message': 'Request could not be verified.'}), 403
            g.auth_mode = 'session'
            g.admin_session_hash = token_hash
            g.admin_username = username
            return function(*args, **kwargs)
        return wrapped

    @app.post('/api/auth/logout')
    @protected
    def logout():
        token_hash = getattr(g, 'admin_session_hash', None)
        actor = getattr(g, 'admin_username', None) or 'administrator'
        if token_hash:
            with Session(engine) as session:
                session.execute(delete(AdminSession).where(AdminSession.token_hash == token_hash))
                session.commit()
        _audit(engine, 'auth_logout', actor, resource_id=actor)
        response = make_response('', 204)
        response.delete_cookie(
            SESSION_COOKIE, path='/', secure=request.is_secure, samesite='Strict',
        )
        return response

    @app.post('/api/auth/change-password')
    @protected
    def change_password():
        actor = getattr(g, 'admin_username', None)
        if not actor:
            return jsonify(error={'code': 'unauthorized', 'message': 'Authentication required.'}), 401

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) - {'current_password', 'new_password', 'confirm_password'}:
            return jsonify(error={'code': 'invalid_input', 'message': 'Provide current_password, new_password, and confirm_password.'}), 400

        current_password = payload.get('current_password')
        new_password = payload.get('new_password')
        confirm_password = payload.get('confirm_password')

        if not current_password or not isinstance(current_password, str):
            return jsonify(error={'code': 'invalid_input', 'message': 'Current password is required.'}), 400

        try:
            validate_password(new_password, confirm_password)
        except ValueError as err:
            return jsonify(error={'code': 'invalid_password', 'message': str(err)}), 400

        with Session(engine) as session:
            account = session.scalar(select(AdminAccount).where(AdminAccount.username == actor))
            if account is None:
                return jsonify(error={'code': 'unauthorized', 'message': 'Account not found.'}), 401

            if not check_password_hash(account.password_hash, current_password):
                _audit(engine, 'auth_password_change_failed', actor, details={'reason': 'incorrect_current_password'})
                return jsonify(error={'code': 'invalid_credentials', 'message': 'Current password is incorrect.'}), 401

            account.password_hash = generate_password_hash(new_password)

            # Invalidate all other active sessions for this administrator
            current_token_hash = getattr(g, 'admin_session_hash', None)
            if current_token_hash:
                session.execute(
                    delete(AdminSession).where(
                        AdminSession.username == actor,
                        AdminSession.token_hash != current_token_hash,
                    )
                )
            session.commit()

        _audit(engine, 'auth_password_changed', actor, resource_id=actor, details={'action': 'password_updated'})
        return jsonify(data={'message': 'Password changed successfully.'}), 200

    return protected
