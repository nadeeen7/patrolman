"""End-to-end authentication regression test through the real Vite dev proxy.

The 403 login failure this test guards against was caused by Vite's string
proxy shorthand expanding to ``{target, changeOrigin: true}``, which rewrites
``Host`` to the backend origin while the browser keeps sending its own
``Origin``. Flask compares the two, so every login/signup through the old
proxy failed. The fix set ``changeOrigin: false`` and added the pre-session
``GET /api/auth/csrf`` bootstrap.

This module proves the whole flow over real sockets:

- a Flask child process (``e2e_flask_runner.py``) bound to 127.0.0.1 on its own
  exclusively allocated port, backed by a temporary SQLite database seeded with
  a synthetic administrator only;
- a Vite dev-server child process bound to 127.0.0.1 on another free port,
  configured from the project's real ``frontend/vite.config.js`` (the proxy
  target is injected via ``AVA_PROXY_TARGET``);
- a second Vite child using a temporary ``changeOrigin: true`` config that
  reproduces the pre-fix proxy behaviour against the same backend;
- a second Flask child started with ``AVA_REGISTRATION_ENABLED=false``.

Requests are issued with ``http.client`` using browser semantics (Host comes
from the connection target, Origin is sent on state-changing requests, cookies
are jarred), and always target the Vite port, never the Flask port. This is an
HTTP-level test: no real browser, no JavaScript execution, no scanners, no
external network access, no production database, and no credentials
other than synthetic ones created by this test.

Secrets (passwords, CSRF tokens, session cookies) are kept inside class
attributes whose default repr cannot appear in an assertion report, and the
backend's request diagnostics record only method, path, Host, Origin, CSRF
header presence, status and error code.

Transient Windows loopback connect stalls have been observed against Vite's
proxy (``connect ETIMEDOUT`` before any byte reaches Flask). The client retries
only connect-phase failures and Vite's own non-JSON proxy-error pages, at most
``TRANSPORT_ATTEMPTS`` times; anything Flask itself answered is never retried,
so no application behaviour can be double-applied or masked.
"""
import http.client
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import URL

from backend.auth import initialize_admin
from backend.config import Settings  # noqa: F401  (documents the settings surface the children use)
from backend.models import Base

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / 'frontend'
VITE_BIN = FRONTEND_DIR / 'node_modules' / 'vite' / 'bin' / 'vite.js'
BACKEND_RUNNER = Path(__file__).with_name('e2e_flask_runner.py')

API_TOKEN = 'e2e-auth-test-token-' + 'x' * 32          # synthetic, never a real token
ADMIN_USERNAME = 'e2e-admin'
ADMIN_PASSWORD = 'synthetic-e2e-password-123'

STARTUP_TIMEOUT = 45.0
HTTP_TIMEOUT = 10.0
TRANSPORT_ATTEMPTS = 3      # bounded retries for connect-level failures only
_OMIT = object()


class TransportFailure(Exception):
    """Connect-phase failure: the request never reached Flask.

    Retrying this cannot double-apply any application behaviour (no session,
    throttle counter or audit row was created), because Flask always answers
    with JSON and never lets a TCP connect to it time out while listening.
    """

# The exact, non-sensitive schema of one diagnostic line written by
# e2e_flask_runner.py. Anything else in a record fails the final test.
EXPECTED_DIAGNOSTIC_FIELDS = {
    'method', 'path', 'host', 'origin', 'csrf_header_present', 'status', 'error_code',
}

pytestmark = pytest.mark.skipif(
    not VITE_BIN.is_file() or not shutil.which('node'),
    reason='frontend/node_modules or node is unavailable; run npm install first.',
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def free_port():
    """Allocate an exclusively bound loopback port and release it for reuse."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def log_tail(path, limit=2000):
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return '<no log captured>'
    return text[-limit:]


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def wait_for_port(process, port, log_path, what):
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f'{what} exited with code {process.returncode} during startup.\n'
                f'log tail:\n{log_tail(log_path)}'
            )
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(
        f'{what} did not listen on 127.0.0.1:{port} within {STARTUP_TIMEOUT:.0f}s.\n'
        f'log tail:\n{log_tail(log_path)}'
    )


def raw_get(port, path):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=HTTP_TIMEOUT)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_for_vite(process, port, log_path, what):
    deadline = time.monotonic() + STARTUP_TIMEOUT
    last = 'no attempt yet'
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f'{what} exited with code {process.returncode} during startup.\n'
                f'log tail:\n{log_tail(log_path)}'
            )
        try:
            status, body = raw_get(port, '/')
            if status == 200 and b'id="root"' in body:
                return
            last = f'HTTP {status}'
        except OSError as error:
            last = error.__class__.__name__
        time.sleep(0.3)
    raise RuntimeError(
        f'{what} was not ready within {STARTUP_TIMEOUT:.0f}s ({last}).\n'
        f'log tail:\n{log_tail(log_path)}'
    )


class Response:
    """HTTP response wrapper.

    Deliberately keeps the default object repr so a failing assertion report
    can never dump a response body (which may carry a CSRF token).
    """

    def __init__(self, status, headers, body):
        self.status = status
        self._headers = headers      # email.message.Message
        self.body = body             # bytes

    @property
    def headers(self):
        return self._headers

    @property
    def text(self):
        return self.body.decode('utf-8', 'replace')

    @property
    def json(self):
        try:
            payload = json.loads(self.text)
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None

    @property
    def content_type(self):
        return self._headers.get('Content-Type', '')

    @property
    def data(self):
        payload = self.json
        data = payload.get('data') if payload else None
        return data if isinstance(data, dict) else {}

    @property
    def error_code(self):
        payload = self.json
        error = payload.get('error') if payload else None
        return error.get('code') if isinstance(error, dict) else None

    @property
    def error_message(self):
        payload = self.json
        error = payload.get('error') if payload else None
        return error.get('message') if isinstance(error, dict) else None

    def set_cookie_headers(self):
        return self._headers.get_all('Set-Cookie') or []


class Browser:
    """Cookie-aware HTTP client bound to a single origin (the Vite dev server).

    - ``Host`` is never set as a header: the connection target decides it,
      exactly as in a browser, so the Host Flask records proves the request
      travelled through the proxy.
    - ``Origin`` is sent on state-changing requests (browser behaviour) unless
      the caller overrides it.
    - Secrets live only in attributes, whose default repr pytest cannot
      expand, so assertion failures cannot print tokens or cookies.
    """

    def __init__(self, origin):
        parts = urlsplit(origin)
        self.origin = f'{parts.scheme}://{parts.netloc}'
        self.host = parts.hostname
        self.port = parts.port
        self.cookies = {}
        self.presession_csrf = ''
        self.session_csrf = ''
        self.presession_issued = False
        self.csrf_pair_matches = False
        self.session_issued = False
        self._replay_cookie = ''

    # -- low level ---------------------------------------------------------- #

    def request(self, method, path, *, json_body=_OMIT, headers=None):
        request_headers = {'Accept': 'application/json'}
        supplied = {key.lower() for key in (headers or {})}
        if 'host' in supplied:
            raise AssertionError('Host must come from the connection target, never a header override')
        if 'origin' not in supplied and method.upper() not in {'GET', 'HEAD', 'OPTIONS'}:
            request_headers['Origin'] = self.origin
        if headers:
            request_headers.update(headers)
        if self.cookies:
            request_headers['Cookie'] = '; '.join(
                f'{name}={value}' for name, value in self.cookies.items()
            )
        # One request per connection: the backend's handler threads exit as
        # soon as the response is delivered instead of waiting for reuse.
        request_headers['Connection'] = 'close'
        request_headers = {
            key: value for key, value in request_headers.items() if value is not None
        }
        payload = None
        if json_body is not _OMIT:
            payload = json.dumps(json_body).encode('utf-8')
            request_headers['Content-Type'] = 'application/json'

        response = None
        for attempt in range(1, TRANSPORT_ATTEMPTS + 1):
            try:
                response = self._send(method, path, payload, request_headers)
            except TransportFailure:
                if attempt == TRANSPORT_ATTEMPTS:
                    raise
            else:
                # A non-JSON >=500 is Vite's own proxy-error page (Flask always
                # answers JSON), so the backend was unreachable for this try.
                if attempt == TRANSPORT_ATTEMPTS or not (
                        response.status >= 500 and response.json is None):
                    break
            time.sleep(0.5 * attempt)
        self._absorb_cookies(response)
        return response

    def _send(self, method, path, payload, request_headers):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=HTTP_TIMEOUT)
        try:
            try:
                connection.connect()
            except OSError as error:
                raise TransportFailure(
                    f'connect to {self.host}:{self.port} failed: {error.__class__.__name__}'
                ) from error
            connection.request(method.upper(), path, body=payload, headers=request_headers)
            raw = connection.getresponse()
            body = raw.read()
            return Response(raw.status, raw.headers, body)
        finally:
            connection.close()

    def _absorb_cookies(self, response):
        for header in response.set_cookie_headers():
            first, _, remainder = header.partition(';')
            name, separator, value = first.partition('=')
            if not separator:
                continue
            name, value = name.strip(), value.strip()
            attributes = {}
            for item in remainder.split(';'):
                key, _, item_value = item.partition('=')
                attributes[key.strip().lower()] = item_value.strip()
            expired = value == '' or attributes.get('max-age') == '0'
            if not expired and '1970' in attributes.get('expires', ''):
                expired = True
            if expired:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value

    # -- browser-like flows ------------------------------------------------- #

    def bootstrap_csrf(self):
        """GET /api/auth/csrf the way the frontend does before login/signup."""
        response = self.request('GET', '/api/auth/csrf')
        self.presession_csrf = str(response.data.get('csrf_token') or '')
        cookie_value = self.cookies.get('patrolman_csrf', '')
        self.presession_issued = len(self.presession_csrf) >= 20
        self.csrf_pair_matches = bool(cookie_value) and hmac.compare_digest(
            self.presession_csrf, cookie_value
        )
        return response

    def login(self, username, password, *, headers=None):
        request_headers = dict(headers or {})
        request_headers.setdefault('X-CSRF-Token', self.presession_csrf)
        response = self.request(
            'POST', '/api/auth/login',
            json_body={'username': username, 'password': password},
            headers=request_headers,
        )
        if response.status == 200:
            self.session_csrf = str(response.data.get('csrf_token') or '')
            self.session_issued = len(self.session_csrf) >= 32
        return response

    def signup(self, username, password, *, headers=None):
        request_headers = dict(headers or {})
        request_headers.setdefault('X-CSRF-Token', self.presession_csrf)
        response = self.request(
            'POST', '/api/auth/signup',
            json_body={
                'username': username,
                'password': password,
                'confirm_password': password,
            },
            headers=request_headers,
        )
        if response.status == 200:
            self.session_csrf = str(response.data.get('csrf_token') or '')
            self.session_issued = len(self.session_csrf) >= 32
        return response

    def logout(self, *, headers=None):
        request_headers = dict(headers or {})
        request_headers.setdefault('X-CSRF-Token', self.session_csrf)
        response = self.request('POST', '/api/auth/logout', headers=request_headers)
        if response.status == 204:
            self.session_csrf = ''
            self.session_issued = False
        return response

    def remember_session_cookie(self):
        """Keep the raw session cookie internally for the replay attempt."""
        self._replay_cookie = self.cookies.get('patrolman_session', '')

    def replay_with_remembered_cookie(self):
        clone = Browser(self.origin)
        clone.cookies['patrolman_session'] = self._replay_cookie
        return clone


class BackendInstance:
    """Flask child process on its own loopback port and temporary database."""

    def __init__(self, name, data_dir, registration_enabled):
        self.name = name
        self.data_dir = Path(data_dir)
        self.diag_path = self.data_dir / 'e2e-diagnostics.jsonl'
        self.log_path = self.data_dir / 'backend.log'
        self.port = free_port()
        self.origin = f'http://127.0.0.1:{self.port}'
        self.registration_enabled = registration_enabled
        self.process = None
        self._log_handle = None

    def seed_administrator(self):
        """Create one synthetic administrator before the child starts."""
        engine = create_engine(URL.create('sqlite', database=str(self.data_dir / 'assessment.sqlite3')))
        try:
            Base.metadata.create_all(engine)
            initialize_admin(engine, ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_PASSWORD)
        finally:
            engine.dispose()

    def start(self):
        environment = dict(os.environ)
        for key in [key for key in environment if key.startswith('AVA_')]:
            environment.pop(key)
        environment.update({
            'AVA_API_TOKEN': API_TOKEN,
            'AVA_DATA_DIR': str(self.data_dir),
            'AVA_PORT': str(self.port),
            'AVA_REGISTRATION_ENABLED': 'true' if self.registration_enabled else 'false',
            'AVA_TRUSTED_ORIGINS': '',          # same-origin must be enough
            'AVA_WAPITI_ENABLED': 'false',  # never enable scanners
            'AVA_ALLOW_PRIVATE_TARGETS': 'false',
            'AVA_REQUIRE_AUTHORIZED_TARGET': 'true',
            'AVA_E2E_DIAG': str(self.diag_path),
        })
        self._log_handle = open(self.log_path, 'w', encoding='utf-8', errors='replace')
        self.process = subprocess.Popen(
            [sys.executable, str(BACKEND_RUNNER)],
            cwd=str(PROJECT_ROOT),
            env=environment,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_port(self.process, self.port, self.log_path, f'{self.name} (Flask)')
        except Exception:
            self.stop()
            raise

    def stop(self):
        if self.process is not None:
            stop_process(self.process)
            self.process = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def records(self):
        if not self.diag_path.is_file():
            return []
        return [
            json.loads(line)
            for line in self.diag_path.read_text(encoding='utf-8').splitlines()
            if line.strip()
        ]

    def last_record(self):
        records = self.records()
        return records[-1] if records else None


LEGACY_VITE_CONFIG = """export default {{
  root: {root},
  logLevel: 'warn',
  clearScreen: false,
  server: {{
    host: '127.0.0.1',
    port: {port},
    strictPort: true,
    proxy: {{
      // Vite expands a string shorthand with `changeOrigin: true`, which is
      // exactly the pre-fix configuration: Host is rewritten to the backend
      // origin while Origin stays on this dev server, reproducing the 403.
      '/api': {{ target: {target}, changeOrigin: true }},
    }},
  }},
}};
"""


class ViteInstance:
    """Vite dev-server child bound to 127.0.0.1.

    ``legacy=True`` writes a temporary config reproducing the pre-fix proxy
    (``changeOrigin: true``); otherwise the project's real vite.config.js is
    used with ``AVA_PROXY_TARGET`` pointing at the test backend.
    """

    def __init__(self, name, workspace, target_backend, legacy=False):
        self.name = name
        self.workspace = Path(workspace)
        self.target_backend = target_backend
        self.legacy = legacy
        self.port = free_port()
        self.origin = f'http://127.0.0.1:{self.port}'
        self.log_path = self.workspace / 'vite.log'
        self.process = None
        self._log_handle = None
        self.config_path = None
        if legacy:
            self.config_path = self.workspace / 'vite.legacy-proxy.config.mjs'
            self.config_path.write_text(
                LEGACY_VITE_CONFIG.format(
                    root=json.dumps(FRONTEND_DIR.as_posix()),
                    port=self.port,
                    target=json.dumps(target_backend.origin),
                ),
                encoding='utf-8',
            )

    def start(self):
        environment = dict(os.environ)
        for key in [key for key in environment if key.startswith('AVA_')]:
            environment.pop(key)
        if not self.legacy:
            environment['AVA_PROXY_TARGET'] = self.target_backend.origin
        command = [
            shutil.which('node'), str(VITE_BIN),
            '--host', '127.0.0.1', '--port', str(self.port), '--strictPort',
        ]
        if self.config_path is not None:
            command += ['--config', str(self.config_path)]
        self._log_handle = open(self.log_path, 'w', encoding='utf-8', errors='replace')
        self.process = subprocess.Popen(
            command,
            cwd=str(FRONTEND_DIR),
            env=environment,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_vite(self.process, self.port, self.log_path, self.name)
        except Exception:
            self.stop()
            raise

    def stop(self):
        if self.process is not None:
            stop_process(self.process)
            self.process = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None


def host_header(port):
    return f'127.0.0.1:{port}'


# --------------------------------------------------------------------------- #
# fixtures (every child process is stopped in a finally block)
# --------------------------------------------------------------------------- #

@pytest.fixture(scope='module')
def backend_a(tmp_path_factory):
    """Registration-enabled backend seeded with the synthetic administrator."""
    instance = BackendInstance(
        'backend-a', tmp_path_factory.mktemp('auth-e2e-backend-a'), registration_enabled=True,
    )
    instance.seed_administrator()
    try:
        instance.start()
        yield instance
    finally:
        instance.stop()


@pytest.fixture(scope='module')
def vite_fixed(backend_a, tmp_path_factory):
    """The project's real vite.config.js pointed at backend A."""
    vite = ViteInstance('vite-fixed', tmp_path_factory.mktemp('auth-e2e-vite-fixed'), backend_a)
    try:
        vite.start()
        yield vite
    finally:
        vite.stop()


@pytest.fixture(scope='module')
def vite_legacy(backend_a, tmp_path_factory):
    """Pre-fix proxy behaviour (changeOrigin: true) against backend A."""
    vite = ViteInstance(
        'vite-legacy', tmp_path_factory.mktemp('auth-e2e-vite-legacy'), backend_a, legacy=True,
    )
    try:
        vite.start()
        yield vite
    finally:
        vite.stop()


@pytest.fixture(scope='module')
def backend_b(tmp_path_factory):
    """Registration-disabled backend with no accounts."""
    instance = BackendInstance(
        'backend-b', tmp_path_factory.mktemp('auth-e2e-backend-b'), registration_enabled=False,
    )
    try:
        instance.start()
        yield instance
    finally:
        instance.stop()


@pytest.fixture(scope='module')
def vite_disabled(backend_b, tmp_path_factory):
    """The real vite.config.js pointed at the registration-disabled backend."""
    vite = ViteInstance(
        'vite-disabled', tmp_path_factory.mktemp('auth-e2e-vite-disabled'), backend_b,
    )
    try:
        vite.start()
        yield vite
    finally:
        vite.stop()


# --------------------------------------------------------------------------- #
# A — CSRF bootstrap through the proxy
# --------------------------------------------------------------------------- #

def test_csrf_bootstrap_through_vite_preserves_host(vite_fixed, backend_a):
    browser = Browser(vite_fixed.origin)

    status = browser.request('GET', '/api/auth/status')
    assert status.status == 200, (status.status, status.error_code)
    assert status.content_type.startswith('application/json')
    assert status.data.get('administrator_initialized') is True
    assert status.data.get('registration_enabled') is True

    record = backend_a.last_record()
    assert record['path'] == '/api/auth/status'
    # The proxy preserved the browser's Host instead of rewriting it.
    assert record['host'] == host_header(vite_fixed.port)
    assert record['host'] != host_header(backend_a.port)

    bootstrap = browser.bootstrap_csrf()
    assert bootstrap.status == 200, (bootstrap.status, bootstrap.error_code)
    assert bootstrap.headers.get('Cache-Control') == 'no-store'
    cookie = next(
        (header for header in bootstrap.set_cookie_headers()
         if header.startswith('patrolman_csrf=')),
        None,
    )
    assert cookie is not None, 'patrolman_csrf cookie was not set'
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    assert 'Secure' not in cookie
    assert browser.presession_issued
    assert browser.csrf_pair_matches      # body token equals the cookie value
    assert 'patrolman_csrf' in browser.cookies


# --------------------------------------------------------------------------- #
# B — login through the proxy
# --------------------------------------------------------------------------- #

def test_login_through_vite_opens_session_and_rejects_bad_credentials(vite_fixed, backend_a):
    browser = Browser(vite_fixed.origin)
    browser.bootstrap_csrf()
    assert 'patrolman_csrf' in browser.cookies
    assert browser.csrf_pair_matches

    login = browser.login(ADMIN_USERNAME, ADMIN_PASSWORD)
    assert login.status == 200, (login.status, login.error_code)
    assert login.data.get('username') == ADMIN_USERNAME
    assert browser.session_issued
    assert 'patrolman_session' in browser.cookies
    assert 'patrolman_csrf' not in browser.cookies     # pre-session cookie discarded
    session_cookie = next(
        (header for header in login.set_cookie_headers()
         if header.startswith('patrolman_session=')),
        None,
    )
    assert session_cookie is not None
    assert 'HttpOnly' in session_cookie and 'SameSite=Strict' in session_cookie
    assert 'Secure' not in session_cookie

    # What Flask actually received: browser Origin, Vite's Host, CSRF present.
    record = backend_a.last_record()
    assert record['path'] == '/api/auth/login'
    assert record['origin'] == vite_fixed.origin
    assert record['host'] == host_header(vite_fixed.port)
    assert record['csrf_header_present'] is True
    assert record['status'] == 200 and record['error_code'] is None

    # Authenticated session requests succeed through the proxy.
    session_view = browser.request('GET', '/api/auth/session')
    assert session_view.status == 200, (session_view.status, session_view.error_code)
    assert session_view.data.get('username') == ADMIN_USERNAME
    dashboard = browser.request('GET', '/api/dashboard')
    assert dashboard.status == 200, (dashboard.status, dashboard.error_code)
    assert dashboard.data.get('total_scans') == 0

    # Incorrect credentials are rejected with one generic, non-leaking error.
    wrong = Browser(vite_fixed.origin)
    wrong.bootstrap_csrf()
    bad_password = wrong.login(ADMIN_USERNAME, 'incorrect-password-abc')
    unknown_user = wrong.login('no-such-admin', 'incorrect-password-abc')
    assert bad_password.status == unknown_user.status == 401
    assert bad_password.error_code == unknown_user.error_code == 'unauthorized'
    assert bad_password.json == unknown_user.json
    assert bad_password.error_message == 'Invalid username or password.'
    assert ADMIN_USERNAME not in bad_password.text
    assert ADMIN_PASSWORD not in bad_password.text

    # A clean successful login resets the shared rate-limit window for the
    # tests that follow (they all arrive from 127.0.0.1).
    recovery = Browser(vite_fixed.origin)
    recovery.bootstrap_csrf()
    recovered = recovery.login(ADMIN_USERNAME, ADMIN_PASSWORD)
    assert recovered.status == 200, (recovered.status, recovered.error_code)


# --------------------------------------------------------------------------- #
# C — CSRF enforcement through the proxy
# --------------------------------------------------------------------------- #

def test_csrf_enforcement_through_vite(vite_fixed, backend_a):
    without_token = Browser(vite_fixed.origin)
    without_token.bootstrap_csrf()
    missing = without_token.login(ADMIN_USERNAME, ADMIN_PASSWORD, headers={'X-CSRF-Token': None})
    assert missing.status == 403, (missing.status, missing.error_code)
    assert missing.error_code == 'csrf_failed'

    forged = Browser(vite_fixed.origin)
    forged.bootstrap_csrf()
    invalid = forged.login(
        ADMIN_USERNAME, ADMIN_PASSWORD, headers={'X-CSRF-Token': 'not-the-issued-token'},
    )
    assert invalid.status == 403, (invalid.status, invalid.error_code)
    assert invalid.error_code == 'csrf_failed'
    assert backend_a.last_record()['error_code'] == 'csrf_failed'

    cross = Browser(vite_fixed.origin)
    cross.bootstrap_csrf()
    foreign = cross.login(
        ADMIN_USERNAME, ADMIN_PASSWORD,
        headers={'Origin': 'https://attacker.example'},
    )
    assert foreign.status == 403, (foreign.status, foreign.error_code)
    assert foreign.error_code == 'csrf_failed'
    cross_record = backend_a.last_record()
    assert cross_record['origin'] == 'https://attacker.example'
    assert cross_record['host'] == host_header(vite_fixed.port)   # Host still preserved
    assert cross_record['error_code'] == 'csrf_failed'
    assert 'patrolman_session' not in cross.cookies
    assert cross.request('GET', '/api/auth/session').status == 401

    # Valid same-origin requests continue to work.
    accepted_browser = Browser(vite_fixed.origin)
    accepted_browser.bootstrap_csrf()
    accepted = accepted_browser.login(ADMIN_USERNAME, ADMIN_PASSWORD)
    assert accepted.status == 200, (accepted.status, accepted.error_code)
    record = backend_a.last_record()
    assert record['origin'] == vite_fixed.origin
    assert record['host'] == host_header(vite_fixed.port)
    assert record['csrf_header_present'] is True
    assert record['error_code'] is None
    assert accepted_browser.request('GET', '/api/auth/session').status == 200


# --------------------------------------------------------------------------- #
# D — registration through the proxy
# --------------------------------------------------------------------------- #

def test_registration_through_vite(vite_fixed, backend_a):
    first = Browser(vite_fixed.origin)
    first.bootstrap_csrf()
    created = first.signup('e2e-reg-one', 'abcdefgh')     # exactly 8 characters
    assert created.status == 200, (created.status, created.error_code)
    assert created.data.get('username') == 'e2e-reg-one'
    assert first.session_issued
    record = backend_a.last_record()
    assert record['host'] == host_header(vite_fixed.port)
    assert record['error_code'] is None

    short = Browser(vite_fixed.origin)
    short.bootstrap_csrf()
    rejected = short.signup('e2e-reg-short', 'abcdefg')   # 7 characters, backend must refuse
    assert rejected.status == 400, (rejected.status, rejected.error_code)
    assert rejected.error_code == 'invalid_input'
    assert 'between 8 and 1024' in (rejected.error_message or '')

    duplicate = Browser(vite_fixed.origin)
    duplicate.bootstrap_csrf()
    clash = duplicate.signup('e2e-reg-one', 'abcdefgh')
    assert clash.status == 409, (clash.status, clash.error_code)
    assert clash.error_code == 'registration_failed'

    # The refused 7-character attempt created nothing: the same name now works.
    repaired = Browser(vite_fixed.origin)
    repaired.bootstrap_csrf()
    after_short = repaired.signup('e2e-reg-short', 'abcdefgh')
    assert after_short.status == 200, (after_short.status, after_short.error_code)

    second = Browser(vite_fixed.origin)
    second.bootstrap_csrf()
    another = second.signup('e2e-reg-two', 'second-password-123')
    assert another.status == 200, (another.status, another.error_code)
    assert another.data.get('username') == 'e2e-reg-two'

    # The second distinct account can also sign in.
    signin = Browser(vite_fixed.origin)
    signin.bootstrap_csrf()
    login = signin.login('e2e-reg-two', 'second-password-123')
    assert login.status == 200, (login.status, login.error_code)


def test_registration_disabled_setting_enforced_through_vite(vite_disabled, backend_b):
    browser = Browser(vite_disabled.origin)

    status = browser.request('GET', '/api/auth/status')
    assert status.status == 200, (status.status, status.error_code)
    assert status.data.get('registration_enabled') is False
    assert status.data.get('administrator_initialized') is False

    browser.bootstrap_csrf()
    blocked = browser.signup('e2e-disabled-admin', 'password-at-least-8')
    assert blocked.status == 403, (blocked.status, blocked.error_code)
    assert blocked.error_code == 'registration_disabled'

    record = backend_b.last_record()
    assert record['path'] == '/api/auth/signup'
    assert record['host'] == host_header(vite_disabled.port)   # still via Vite
    assert record['error_code'] == 'registration_disabled'


# --------------------------------------------------------------------------- #
# E — logout and session invalidation through the proxy
# --------------------------------------------------------------------------- #

def test_logout_and_session_invalidation_through_vite(vite_fixed, backend_a):
    browser = Browser(vite_fixed.origin)
    browser.bootstrap_csrf()
    login = browser.login(ADMIN_USERNAME, ADMIN_PASSWORD)
    assert login.status == 200, (login.status, login.error_code)
    assert 'patrolman_session' in browser.cookies
    browser.remember_session_cookie()
    assert browser._replay_cookie

    missing = browser.logout(headers={'X-CSRF-Token': None})
    assert missing.status == 403, (missing.status, missing.error_code)
    assert missing.error_code == 'csrf_failed'

    forged = browser.logout(headers={'X-CSRF-Token': 'wrong-session-token'})
    assert forged.status == 403, (forged.status, forged.error_code)
    assert forged.error_code == 'csrf_failed'

    foreign = browser.logout(headers={
        'X-CSRF-Token': browser.session_csrf,
        'Origin': 'https://attacker.example',
    })
    assert foreign.status == 403, (foreign.status, foreign.error_code)
    assert browser.request('GET', '/api/auth/session').status == 200   # session survives

    logout = browser.logout()
    assert logout.status == 204, (logout.status, logout.error_code)
    logout_record = backend_a.last_record()
    deletion = next(
        (header for header in logout.set_cookie_headers()
         if header.startswith('patrolman_session=')),
        None,
    )
    assert deletion is not None, 'logout did not send a session cookie deletion'
    assert 'Max-Age=0' in deletion and '1970' in deletion
    assert 'patrolman_session' not in browser.cookies

    # The revoked session is gone server-side.
    assert browser.request('GET', '/api/auth/session').status == 401
    assert browser.request('GET', '/api/dashboard').status == 401

    # Replaying the captured raw cookie does not restore access.
    replay = browser.replay_with_remembered_cookie()
    assert replay.request('GET', '/api/auth/session').status == 401
    assert replay.request('GET', '/api/dashboard').status == 401

    assert logout_record['path'] == '/api/auth/logout'
    assert logout_record['host'] == host_header(vite_fixed.port)
    assert logout_record['csrf_header_present'] is True
    assert logout_record['status'] == 204 and logout_record['error_code'] is None


# --------------------------------------------------------------------------- #
# Host/Origin regression: pre-fix proxy behaviour reproduced, then diagnosed
# --------------------------------------------------------------------------- #

def test_pre_fix_proxy_reproduces_host_origin_login_failure(vite_legacy, backend_a):
    """Run the pre-fix configuration (changeOrigin: true) against the same backend.

    The same synthetic credentials that succeed through the fixed proxy must
    fail here with csrf_failed, with Flask seeing Host != Origin — the exact
    regression this test guards.
    """
    browser = Browser(vite_legacy.origin)
    browser.bootstrap_csrf()
    login = browser.login(ADMIN_USERNAME, ADMIN_PASSWORD)

    assert login.status == 403, (login.status, login.error_code)
    assert login.error_code == 'csrf_failed'
    assert 'patrolman_session' not in browser.cookies

    record = backend_a.last_record()
    assert record['path'] == '/api/auth/login'
    assert record['origin'] == vite_legacy.origin          # browser Origin unchanged
    assert record['host'] == host_header(backend_a.port)   # Host rewritten by old proxy
    assert record['host'] != record['origin'].split('//', 1)[-1]   # the mismatch
    assert record['error_code'] == 'csrf_failed'


def test_diagnostics_capture_host_origin_without_secrets(
        backend_a, backend_b, vite_fixed, vite_legacy, vite_disabled,
):
    """Aggregate Task 4 diagnostics; runs last, after the flow tests populated them."""
    records_a = backend_a.records()
    records_b = backend_b.records()
    assert records_a, 'backend A recorded no requests'
    assert records_b, 'backend B recorded no requests'

    for record in records_a + records_b:
        assert set(record) == EXPECTED_DIAGNOSTIC_FIELDS   # no cookie/token/hash fields
        if record['origin'] is not None:
            assert record['origin'].startswith(('http://', 'https://'))
        assert record['method'] in {'GET', 'POST'}
        assert record['status'] in {200, 204, 400, 401, 403, 409}

    # Fixed proxy: Flask saw the Vite Host, matching the browser Origin, and accepted login.
    fixed_login = [
        record for record in records_a
        if record['host'] == host_header(vite_fixed.port)
        and record['path'] == '/api/auth/login'
    ]
    assert fixed_login, 'no login through the fixed proxy reached Flask'
    assert any(
        record['status'] == 200
        and record['origin'] == vite_fixed.origin
        and record['error_code'] is None
        for record in fixed_login
    )
    # Every request the fixed proxy delivered carried the Vite Host, so Host and
    # Origin agreed on all of them; no rejection can be blamed on a mismatch.
    fixed_records = [
        record for record in records_a
        if record['host'] == host_header(vite_fixed.port)
    ]
    assert fixed_records
    assert all(
        record['origin'] in (vite_fixed.origin, 'https://attacker.example')
        for record in fixed_records if record['method'] == 'POST'
    )
    # The only foreign-Origin probe is rejected; Host stays the Vite origin.
    assert all(
        record['status'] == 403 and record['error_code'] == 'csrf_failed'
        for record in fixed_records
        if record['method'] == 'POST' and record['origin'] != vite_fixed.origin
    )
    # Every 403 through the fixed proxy was an intentional CSRF/origin rejection
    # (business rejections are 400/401/409), never a Host/Origin mismatch.
    fixed_forbidden = [record for record in fixed_records if record['status'] == 403]
    assert fixed_forbidden
    assert all(record['error_code'] == 'csrf_failed' for record in fixed_forbidden)

    # Pre-fix proxy: Host was rewritten away from the browser Origin on every request.
    legacy_records = [record for record in records_a if record['origin'] == vite_legacy.origin]
    assert legacy_records, 'the pre-fix proxy sent no requests to Flask'
    assert all(record['host'] == host_header(backend_a.port) for record in legacy_records)
    assert any(
        record['path'] == '/api/auth/login'
        and record['status'] == 403
        and record['error_code'] == 'csrf_failed'
        for record in legacy_records
    )

    interesting_paths = {'/api/auth/login', '/api/auth/signup', '/api/auth/logout'}
    summary = {
        'fixed_proxy': [
            {key: record[key] for key in
             ('path', 'origin', 'host', 'status', 'csrf_header_present', 'error_code')}
            for record in records_a
            if record['host'] == host_header(vite_fixed.port) and record['path'] in interesting_paths
        ],
        'pre_fix_proxy': [
            {key: record[key] for key in
             ('path', 'origin', 'host', 'status', 'csrf_header_present', 'error_code')}
            for record in legacy_records if record['path'] in interesting_paths
        ],
        'registration_disabled_backend': [
            {key: record[key] for key in
             ('path', 'origin', 'host', 'status', 'csrf_header_present', 'error_code')}
            for record in records_b
        ],
        'vite_origins': {
            'fixed': vite_fixed.origin,
            'pre_fix': vite_legacy.origin,
            'registration_disabled': vite_disabled.origin,
        },
        'backend_origins': {'a': backend_a.origin, 'b': backend_b.origin},
    }
    print('\nHOST/ORIGIN DIAGNOSTICS (non-sensitive):\n' + json.dumps(summary, indent=2))
