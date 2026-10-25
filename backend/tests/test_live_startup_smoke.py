"""Automated live-startup smoke tests for the PATROLMAN framework.

Exercises the real backend process across core startup and configuration
workflows over local loopback sockets:

Case A: Valid API token and existing allowed root
  - Real backend process starts and listens on loopback.
  - /api/health returns HTTP 200.
  - Gitleaks reports runtime status 'configured' with roots 1/1.
  - The configured allowed root is recognized.
  - Startup banner displays without exposing the token value.
  - Unauthenticated requests are rejected (HTTP 401).
  - Wapiti remains safety-gated (disabled/missing, not verified).

Case B: Missing API token
  - Startup fails immediately with exit code 1.
  - Actionable configuration error is reported to stderr.
  - No traceback is emitted.
  - Token value is never displayed or leaked.
  - Backend does not bind or bypass authentication.

Case C: Invalid or deleted allowed root
  - Backend starts safely without crashing.
  - /api/health returns HTTP 200.
  - Gitleaks reports runtime status 'configuration_required' (roots 1/0).
  - The missing/deleted filesystem path is never exposed in API responses or logs.

Case D: Durable configuration via AVA_ENV_FILE / .env
  - Fresh backend process loads configuration from a file.
  - Inherited runner environment variables are isolated and not relied upon.
  - Loaded token and local roots take effect in the live running process.
  - /api/health and authenticated /api/tools succeed.
"""

import json
import os
import secrets
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PYTHON_EXECUTABLE = sys.executable

STARTUP_TIMEOUT = 45.0
SHUTDOWN_TIMEOUT = 10.0
HTTP_TIMEOUT = 30.0
SYNTHETIC_TOKEN_PREFIX = 'synthetic-smoke-token-'


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


def clean_subprocess_env(extra_env=None):
    """Return a clean environment dict free from any inherited AVA_* variables.

    Preserves standard operating system and Python environment keys while
    ensuring test isolation from the host machine or active terminal.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith('AVA_')}
    env['PYTHONPATH'] = str(PROJECT_ROOT)
    env['PYTHONUNBUFFERED'] = '1'
    env['AVA_ENV_FILE'] = str(PROJECT_ROOT / '.env.test_isolated_nonexistent')
    if extra_env:
        env.update(extra_env)
    return env


def stop_backend_process(process, timeout=SHUTDOWN_TIMEOUT):
    """Gracefully terminate a backend process, escalating to kill if bounded."""
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5.0)
        except OSError:
            pass
    except OSError:
        pass


@contextmanager
def managed_live_backend(env, log_path, entrypoint='backend'):
    """Context manager to spawn and reliably tear down a live backend subprocess."""
    log_file = open(log_path, 'w+', encoding='utf-8', errors='replace')
    process = None
    try:
        process = subprocess.Popen(
            [PYTHON_EXECUTABLE, '-m', entrypoint],
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        yield process
    finally:
        if process is not None:
            stop_backend_process(process)
        try:
            log_file.flush()
            log_file.close()
        except OSError:
            pass


def wait_for_backend_health(port, process, log_path, timeout=STARTUP_TIMEOUT):
    """Poll /api/health until HTTP 200 is returned or startup timeout expires."""
    deadline = time.monotonic() + timeout
    last_error = None
    url = f'http://127.0.0.1:{port}/api/health'

    while time.monotonic() < deadline:
        if process.poll() is not None:
            log_content = ''
            try:
                log_content = Path(log_path).read_text(encoding='utf-8', errors='replace')
            except OSError:
                pass
            raise RuntimeError(
                f'Backend exited prematurely with code {process.returncode} during startup.\n'
                f'Server logs:\n{log_content[-2000:]}'
            )

        try:
            req = Request(url)
            with urlopen(req, timeout=1.0) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get('data', {}).get('status') == 'ok':
                        return data
        except (URLError, OSError, json.JSONDecodeError) as err:
            last_error = err

        time.sleep(0.25)

    log_content = ''
    try:
        log_content = Path(log_path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        pass
    raise TimeoutError(
        f'Backend on port {port} failed to become healthy within {timeout:.1f}s. Last error: {last_error}\n'
        f'Server logs:\n{log_content[-2000:]}'
    )


def http_request(port, path, token=None, timeout=HTTP_TIMEOUT):
    """Execute an HTTP GET request against the local backend server."""
    url = f'http://127.0.0.1:{port}{path}'
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read().decode('utf-8')
            return response.status, json.loads(body), body
    except HTTPError as err:
        body = err.read().decode('utf-8')
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = body
        return err.code, parsed, body


# --------------------------------------------------------------------------- #
# Test Cases
# --------------------------------------------------------------------------- #

def test_live_startup_valid_configuration(tmp_path):
    """Case A: Valid API token and existing allowed root.

    - Real backend process starts and listens on loopback.
    - /api/health returns HTTP 200.
    - Gitleaks reports runtime status 'configured' with roots 1/1.
    - The configured allowed root is recognized.
    - Startup banner displays without exposing the token value.
    - Unauthenticated requests are rejected (HTTP 401).
    - Wapiti remains safety-gated (disabled/missing, not verified).
    """
    data_dir = tmp_path / 'data'
    allowed_root = tmp_path / 'authorized_root'
    allowed_root.mkdir(parents=True, exist_ok=True)
    log_path = tmp_path / 'backend.log'

    port = free_port()
    synthetic_token = SYNTHETIC_TOKEN_PREFIX + secrets.token_hex(16)

    env = clean_subprocess_env({
        'AVA_PORT': str(port),
        'AVA_DATA_DIR': str(data_dir),
        'AVA_API_TOKEN': synthetic_token,
        'AVA_ALLOWED_LOCAL_ROOTS': str(allowed_root),
        'AVA_ALLOWED_TARGETS': '127.0.0.1',
        'AVA_ALLOW_PRIVATE_TARGETS': 'true',
    })

    with managed_live_backend(env, log_path, entrypoint='backend') as proc:
        health_data = wait_for_backend_health(port, proc, log_path)
        assert health_data['data']['status'] == 'ok'
        assert health_data['data']['scanning_enabled'] is True

        # Unauthenticated request fails with 401
        status_unauth, unauth_body, _ = http_request(port, '/api/tools')
        assert status_unauth == 401
        assert unauth_body.get('error', {}).get('code') == 'unauthorized'

        # Invalid token request fails with 401
        status_bad, bad_body, _ = http_request(port, '/api/tools', token='invalid-' + 'y' * 32)
        assert status_bad == 401
        assert bad_body.get('error', {}).get('code') == 'unauthorized'

        # Authenticated request succeeds
        status_auth, auth_body, _ = http_request(port, '/api/tools', token=synthetic_token)
        assert status_auth == 200
        tools = auth_body.get('data', [])
        assert len(tools) > 0

        # Gitleaks runtime configuration check
        gitleaks = next((t for t in tools if t['name'] == 'gitleaks'), None)
        assert gitleaks is not None, 'Gitleaks adapter missing from inventory'
        runtime = gitleaks.get('runtime_configuration', {})
        assert runtime.get('status') == 'configured'
        assert runtime.get('roots_configured') == 1
        assert runtime.get('roots_usable') == 1
        assert 'exact existing local directory' in runtime.get('message', '')

        # Wapiti safety gate verification: Wapiti must remain safety-gated (never integration_ready)
        wapiti = next((t for t in tools if t['name'] == 'wapiti'), None)
        assert wapiti is not None, 'Wapiti adapter missing from inventory'
        assert wapiti.get('status') in {'disabled', 'missing', 'unverified'}
        assert wapiti.get('integration_ready') is False

    # Log inspection after shutdown
    log_text = log_path.read_text(encoding='utf-8', errors='replace')
    assert 'PATROLMAN' in log_text
    assert 'Status: RUNNING' in log_text
    assert f'Local URL: http://127.0.0.1:{port}' in log_text
    assert f'Port: {port}' in log_text
    assert 'bearer token required' not in log_text
    assert synthetic_token not in log_text


def test_live_startup_missing_token_fails_safely(tmp_path):
    """Case B: Missing API token.

    - Startup fails immediately with exit code 1.
    - Actionable configuration error is reported to stderr.
    - No traceback is emitted.
    - Token value is never displayed or leaked.
    - Backend does not bind or bypass authentication.
    """
    data_dir = tmp_path / 'data'
    port = free_port()

    env = clean_subprocess_env({
        'AVA_PORT': str(port),
        'AVA_DATA_DIR': str(data_dir),
        'AVA_REQUIRE_API_TOKEN': 'true',
    })

    result = subprocess.run(
        [PYTHON_EXECUTABLE, '-m', 'backend'],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )

    assert result.returncode == 1
    stderr = result.stderr
    assert 'PATROLMAN configuration error: AVA_API_TOKEN is not set' in stderr
    assert 'Start-Patrolman.ps1 -SetupCredential' in stderr
    assert '.env' in stderr
    assert 'never displayed' in stderr

    # No traceback or source leakage
    assert 'Traceback (most recent call last):' not in stderr
    assert 'Traceback' not in stderr
    assert 'File "' not in stderr

    # No banner output was printed to stdout
    assert 'Status: RUNNING' not in result.stdout

    # Authentication is not bypassed: port is not listening
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.5)
        probe.connect(('127.0.0.1', port))
        assert False, f'Port {port} unexpectedly accepted connection!'
    except OSError:
        pass
    finally:
        probe.close()


def test_live_startup_invalid_or_deleted_root(tmp_path):
    """Case C: Invalid or deleted allowed root.

    - Backend starts safely without crashing.
    - /api/health returns HTTP 200.
    - Gitleaks reports runtime status 'configuration_required' (roots 1/0).
    - The missing/deleted filesystem path is never exposed in API responses or logs.
    """
    data_dir = tmp_path / 'data'
    deleted_root = tmp_path / 'deleted_secret_local_root'
    # Ensure directory does not exist
    if deleted_root.exists():
        deleted_root.rmdir()
    log_path = tmp_path / 'backend.log'

    port = free_port()
    synthetic_token = SYNTHETIC_TOKEN_PREFIX + secrets.token_hex(16)

    env = clean_subprocess_env({
        'AVA_PORT': str(port),
        'AVA_DATA_DIR': str(data_dir),
        'AVA_API_TOKEN': synthetic_token,
        'AVA_ALLOWED_LOCAL_ROOTS': str(deleted_root),
        'AVA_ALLOWED_TARGETS': '127.0.0.1',
        'AVA_ALLOW_PRIVATE_TARGETS': 'true',
    })

    with managed_live_backend(env, log_path, entrypoint='backend') as proc:
        health_data = wait_for_backend_health(port, proc, log_path)
        assert health_data['data']['status'] == 'ok'

        status_auth, auth_body, raw_response = http_request(
            port, '/api/tools', token=synthetic_token
        )
        assert status_auth == 200
        tools = auth_body.get('data', [])

        gitleaks = next((t for t in tools if t['name'] == 'gitleaks'), None)
        assert gitleaks is not None
        assert gitleaks.get('state') == 'CONFIGURATION_REQUIRED'
        assert gitleaks.get('integration_ready') is False

        runtime = gitleaks.get('runtime_configuration', {})
        assert runtime.get('status') == 'configuration_required'
        assert runtime.get('roots_configured') == 1
        assert runtime.get('roots_usable') == 0
        assert 'cannot be used' in runtime.get('message', '')

        # The path must not be exposed in public API output or logs
        assert str(deleted_root) not in raw_response
        assert deleted_root.name not in raw_response

    log_text = log_path.read_text(encoding='utf-8', errors='replace')
    assert str(deleted_root) not in log_text
    assert deleted_root.name not in log_text
    assert synthetic_token not in log_text


def test_live_startup_durable_configuration_file(tmp_path):
    """Case D: Durable configuration via AVA_ENV_FILE (.env workflow).

    - Fresh backend process loads configuration from a file.
    - Inherited runner environment variables are isolated and not relied upon.
    - Loaded token and local roots take effect in the live running process.
    - /api/health and authenticated /api/tools succeed.
    """
    env_file_path = tmp_path / 'patrolman.env'
    data_dir = tmp_path / 'durable_data'
    allowed_root = tmp_path / 'durable_root'
    allowed_root.mkdir(parents=True, exist_ok=True)
    log_path = tmp_path / 'backend.log'

    port = free_port()
    synthetic_token = SYNTHETIC_TOKEN_PREFIX + secrets.token_hex(16)

    # Write documented .env format
    env_content = (
        '# PATROLMAN durable configuration\n'
        f'AVA_PORT={port}\n'
        f'AVA_DATA_DIR="{data_dir}"\n'
        f'AVA_API_TOKEN="{synthetic_token}"\n'
        f'AVA_ALLOWED_LOCAL_ROOTS="{allowed_root}"\n'
    )
    env_file_path.write_text(env_content, encoding='utf-8')

    # Start a fresh backend with ONLY AVA_ENV_FILE set (no other AVA_* in env)
    env = clean_subprocess_env({
        'AVA_ENV_FILE': str(env_file_path),
    })
    # Verify no other AVA_* variables exist in env
    assert not any(k.startswith('AVA_') and k != 'AVA_ENV_FILE' for k in env)

    with managed_live_backend(env, log_path, entrypoint='backend.app') as proc:
        health_data = wait_for_backend_health(port, proc, log_path)
        assert health_data['data']['status'] == 'ok'

        # Authenticate with the token loaded from file
        status_auth, auth_body, _ = http_request(
            port, '/api/tools', token=synthetic_token
        )
        assert status_auth == 200
        tools = auth_body.get('data', [])

        gitleaks = next((t for t in tools if t['name'] == 'gitleaks'), None)
        assert gitleaks is not None
        runtime = gitleaks.get('runtime_configuration', {})
        assert runtime.get('status') == 'configured'
        assert runtime.get('roots_configured') == 1
        assert runtime.get('roots_usable') == 1

        # Unauthenticated request still fails
        status_unauth, _, _ = http_request(port, '/api/tools')
        assert status_unauth == 401

    log_text = log_path.read_text(encoding='utf-8', errors='replace')
    assert f'loaded 4 AVA_* setting(s) from {env_file_path}' in log_text
    assert synthetic_token not in log_text


if __name__ == '__main__':
    sys.exit(pytest.main(['-v', __file__]))
