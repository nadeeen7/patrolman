"""Loopback-only Flask child for the end-to-end authentication test.

Started by ``backend/tests/test_auth_e2e.py`` with:

- ``AVA_DATA_DIR`` pointing at a temporary test database (never the project's
  ``data`` directory, which is refused below),
- ``AVA_PORT`` bound to an exclusively allocated loopback port,
- ``AVA_E2E_DIAG`` pointing at a JSONL file this runner appends to.

The runner otherwise uses ``Settings.from_env()`` exactly like the production
server, so the E2E test exercises the real application factory, real routes and
real SQLite storage.

Each request appends one line recording only non-sensitive diagnostics:

    method, path, host (the Host header Flask received), origin, whether an
    X-CSRF-Token header was present (a boolean, never the value), the response
    status and the error code (never the message).

Cookies, CSRF tokens, passwords, bearer tokens and hashes are never written.
"""
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RECORD_FIELDS = (
    'method',
    'path',
    'host',
    'origin',
    'csrf_header_present',
    'status',
    'error_code',
)


def main():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    from flask import request

    from backend.app import create_app
    from backend.config import Settings
    from backend.server import HOST, make_server, port_available

    settings = Settings.from_env()
    settings.validate()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    # Refuse to run the test backend against the project's production data.
    if settings.data_dir == (PROJECT_ROOT / 'data').resolve():
        raise SystemExit('E2E backend refuses to use the project data directory; set AVA_DATA_DIR.')
    diag_path = os.environ.get('AVA_E2E_DIAG', '')

    if not port_available(HOST, settings.port):
        raise SystemExit(f'E2E backend port {settings.port} is already in use.')

    app = create_app(settings)

    @app.after_request
    def record_diagnostics(response):
        if diag_path:
            error_code = None
            if response.status_code >= 400:
                try:
                    payload = response.get_json()
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    error = payload.get('error')
                    if isinstance(error, dict):
                        error_code = error.get('code')
            record = {
                'method': request.method,
                'path': request.path,
                'host': request.host,
                'origin': request.headers.get('Origin'),
                'csrf_header_present': bool(request.headers.get('X-CSRF-Token')),
                'status': response.status_code,
                'error_code': error_code,
            }
            with open(diag_path, 'a', encoding='utf-8') as handle:
                handle.write(json.dumps(record) + '\n')
                handle.flush()
        return response

    server = make_server(HOST, settings.port, app, threaded=True)
    print(f'E2E_BACKEND_READY {HOST}:{settings.port}', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


if __name__ == '__main__':
    main()
