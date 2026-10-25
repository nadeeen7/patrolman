"""Real HTTP + SQLite + report smoke test. Uses no synthetic scanner results."""
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


PORT = int(os.environ.get('AVA_PORT', '5055'))


class _Workspace:
    """Temporary data directory that tolerates the Windows handle-release delay.

    A terminated process releases its SQLite files a moment later, so an
    immediate rmtree fails on Windows. Retry, but still raise if it never clears.
    """

    def __init__(self, prefix=''):
        self.name = tempfile.mkdtemp(prefix=prefix)

    def __enter__(self):
        return self.name

    def __exit__(self, *_error):
        deadline = time.monotonic() + 10
        while True:
            try:
                shutil.rmtree(self.name)
            except FileNotFoundError:
                return False
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.1)
            else:
                return False


def main():
    if not Path('frontend/dist/index.html').is_file():
        raise SystemExit('Build the frontend before running this verification.')
    with _Workspace('ava-live-') as directory:
        token = secrets.token_urlsafe(32)
        env = dict(os.environ, AVA_API_TOKEN=token, AVA_DATA_DIR=directory,
                   AVA_ALLOWED_TARGETS='127.0.0.1', AVA_ALLOW_PRIVATE_TARGETS='true',
                   AVA_PORT=str(PORT))
        process = subprocess.Popen([sys.executable, '-m', 'backend'], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def request(path, body=None, headers=None):
            merged = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
            merged.update(headers or {})
            data = json.dumps(body).encode() if body is not None else None
            with urlopen(Request(f'http://127.0.0.1:{PORT}' + path, data=data, headers=merged), timeout=30) as response:
                return response.status, response.read()
        try:
            for _ in range(100):
                if process.poll() is not None: raise RuntimeError(f'Backend exited; ensure port {PORT} is free.')
                try:
                    request('/api/health'); break
                except URLError: time.sleep(.05)
            else: raise RuntimeError('Readiness timeout.')
            status, html = request('/')
            assert status == 200 and b'/assets/' in html
            status, tools = request('/api/tools')
            inventory = json.loads(tools)['data']
            # No external target is ever selected. If tools exist, only loopback is assessed.
            status, response = request('/api/scans', {'target':'127.0.0.1', 'profile':'quick', 'authorized':True},
                                       {'Idempotency-Key':'live-workflow-verification-001'})
            assert status == 202
            scan_id = json.loads(response)['data']['id']
            for _ in range(2000):
                _, response = request('/api/scans/' + scan_id)
                scan = json.loads(response)['data']
                if scan['state'] in {'completed','completed_with_errors','failed','cancelled'}: break
                time.sleep(.1)
            else: raise RuntimeError('Scan timeout.')
            if all(not item['executable_found'] for item in inventory):
                assert scan['state'] == 'failed'
                assert all(item['state'] == 'unavailable' for item in scan['executions'])
            for format_name in ('html', 'json', 'vulnerabilities'):
                status, output = request('/api/scans/' + scan_id + '/report?format=' + format_name)
                assert status == 200 and output
            report = next(Path(directory).glob('reports/*/*/report.html')).read_text()
            assert 'Executive summary' in report and '127.0.0.1' in report and 'Limitations' in report
            assert len(list(Path(directory).glob('reports/*/*/*.json'))) == 2
            # sqlite3's context manager commits but never closes, which would keep
            # the database locked against the workspace cleanup below.
            connection = sqlite3.connect(Path(directory) / 'assessment.sqlite3')
            try:
                assert connection.execute('SELECT state FROM scans WHERE id=?', (scan_id,)).fetchone()[0] == scan['state']
            finally:
                connection.close()
            print('PASS: built SPA, real HTTP scan workflow, SQLite persistence, and three authenticated reports.')
            print('Actual scan state:', scan['state'])
            print('Actual tool states:', ', '.join(e['tool'] + '=' + e['state'] for e in scan['executions']))
            print('No simulated findings inserted. HTML structure inspected; visual browser review not performed.')
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill();process.wait()


if __name__ == '__main__':
    main()
