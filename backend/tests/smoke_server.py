"""Loopback HTTP smoke check. No scanning and no external traffic.

`/api/tools` runs scanner version checks when executables are installed, so the
requests below are allowed a generous bound.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen
from urllib.error import URLError


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
    with _Workspace() as directory:
        token = secrets.token_urlsafe(32)
        environment = dict(os.environ, AVA_API_TOKEN=token, AVA_DATA_DIR=directory,
                           AVA_ALLOWED_TARGETS='127.0.0.1', AVA_ALLOW_PRIVATE_TARGETS='true',
                           AVA_PORT=str(PORT))
        process = subprocess.Popen([sys.executable, '-m', 'backend.app'], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError('Server exited before becoming ready')
                try:
                    with urlopen(f'http://127.0.0.1:{PORT}/api/health', timeout=1) as response:
                        assert json.load(response)['data']['status'] == 'ok'
                    break
                except URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('Server readiness timed out')
            for path, payload in [('/api/tools', None), ('/api/targets/validate', {'target': '127.0.0.1'})]:
                request = Request(f'http://127.0.0.1:{PORT}' + path,
                                  data=json.dumps(payload).encode() if payload else None,
                                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
                with urlopen(request, timeout=60) as response:
                    assert response.status == 200
                    assert 'data' in json.load(response)
            print('PASS: live Flask health, authenticated tools, loopback target validation')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
