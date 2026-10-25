"""Optional project `.env` for AVA_* settings; the process environment wins.

The project already ships `backend/.env.example` and git-ignores `.env`, but
nothing ever loaded that file: every AVA_* value had to be exported in the
PowerShell window that started the backend. Restarting in a fresh window
therefore lost AVA_API_TOKEN (startup refused) and AVA_ALLOWED_LOCAL_ROOTS
(Gitleaks reported configuration_required despite a documented setup).

This loader reads one plain file and only adds AVA_* keys that are not already
set. Rules, in order of importance:

* Only AVA_* names are accepted, so a file can never set PATH, PYTHONPATH or
  any other interpreter-affecting variable.
* An exported value is never overridden; a process environment explicitly
  prepared by the operator (or by Start-Patrolman.ps1 / Windows Credential
  Manager) always takes precedence.
* Values are never returned by the summary, printed or logged.
* Anything that is not a regular, bounded file is refused rather than read.
"""
import os
import re
import stat
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = PROJECT_ROOT / '.env'
MAX_BYTES = 64 * 1024
MAX_VALUE = 4096
KEY = re.compile(r'^AVA_[A-Z0-9_]+$')


def _decode(raw):
    """Tolerate the encodings Windows editors actually produce."""
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        return raw.decode('utf-16')
    return raw.decode('utf-8-sig')


def parse(text):
    """Return ({key: value}, rejected_line_count) for `.env` content.

    Blank lines and `#` comments are skipped, a leading `export ` is accepted,
    and one surrounding pair of matching quotes is removed. No interpolation,
    no multiline values and no key expansion: the value is taken literally.
    """
    values = {}
    rejected = 0
    for row in text.splitlines():
        line = row.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[len('export '):].strip()
        key, separator, value = line.partition('=')
        key = key.strip()
        if not separator or not KEY.match(key):
            rejected += 1
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if not value or len(value) > MAX_VALUE or '\0' in value or '\n' in value:
            rejected += 1
            continue
        values[key] = value
    return values, rejected


def load(path=None):
    """Load the project `.env` once, adding only AVA_* variables still unset.

    Returns a value-free summary so a caller can tell whether a file was read
    without handling its contents. Never raises: an unreadable or malformed
    file leaves the process environment untouched.
    """
    target = Path(path or os.getenv('AVA_ENV_FILE') or DEFAULT_ENV_FILE)
    summary = {'path': None, 'loaded': 0, 'skipped': 0, 'rejected': 0, 'error': None}
    try:
        info = target.lstat()
    except OSError:
        return summary
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        summary['error'] = 'The .env path is a link or reparse point; it was not read.'
        return summary
    if not stat.S_ISREG(info.st_mode):
        summary['error'] = 'The .env path is not a regular file; it was not read.'
        return summary
    if info.st_size > MAX_BYTES:
        summary['error'] = f'The .env file exceeds {MAX_BYTES} bytes; it was not read.'
        return summary
    try:
        raw = target.read_bytes()
    except OSError as error:
        summary['error'] = f'The .env file could not be read ({error.__class__.__name__}); it was ignored.'
        return summary
    values, rejected = parse(_decode(raw))
    summary.update(path=str(target), rejected=rejected)
    for key, value in values.items():
        if key in os.environ:
            summary['skipped'] += 1
            continue
        os.environ[key] = value
        summary['loaded'] += 1
    return summary
