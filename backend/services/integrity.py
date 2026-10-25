"""Approved-binary digest pinning: hash the file, never execute, never download.

PATROLMAN records the SHA-256 of an approved scanner binary in
`backend/approved_binaries.json` and verifies the file on disk against it before
any execution. The module is pure file I/O, so it is fully testable without ever
running the binary it is checking.

Failure policy, chosen deliberately:

* no manifest, or no entry for the tool  -> `unpinned`; the tool runs and the
  inventory reports that it is unpinned, so nothing is silently "verified";
* entry present and digest matches       -> `verified`;
* entry present and digest differs       -> `mismatch`; execution is refused;
* entry present but the binary is absent -> `missing`; execution is refused as
  unavailable;
* entry present and the file cannot be read, or the manifest is unreadable or
  malformed -> `error`; execution is refused. A corrupt integrity control must
  fail closed rather than quietly stop protecting anything.
"""
import hashlib
import json
import os
from pathlib import Path

MANIFEST_ENV = 'AVA_APPROVED_BINARIES'
DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / 'approved_binaries.json'
CHUNK = 1024 * 1024


def manifest_path(override=None):
    if override:
        return Path(override)
    configured = os.getenv(MANIFEST_ENV)
    return Path(configured) if configured else DEFAULT_MANIFEST


def load_manifest(override=None):
    """Return the manifest mapping, or raise ValueError if it exists but is broken."""
    path = manifest_path(override)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ValueError(f'Integrity manifest could not be read: {type(exc).__name__}.') from None
    if not isinstance(data, dict):
        raise ValueError('Integrity manifest must be a JSON object.')
    return {key: value for key, value in data.items() if not key.startswith('$')}


def approved_digest(tool, override=None):
    """The pinned digest for a tool, or None when unpinned. Raises on a broken manifest."""
    entries = load_manifest(override)
    if not entries:
        return None
    entry = entries.get(tool)
    if not isinstance(entry, dict):
        return None
    digest = entry.get('sha256')
    return digest.lower() if isinstance(digest, str) and digest else None


def sha256_file(path, chunk=CHUNK):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def verify_digest(tool, executable, override=None):
    """Verify one binary. Returns a dict with status/expected/actual/message.

    `executable` may be a path string, a list (script plus interpreter, in which
    case only the last element is treated as the artifact), or None.
    """
    def result(status, message, expected=None, actual=None):
        return {'tool': tool, 'status': status, 'expected': expected, 'actual': actual, 'message': message}

    if isinstance(executable, (list, tuple)):
        executable = executable[-1] if executable else None
    try:
        expected = approved_digest(tool, override)
    except ValueError as exc:
        return result('error', f'{exc} Execution refused until the manifest is readable.')
    if executable is None:
        return result('unpinned' if expected is None else 'missing',
                      'No executable is configured for this tool.' if expected is None
                      else 'A pinned digest is recorded but the binary is not present.', expected)
    path = Path(executable)
    if expected is None:
        return result('unpinned', 'No approved digest is recorded for this tool, so it runs unpinned.')
    if not path.is_file():
        return result('missing', 'A pinned digest is recorded but the binary is not present.', expected)
    try:
        actual = sha256_file(path)
    except OSError as exc:
        return result('error', f'The binary could not be hashed ({type(exc).__name__}); execution refused.', expected)
    if actual != expected:
        return result('mismatch', 'Binary digest does not match the approved digest; execution refused. '
                                 'PATROLMAN never replaces or downloads a binary.', expected, actual)
    return result('verified', 'Binary digest matches the approved digest.', expected, actual)


def blocks_execution(status):
    """Only these statuses stop a run; `unpinned` is reported but does not block."""
    return status in {'mismatch', 'missing', 'error'}
