"""Approved-binary digest pinning tests.

The point of the pin is that a binary whose SHA-256 differs from the recorded
digest is never executed, and that PATROLMAN never downloads or replaces a binary.
All checks here are pure file hashing on temporary files, so no untrusted binary
is ever run — the tests exercise the verification path, not a scanner.
"""
import hashlib
import json
from pathlib import Path

import pytest

from backend.services import integrity
from backend.services.integrity import (approved_digest, blocks_execution, load_manifest,
                                        sha256_file, verify_digest)

CONTENT = b'PATROLMAN synthetic binary payload \x00\x01\x02 not a real executable\n'
DIGEST = hashlib.sha256(CONTENT).hexdigest()


@pytest.fixture
def pinned(tmp_path):
    """A manifest pinning tool 'synthetic' to DIGEST, plus the artifact on disk."""
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(CONTENT)
    manifest = tmp_path / 'approved_binaries.json'
    manifest.write_text(json.dumps({'synthetic': {'sha256': DIGEST, 'release': 'fixture'}}), encoding='utf-8')
    return {'artifact': artifact, 'manifest': manifest}


# --- 1. Matching digest ------------------------------------------------------

def test_matching_digest_verifies(pinned):
    result = verify_digest('synthetic', str(pinned['artifact']), override=str(pinned['manifest']))
    assert result['status'] == 'verified'
    assert result['expected'] == result['actual'] == DIGEST
    assert blocks_execution(result['status']) is False
    assert approved_digest('synthetic', override=str(pinned['manifest'])) == DIGEST


def test_sha256_streams_and_matches_hashlib(tmp_path):
    """Chunked hashing must agree with a whole-file hash, including multi-chunk files."""
    blob = (b'x' * (1024 * 1024)) + b'tail'
    target = tmp_path / 'large.bin'
    target.write_bytes(blob)
    assert sha256_file(target) == hashlib.sha256(blob).hexdigest()
    assert sha256_file(target, chunk=7) == hashlib.sha256(blob).hexdigest()


def test_uppercase_manifest_digest_is_accepted(tmp_path):
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(CONTENT)
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'synthetic': {'sha256': DIGEST.upper()}}), encoding='utf-8')
    assert verify_digest('synthetic', str(artifact), override=str(manifest))['status'] == 'verified'


def test_a_list_executable_hashes_the_artifact(tmp_path):
    """Script-plus-interpreter resolution pins the script, not the interpreter."""
    artifact = tmp_path / 'scanner.pl'
    artifact.write_bytes(CONTENT)
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'synthetic': {'sha256': DIGEST}}), encoding='utf-8')
    result = verify_digest('synthetic', ['C:/perl/bin/perl.exe', str(artifact)], override=str(manifest))
    assert result['status'] == 'verified' and result['actual'] == DIGEST


# --- 2. Mismatching digest ---------------------------------------------------

def test_mismatching_digest_is_refused(tmp_path):
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(b'different content entirely')
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'synthetic': {'sha256': DIGEST}}), encoding='utf-8')
    result = verify_digest('synthetic', str(artifact), override=str(manifest))
    assert result['status'] == 'mismatch'
    assert result['expected'] == DIGEST and result['actual'] != DIGEST
    assert blocks_execution(result['status']) is True
    assert 'refused' in result['message']
    # The refusal explicitly disclaims any download or replacement behaviour.
    assert 'never replaces or downloads' in result['message']


def test_tampered_binary_is_detected(tmp_path):
    """A single flipped byte in an otherwise matching artifact must not verify."""
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(CONTENT)
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'synthetic': {'sha256': DIGEST}}), encoding='utf-8')
    assert verify_digest('synthetic', str(artifact), override=str(manifest))['status'] == 'verified'
    artifact.write_bytes(CONTENT + b' ')
    assert verify_digest('synthetic', str(artifact), override=str(manifest))['status'] == 'mismatch'


# --- 3. Missing binary -------------------------------------------------------

def test_missing_binary_is_reported_and_blocks(tmp_path):
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'synthetic': {'sha256': DIGEST}}), encoding='utf-8')
    result = verify_digest('synthetic', str(tmp_path / 'absent.exe'), override=str(manifest))
    assert result['status'] == 'missing' and blocks_execution(result['status']) is True
    assert result['expected'] == DIGEST
    # A pinned tool with no configured path is also missing, not silently fine.
    assert verify_digest('synthetic', None, override=str(manifest))['status'] == 'missing'


# --- 4. Verification failure -------------------------------------------------

def test_unreadable_binary_is_an_error_and_blocks(tmp_path, monkeypatch):
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(CONTENT)
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'synthetic': {'sha256': DIGEST}}), encoding='utf-8')
    def unreadable(path, chunk=integrity.CHUNK):
        raise PermissionError('denied')
    monkeypatch.setattr(integrity, 'sha256_file', unreadable)
    result = verify_digest('synthetic', str(artifact), override=str(manifest))
    assert result['status'] == 'error' and blocks_execution(result['status']) is True
    assert 'could not be hashed' in result['message']


@pytest.mark.parametrize('payload', ['{not json', '[]', '"string"', 'null'])
def test_corrupt_manifest_fails_closed(tmp_path, payload):
    """A broken integrity control refuses execution instead of silently disabling itself."""
    manifest = tmp_path / 'm.json'
    manifest.write_text(payload, encoding='utf-8')
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(CONTENT)
    result = verify_digest('synthetic', str(artifact), override=str(manifest))
    assert result['status'] == 'error' and blocks_execution(result['status']) is True
    assert 'manifest' in result['message']
    with pytest.raises(ValueError):
        load_manifest(override=str(manifest))


# --- 5. Unpinned tools keep working -----------------------------------------

def test_absent_manifest_leaves_tools_unpinned(tmp_path):
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(CONTENT)
    result = verify_digest('synthetic', str(artifact), override=str(tmp_path / 'no-manifest.json'))
    assert result['status'] == 'unpinned'
    assert result['expected'] is None and blocks_execution(result['status']) is False


def test_tool_absent_from_a_manifest_is_unpinned(tmp_path):
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'other-tool': {'sha256': DIGEST}}), encoding='utf-8')
    artifact = tmp_path / 'synthetic.exe'
    artifact.write_bytes(CONTENT)
    assert verify_digest('synthetic', str(artifact), override=str(manifest))['status'] == 'unpinned'
    assert verify_digest('unrelated', 'C:/missing/tool.exe', override=str(manifest))['status'] == 'unpinned'
    assert verify_digest('unrelated', None, override=str(manifest))['status'] == 'unpinned'


def test_comment_keys_are_not_treated_as_tools(tmp_path):
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps({'$comment': 'explanation', 'synthetic': {'sha256': DIGEST}}), encoding='utf-8')
    entries = load_manifest(override=str(manifest))
    assert set(entries) == {'synthetic'}


def test_verification_module_cannot_download_or_execute():
    """A policy guard: the integrity module performs no network or process I/O."""
    source = Path(integrity.__file__).read_text(encoding='utf-8')
    for forbidden in ('urllib', 'requests', 'httplib', 'socket', 'subprocess', 'urlretrieve', 'Popen'):
        assert forbidden not in source, forbidden


# --- 6. The shipped manifest for the approved binary ------------------------

def test_shipped_manifest_pins_subfinder_and_excludes_retired_nikto():
    entries = load_manifest()
    assert entries['subfinder']['sha256'] == '163c509636aaea3d333c5f3119fd9152cf661d7aef7212522509c14aa20475c6'
    assert entries['subfinder']['archive_sha256'] == 'a3fd612928d591fb31c1e59a2e06055e364421ba32251e553073f5673a2d3103'
    # Nikto is retired from the active project: it has no manifest entry at all,
    # so no digest is or can be approved for it here.
    assert 'nikto' not in entries
    assert approved_digest('nikto') is None
