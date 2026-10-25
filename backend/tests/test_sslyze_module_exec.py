"""Regression tests for SSLyze module-based execution and version detection.

These tests cover:
- Version detection via importlib.metadata (SSLyze 6.x has no --version flag)
- Module-based invocation resolution: [python_exe, '-m', 'sslyze']
- Policy-block failure handling when the console-script .exe is refused
- Timeout and cancellation safeguards remain effective
- Valid and malformed scan report parsing
- Successful workflow execution path
- configure_tool_environment skips MODULE_BASED adapters
"""
import json
import sys
import threading
from pathlib import Path

import pytest

from backend.integrations import sslyze as sslyze_adapter
from backend.services import executables, tool_manager
from backend.services.process_runner import ProcessResult


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def test_parse_version_reads_importlib_metadata(monkeypatch):
    """parse_version() reads from importlib.metadata, not from CLI output."""
    import importlib.metadata as meta

    # Patch the installed metadata so the test is deterministic and isolated.
    monkeypatch.setattr(meta, 'version', lambda name: '6.3.1' if name == 'sslyze' else meta.version(name))

    # The 'output' argument is the --help text; version must NOT come from it.
    version = sslyze_adapter.parse_version('some --help output without a version line')
    assert version == '6.3.1'


def test_parse_version_falls_back_to_help_text_when_metadata_missing(monkeypatch):
    """If importlib.metadata raises, the fallback parses 'SSLyze version X.Y.Z'."""
    import importlib.metadata as meta

    def raise_not_found(name):
        raise meta.PackageNotFoundError(name)

    monkeypatch.setattr(meta, 'version', raise_not_found)

    help_text = 'SSLyze version 6.3.1\nusage: sslyze ...'
    version = sslyze_adapter.parse_version(help_text)
    assert version == '6.3.1'


def test_parse_version_returns_none_when_both_sources_unavailable(monkeypatch):
    """Returns None rather than crashing when neither metadata nor help text has a version."""
    import importlib.metadata as meta

    monkeypatch.setattr(meta, 'version', lambda _: (_ for _ in ()).throw(meta.PackageNotFoundError('sslyze')))

    version = sslyze_adapter.parse_version('no version string here')
    assert version is None


# ---------------------------------------------------------------------------
# matches_identity
# ---------------------------------------------------------------------------

def test_matches_identity_accepts_sslyze_help_output():
    """matches_identity() returns True for the real --help banner."""
    output = 'SSLyze version 6.3.1\nusage: sslyze ...'
    assert sslyze_adapter.matches_identity(output) is True


def test_matches_identity_rejects_unrelated_output():
    """matches_identity() returns False when the SSLyze product word is absent."""
    assert sslyze_adapter.matches_identity('some other tool v1.2') is False
    assert sslyze_adapter.matches_identity('') is False


# ---------------------------------------------------------------------------
# Module-based executable resolution
# ---------------------------------------------------------------------------

def test_sslyze_resolves_to_module_invocation_not_exe(monkeypatch):
    """find_argv(sslyze.COMMANDS) must return [python, '-m', 'sslyze'], not the .exe."""
    # Ensure no operator override and that sslyze module is importable.
    monkeypatch.delenv('AVA_SSLYZE_PATH', raising=False)
    monkeypatch.setattr(executables.shutil, 'which', lambda *a, **k: None)

    result = executables.find_argv(sslyze_adapter.COMMANDS)

    assert isinstance(result, list), 'Expected a list [python, -m, sslyze]'
    expected_pythons = {sys.executable, executables._venv_python_executable()}
    assert result[0] in expected_pythons
    assert result[1] == '-m'
    assert result[2] == 'sslyze'


def test_sslyze_module_resolution_is_prioritised_over_exe_on_path(monkeypatch, tmp_path):
    """Even when sslyze.exe is on PATH, module invocation is returned."""
    fake_exe = tmp_path / 'sslyze.exe'
    fake_exe.write_bytes(b'placeholder')
    monkeypatch.delenv('AVA_SSLYZE_PATH', raising=False)
    # Pretend shutil.which finds the .exe.
    monkeypatch.setattr(executables.shutil, 'which', lambda cmd, **k: str(fake_exe) if 'sslyze' in cmd else None)

    result = executables.find_argv(sslyze_adapter.COMMANDS)

    assert isinstance(result, list)
    expected_pythons = {sys.executable, executables._venv_python_executable()}
    assert result[0] in expected_pythons, 'Python interpreter must be used, not the .exe'


def test_operator_override_is_honoured_for_sslyze(monkeypatch, tmp_path):
    """AVA_SSLYZE_PATH still takes precedence over the module fallback."""
    approved = tmp_path / 'sslyze-approved.exe'
    approved.write_bytes(b'approved binary')
    monkeypatch.setenv('AVA_SSLYZE_PATH', str(approved))
    # MODULE_BASED check is skipped when override is present.
    monkeypatch.setattr(executables.shutil, 'which', lambda *a, **k: None)

    result = executables.find_argv(sslyze_adapter.COMMANDS)
    # The override resolves to the approved file.
    assert result == str(approved.resolve())


def test_sslyze_reports_missing_when_module_not_importable(monkeypatch):
    """find_argv returns None when sslyze is not installed in the environment."""
    monkeypatch.delenv('AVA_SSLYZE_PATH', raising=False)
    monkeypatch.setattr(executables.shutil, 'which', lambda *a, **k: None)

    # Simulate sslyze not being importable.
    import importlib
    original_import = importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name == 'sslyze':
            raise ImportError('sslyze not installed')
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, 'import_module', fake_import)

    result = executables.find_argv(sslyze_adapter.COMMANDS)
    assert result is None


# ---------------------------------------------------------------------------
# configure_tool_environment skips MODULE_BASED adapters
# ---------------------------------------------------------------------------

def test_configure_tool_environment_does_not_store_module_name_for_sslyze(monkeypatch):
    """configure_tool_environment must NOT write AVA_SSLYZE_PATH for MODULE_BASED tools."""
    from backend.integrations import ADAPTERS

    monkeypatch.delenv('AVA_SSLYZE_PATH', raising=False)
    # Stub out find_argv so it doesn't actually probe the filesystem.
    monkeypatch.setattr(executables, 'find_argv', lambda commands: None)
    monkeypatch.setattr('backend.integrations.trivy.discover_cache', lambda: None)

    executables.configure_tool_environment()

    assert 'AVA_SSLYZE_PATH' not in __import__('os').environ, (
        'AVA_SSLYZE_PATH must not be set for MODULE_BASED adapters; '
        'the module name string would confuse the native-path resolver.'
    )


# ---------------------------------------------------------------------------
# Policy-block failure handling
# ---------------------------------------------------------------------------

def test_policy_blocked_exe_produces_blocked_status(monkeypatch):
    """When the .exe is blocked by policy, diagnose returns ('blocked', ...) status."""
    # Simulate a policy-blocked launch: process_runner returns state='blocked'.
    blocked_result = ProcessResult(
        state='blocked',
        stderr='An Application Control policy has blocked this file',
        exit_code=None,
    )
    monkeypatch.setattr(tool_manager, 'run', lambda *a, **k: blocked_result)

    valid, version, status, reason = tool_manager.diagnose(
        'sslyze', [sys.executable, '-m', 'sslyze']
    )

    assert status == 'blocked'
    assert valid is False
    assert version is None


def test_timeout_during_sslyze_probe_produces_unknown_status(monkeypatch):
    """A probe that times out is classified as 'unknown', not 'blocked' or 'ready'."""
    timed_out = ProcessResult(state='timed_out', stderr='', exit_code=None)
    monkeypatch.setattr(tool_manager, 'run', lambda *a, **k: timed_out)

    valid, version, status, reason = tool_manager.diagnose(
        'sslyze', [sys.executable, '-m', 'sslyze']
    )

    assert status == 'unknown'
    assert valid is False
    assert 'timed out' in reason.lower()


def test_cancelled_probe_does_not_set_ready(monkeypatch):
    """A cancelled probe must not produce a 'ready' verdict."""
    cancelled = ProcessResult(state='cancelled', stderr='', exit_code=None)
    monkeypatch.setattr(tool_manager, 'run', lambda *a, **k: cancelled)

    valid, version, status, reason = tool_manager.diagnose(
        'sslyze', [sys.executable, '-m', 'sslyze']
    )

    assert status != 'ready'
    assert valid is False


# ---------------------------------------------------------------------------
# Parse: valid reports
# ---------------------------------------------------------------------------

def _tls_document(host='127.0.0.1', port=443):
    scans = {key: {'status': 'COMPLETED', 'result': {'accepted_cipher_suites': []}}
             for key in sslyze_adapter.CHECKS}
    scans['tls_1_0_cipher_suites']['result']['accepted_cipher_suites'] = [
        {'cipher_suite': {'name': 'TLS_RSA_WITH_AES_128_CBC_SHA'}}
    ]
    scans['certificate_info']['result'] = {'certificate_deployments': [
        {'path_validation_results': [{'was_validation_successful': False,
                                      'trust_store': {'name': 'Mozilla'}}],
         'leaf_certificate_subject_matches_hostname': True}
    ]}
    return {
        'server_scan_results': [{
            'server_location': {'ip_address': host, 'port': port},
            'scan_status': 'COMPLETED',
            'connectivity_status': 'COMPLETED',
            'scan_result': scans,
        }],
        'invalid_server_strings': [],
    }


def test_parse_valid_report_produces_findings_and_assets():
    """A well-formed SSLyze 6 report produces expected findings and assets."""
    data = _tls_document()
    result = sslyze_adapter.parse(json.dumps(data), 'https://127.0.0.1')

    assert any(f['title'] == 'TLS certificate validation failed' for f in result.findings)
    assert any(f['title'] == 'Obsolete TLS/SSL protocol supported' for f in result.findings)
    assert any(a['kind'] == 'tls_protocol' for a in result.assets)
    assert any(a['kind'] == 'tls_certificate' for a in result.assets)


def test_parse_out_of_scope_result_raises():
    """A result for a different IP must raise ValueError('...scope...')."""
    data = _tls_document(host='127.0.0.1')
    with pytest.raises(ValueError, match='scope'):
        sslyze_adapter.parse(json.dumps(data), 'https://127.0.0.2')


def test_parse_empty_server_scan_results_raises():
    """Empty server_scan_results raises ValueError."""
    with pytest.raises(ValueError):
        sslyze_adapter.parse('{"server_scan_results": []}', 'https://127.0.0.1')


# ---------------------------------------------------------------------------
# Parse: malformed reports
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('text', ['bad', '{}', 'null', '[3]', '{"invalid_server_strings":["x"]}'])
def test_parse_malformed_input_raises(text):
    """Malformed or invalid JSON documents always raise rather than silently pass."""
    with pytest.raises((ValueError, KeyError, TypeError, AttributeError)):
        sslyze_adapter.parse(text, 'https://127.0.0.1')


def test_parse_incomplete_connectivity_raises():
    """A scan where connectivity_status != COMPLETED is refused."""
    data = _tls_document()
    data['server_scan_results'][0]['connectivity_status'] = 'ERROR'
    with pytest.raises(ValueError, match='connectivity'):
        sslyze_adapter.parse(json.dumps(data), 'https://127.0.0.1')


def test_parse_incomplete_check_is_recorded_as_error_not_finding():
    """A check whose status is ERROR is recorded as a parse error, not silently omitted."""
    data = _tls_document()
    data['server_scan_results'][0]['scan_result']['tls_1_3_cipher_suites']['status'] = 'ERROR'
    data['server_scan_results'][0]['scan_result']['tls_1_3_cipher_suites']['result'] = None
    result = sslyze_adapter.parse(json.dumps(data), 'https://127.0.0.1')
    assert 'tls_1_3_cipher_suites' in result.errors
    # Other completed checks still produce results.
    assert result.assets


# ---------------------------------------------------------------------------
# Workflow: version 6.3.1 detection in a mock diagnose run
# ---------------------------------------------------------------------------

def test_diagnose_detects_sslyze_631_via_metadata(monkeypatch):
    """Full diagnose() call identifies SSLyze 6.3.1 from importlib.metadata."""
    import importlib.metadata as meta

    help_output = 'SSLyze version 6.3.1\nusage: sslyze [-h] ...\noptional arguments:\n  -h, --help'
    completed = ProcessResult(state='completed', stdout=help_output, stderr='', exit_code=0)
    monkeypatch.setattr(tool_manager, 'run', lambda *a, **k: completed)
    monkeypatch.setattr(meta, 'version', lambda name: '6.3.1' if name == 'sslyze' else meta.version.__wrapped__(name))

    valid, version, status, reason = tool_manager.diagnose(
        'sslyze', [sys.executable, '-m', 'sslyze']
    )

    assert valid is True
    assert version == '6.3.1'
    assert status == 'ready'


def test_sslyze_module_based_flag_is_declared():
    """sslyze adapter must declare MODULE_BASED=True and MODULE_NAME='sslyze'."""
    assert getattr(sslyze_adapter, 'MODULE_BASED', False) is True
    assert getattr(sslyze_adapter, 'MODULE_NAME', None) == 'sslyze'
