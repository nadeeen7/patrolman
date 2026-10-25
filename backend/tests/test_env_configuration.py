"""Regression tests for the two configuration failures seen on Windows.

1. Gitleaks reported configuration_required after a restart because
   AVA_ALLOWED_LOCAL_ROOTS only ever existed in the launching PowerShell
   process, and nothing loaded the project `.env` file.
2. `python -m backend.app` refused to start because AVA_API_TOKEN was not in
   the process environment, and the message did not say how to fix it.

The tests exercise the real loader and the real validation, and assert that no
configured value (token or directory) is ever echoed back.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from backend import env_file
from backend import server as server_module
from backend.config import Settings
from backend.integrations import gitleaks
from backend.services import tool_manager

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOKEN = 'synthetic-env-file-token-' + 'k' * 24
PLACEHOLDER = 'REPLACE_WITH_A_RANDOM_TOKEN_OF_AT_LEAST_32_CHARACTERS'


@pytest.fixture
def isolated_environment():
    """Restore the real AVA_* environment after a test injects variables."""
    saved = {key: value for key, value in os.environ.items() if key.startswith('AVA_')}
    try:
        yield
    finally:
        for key in [key for key in os.environ if key.startswith('AVA_')]:
            if key not in saved:
                os.environ.pop(key, None)
        os.environ.update(saved)


# --- token validation -------------------------------------------------------

def test_missing_token_names_the_actionable_fix_and_no_value(tmp_path):
    with pytest.raises(ValueError) as caught:
        Settings(tmp_path, '', require_api_token=True).validate()
    message = str(caught.value)
    assert 'AVA_API_TOKEN is not set' in message
    assert 'Start-Patrolman.ps1 -SetupCredential' in message
    assert '.env' in message
    assert 'never displayed' in message


def test_missing_token_allowed_in_normal_web_mode(tmp_path):
    # In normal website mode, API token is optional
    settings = Settings(tmp_path, '')
    settings.validate()
    assert settings.api_token == ''



def test_short_token_reports_its_length_not_its_value(tmp_path):
    weak = 'synthetic-short'
    with pytest.raises(ValueError) as caught:
        Settings(tmp_path, weak).validate()
    message = str(caught.value)
    assert 'at least 32 characters' in message
    assert f'has {len(weak)}' in message
    assert weak not in message


def test_example_placeholder_is_rejected_as_a_placeholder(tmp_path):
    with pytest.raises(ValueError) as caught:
        Settings(tmp_path, PLACEHOLDER).validate()
    assert 'placeholder' in str(caught.value)


def test_token_with_surrounding_whitespace_is_rejected(tmp_path):
    with pytest.raises(ValueError) as caught:
        Settings(tmp_path, ' ' + TOKEN).validate()
    assert 'whitespace' in str(caught.value)


def test_exactly_thirty_two_characters_is_accepted(tmp_path):
    Settings(tmp_path, 'a' * 32).validate()
    Settings(tmp_path, TOKEN).validate()


# --- .env parsing and loading ----------------------------------------------

def test_parser_accepts_comments_quotes_export_and_windows_line_endings():
    text = (
        '# PATROLMAN local settings\r\n'
        f'AVA_API_TOKEN="{TOKEN}"\r\n'
        "export AVA_ALLOWED_LOCAL_ROOTS='C:\\Authorized App'\r\n"
        '\r\n'
        'PATH=/tmp/not-allowed\r\n'
        'AVA_ALLOWED_LOCAL_ROOTS\r\n'
    )
    values, rejected = env_file.parse(text)
    assert values == {
        'AVA_API_TOKEN': TOKEN,
        'AVA_ALLOWED_LOCAL_ROOTS': 'C:\\Authorized App',
    }
    assert rejected == 2


@pytest.mark.parametrize('payload', (b'\xef\xbb\xbf', b''))
def test_loader_tolerates_utf8_bom_and_empty_values(tmp_path, isolated_environment, payload):
    path = tmp_path / 'patrolman.env'
    path.write_bytes(payload + f'AVA_API_TOKEN={TOKEN}\r\nAVA_ALLOWED_LOCAL_ROOTS=\r\n'.encode())
    os.environ.pop('AVA_API_TOKEN', None)
    os.environ.pop('AVA_ALLOWED_LOCAL_ROOTS', None)

    summary = env_file.load(path)

    assert summary['error'] is None
    assert summary['loaded'] == 1
    assert summary['rejected'] == 1
    assert os.environ['AVA_API_TOKEN'] == TOKEN
    assert 'AVA_ALLOWED_LOCAL_ROOTS' not in os.environ


def test_loader_never_overrides_an_exported_value(tmp_path, isolated_environment, monkeypatch):
    path = tmp_path / 'patrolman.env'
    path.write_text(f'AVA_API_TOKEN={TOKEN}\nAVA_ALLOWED_LOCAL_ROOTS={tmp_path}\n', encoding='utf-8')
    exported = 'exported-windows-token-' + 'e' * 24
    monkeypatch.setenv('AVA_API_TOKEN', exported)
    monkeypatch.delenv('AVA_ALLOWED_LOCAL_ROOTS', raising=False)
    os.environ.pop('AVA_ALLOWED_LOCAL_ROOTS', None)

    summary = env_file.load(path)

    assert summary['loaded'] == 1
    assert summary['skipped'] == 1
    assert os.environ['AVA_API_TOKEN'] == exported
    assert os.environ['AVA_ALLOWED_LOCAL_ROOTS'] == str(tmp_path)
    # The summary may report the file and counts, never a configured value.
    assert TOKEN not in repr(summary)
    assert exported not in repr(summary)


def test_missing_env_file_is_a_silent_no_op(tmp_path, isolated_environment):
    summary = env_file.load(tmp_path / 'absent.env')
    assert summary == {'path': None, 'loaded': 0, 'skipped': 0, 'rejected': 0, 'error': None}


def test_directory_instead_of_env_file_is_refused(tmp_path):
    summary = env_file.load(tmp_path)
    assert summary['path'] is None
    assert 'not a regular file' in summary['error']


def test_oversized_env_file_is_refused(tmp_path):
    path = tmp_path / 'patrolman.env'
    path.write_bytes(b'#' * (env_file.MAX_BYTES + 1))
    summary = env_file.load(path)
    assert 'exceeds' in summary['error']
    assert summary['loaded'] == 0


def test_restart_reads_token_and_local_roots_from_the_env_file(tmp_path):
    """A fresh process with no exported AVA_* values must still validate."""
    root = tmp_path / 'authorized-source'
    root.mkdir()
    path = tmp_path / 'patrolman.env'
    path.write_text(
        f'AVA_API_TOKEN={TOKEN}\nAVA_ALLOWED_LOCAL_ROOTS="{root}"\n',
        encoding='utf-8',
    )
    environment = {key: value for key, value in os.environ.items() if not key.startswith('AVA_')}
    environment['AVA_ENV_FILE'] = str(path)
    environment['PYTHONPATH'] = str(PROJECT_ROOT)
    code = (
        'from backend.env_file import load\n'
        'load()\n'
        'from backend.config import Settings\n'
        'settings = Settings.from_env()\n'
        'settings.validate()\n'
        'print(len(settings.allowed_local_roots), settings.allowed_local_roots[0])\n'
    )

    result = subprocess.run(
        [sys.executable, '-c', code],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f'1 {root}'
    assert TOKEN not in result.stdout + result.stderr


def test_cli_turns_a_configuration_error_into_one_clear_message(monkeypatch, capsys):
    def refuse():
        raise ValueError('AVA_API_TOKEN is not set. Fix it without printing it.')

    monkeypatch.setattr(server_module, 'main', refuse)

    with pytest.raises(SystemExit) as caught:
        server_module.run()

    message = str(caught.value)
    assert 'PATROLMAN configuration error' in message
    assert 'AVA_API_TOKEN is not set' in message
    assert 'Traceback' not in message


def test_cli_loads_the_env_file_before_validating(tmp_path, isolated_environment, monkeypatch, capsys):
    path = tmp_path / 'patrolman.env'
    path.write_text(f'AVA_API_TOKEN={TOKEN}\n', encoding='utf-8')
    monkeypatch.setenv('AVA_ENV_FILE', str(path))
    monkeypatch.delenv('AVA_API_TOKEN', raising=False)
    os.environ.pop('AVA_API_TOKEN', None)
    observed = {}

    def start():
        observed['token'] = os.environ.get('AVA_API_TOKEN')

    monkeypatch.setattr(server_module, 'main', start)
    server_module.run()

    assert observed['token'] == TOKEN
    output = capsys.readouterr()
    assert TOKEN not in output.out + output.err
    assert 'loaded 1 AVA_* setting' in output.err


# --- Gitleaks runtime configuration ---------------------------------------

def _stub_gitleaks(monkeypatch):
    monkeypatch.setattr(tool_manager, 'ADAPTERS', {'gitleaks': gitleaks})
    monkeypatch.setattr(tool_manager, 'find_argv', lambda _: 'C:/tools/gitleaks.exe')
    monkeypatch.setattr(tool_manager, 'local_candidate', lambda _: None)
    monkeypatch.setattr(
        tool_manager,
        'diagnose',
        lambda *_: (True, 'Gitleaks 8.30.1', 'ready', 'Verified.'),
    )
    monkeypatch.setattr(
        tool_manager,
        'verify_digest',
        lambda *_: {'status': 'unpinned', 'message': 'No approved digest is recorded.'},
    )


def test_unset_local_root_points_at_the_durable_configuration_options(monkeypatch):
    _stub_gitleaks(monkeypatch)

    item = tool_manager.inventory(check_versions=True, allowed_local_roots=())[0]

    assert item['state'] == 'CONFIGURATION_REQUIRED'
    assert 'AVA_ALLOWED_LOCAL_ROOTS' in item['reason']
    assert '.env' in item['reason']
    assert item['runtime_configuration']['roots_configured'] == 0
    assert item['runtime_configuration']['roots_usable'] == 0


def test_configured_but_missing_root_is_reported_as_unusable(monkeypatch, tmp_path):
    _stub_gitleaks(monkeypatch)
    removed = tmp_path / 'deleted-authorized-root'

    item = tool_manager.inventory(check_versions=True, allowed_local_roots=(str(removed),))[0]

    assert item['state'] == 'CONFIGURATION_REQUIRED'
    assert item['integration_ready'] is False
    assert 'cannot be used' in item['reason']
    # The operator sees the fix, not an echoed filesystem path.
    assert str(removed) not in item['reason']
    assert item['runtime_configuration']['roots_configured'] == 1
    assert item['runtime_configuration']['roots_usable'] == 0


@pytest.mark.parametrize('raw', ('relative/directory', '"C:\\Quoted\\Root"', 'C:\\Parent\\..\\Root'))
def test_invalid_root_forms_never_unlock_gitleaks(monkeypatch, tmp_path, raw):
    _stub_gitleaks(monkeypatch)

    item = tool_manager.inventory(check_versions=True, allowed_local_roots=(raw,))[0]

    assert item['state'] == 'CONFIGURATION_REQUIRED'
    assert item['runtime_configuration']['status'] == 'configuration_required'
    assert item['runtime_configuration']['roots_usable'] == 0


def test_existing_root_unlocks_gitleaks_without_weakening_scope(monkeypatch, tmp_path):
    _stub_gitleaks(monkeypatch)
    root = tmp_path / 'authorized-source'
    root.mkdir()

    item = tool_manager.inventory(check_versions=True, allowed_local_roots=(str(root),))[0]

    assert item['runtime_configuration']['status'] == 'configured'
    assert item['runtime_configuration']['roots_usable'] == 1
    assert item['state'] == 'READY'
    assert 'exact existing local directory' in item['runtime_configuration']['message']
