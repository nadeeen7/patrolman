import os
import stat
from types import SimpleNamespace
from pathlib import Path

import pytest

from backend.integrations import httpx_scanner, subfinder
from backend.services import executables, tool_manager
from backend.integrations import gitleaks
from backend.config import Settings
from backend.app import create_app
from backend.services.local_scope import ScopeError, TargetError, validate_local


def test_relative_override_resolves_from_project_root_not_working_directory(monkeypatch, tmp_path):
    project = tmp_path / 'project'
    binary = project / 'tools' / 'httpx' / 'httpx.exe'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'synthetic executable placeholder')
    elsewhere = tmp_path / 'scan-working-directory'
    elsewhere.mkdir()
    monkeypatch.setattr(executables, 'PROJECT_ROOT', project)
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv('AVA_HTTPX_PATH', 'tools/httpx/httpx.exe')
    monkeypatch.setattr(executables.shutil, 'which', lambda *args, **kwargs: None)

    assert executables.find_argv(httpx_scanner.COMMANDS) == str(binary.resolve())


def test_automatic_project_discovery_and_explicit_override_precedence(monkeypatch, tmp_path):
    project = tmp_path / 'project'
    automatic = project / 'tools' / 'httpx' / 'httpx.exe'
    explicit = tmp_path / 'approved' / 'httpx.exe'
    automatic.parent.mkdir(parents=True)
    explicit.parent.mkdir(parents=True)
    automatic.write_bytes(b'automatic candidate')
    explicit.write_bytes(b'explicit operator candidate')
    monkeypatch.setattr(executables, 'PROJECT_ROOT', project)
    monkeypatch.setattr(executables, 'WINDOWS', True)
    monkeypatch.setattr(executables.shutil, 'which', lambda *args, **kwargs: None)
    monkeypatch.delenv('AVA_HTTPX_PATH', raising=False)

    assert executables.find_argv(httpx_scanner.COMMANDS) == str(automatic.resolve())

    monkeypatch.setenv('AVA_HTTPX_PATH', str(explicit))
    assert executables.find_argv(httpx_scanner.COMMANDS) == str(explicit.resolve())

    monkeypatch.setenv('AVA_HTTPX_PATH', str(tmp_path / 'missing.exe'))
    assert executables.find_argv(httpx_scanner.COMMANDS) is None


def test_automatic_interpreter_discovery_uses_existing_runtime(monkeypatch, tmp_path):
    runtime = tmp_path / 'ruby' / 'bin' / 'ruby.exe'
    runtime.parent.mkdir(parents=True)
    runtime.write_bytes(b'runtime')
    monkeypatch.setattr(executables, 'WINDOWS', True)
    monkeypatch.setattr(executables, '_runtime_candidates', lambda name: (runtime,) if name == 'ruby' else ())
    monkeypatch.setattr(executables.shutil, 'which', lambda *args, **kwargs: None)

    assert executables.find_runtime('ruby') == str(runtime.resolve())


def test_startup_configures_discovered_tools_without_overriding_operator_values(monkeypatch):
    from backend.integrations import ADAPTERS

    monkeypatch.setenv('PATH', os.environ.get('PATH', ''))
    watched = [executables.path_variable(module.COMMANDS) for module in ADAPTERS.values()]
    watched.extend(('AVA_TRIVY_CACHE_DIR', 'AVA_TRIVY_SCANNERS'))
    original = {name: os.environ.get(name) for name in watched}
    for module in ADAPTERS.values():
        monkeypatch.delenv(executables.path_variable(module.COMMANDS), raising=False)
    monkeypatch.setenv('AVA_HTTPX_PATH', 'C:\\operator\\httpx.exe')
    monkeypatch.setenv('AVA_TRIVY_CACHE_DIR', 'C:\\operator\\trivy-cache')
    monkeypatch.setenv('AVA_TRIVY_SCANNERS', 'vuln')
    monkeypatch.setattr(executables, 'find_argv', lambda commands: (
        ['C:\\Ruby\\bin\\ruby.exe', 'C:\\project\\whatweb'] if commands[0] == 'whatweb'
        else 'C:\\project\\' + commands[0]
    ))

    executables.configure_tool_environment()

    assert os.environ['AVA_HTTPX_PATH'] == 'C:\\operator\\httpx.exe'
    assert os.environ['AVA_TRIVY_CACHE_DIR'] == 'C:\\operator\\trivy-cache'
    assert os.environ['AVA_TRIVY_SCANNERS'] == 'vuln'
    assert os.environ['AVA_WHATWEB_PATH'] == 'C:\\project\\whatweb'
    assert os.environ['AVA_NMAP_PATH'] == 'C:\\project\\nmap'
    for name, value in original.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def test_startup_uses_config_only_trivy_without_creating_or_downloading_database(monkeypatch, tmp_path):
    from backend.integrations import ADAPTERS

    monkeypatch.setenv('PATH', os.environ.get('PATH', ''))
    watched = [executables.path_variable(module.COMMANDS) for module in ADAPTERS.values()]
    watched.extend(('AVA_TRIVY_CACHE_DIR', 'AVA_TRIVY_SCANNERS'))
    original = {name: os.environ.get(name) for name in watched}
    for module in ADAPTERS.values():
        monkeypatch.delenv(executables.path_variable(module.COMMANDS), raising=False)
    monkeypatch.delenv('AVA_TRIVY_CACHE_DIR', raising=False)
    monkeypatch.delenv('AVA_TRIVY_SCANNERS', raising=False)
    monkeypatch.setattr(executables, 'find_argv', lambda commands: None)
    monkeypatch.setattr('backend.integrations.trivy.discover_cache', lambda: None)

    executables.configure_tool_environment()
    try:
        cache = Path(os.environ['AVA_TRIVY_CACHE_DIR'])
        assert cache.is_dir()
        assert not (cache / 'db' / 'trivy.db').exists()
        assert os.environ['AVA_TRIVY_SCANNERS'] == 'misconfig,secret'
        from backend.integrations import trivy
        status, message = trivy.runtime_status()
        assert status == 'configured'
        assert 'vulnerability database scanning is unavailable' in message.lower()
    finally:
        if executables._TRIVY_CACHE is not None:
            executables._TRIVY_CACHE.cleanup()
            executables._TRIVY_CACHE = None
        for name, value in original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_relative_subfinder_override_keeps_approved_digest_check(monkeypatch):
    monkeypatch.setenv('AVA_SUBFINDER_PATH', 'tools/subfinder/subfinder.exe')

    resolved = executables.find_argv(subfinder.COMMANDS)
    assert resolved == str((executables.PROJECT_ROOT / 'tools' / 'subfinder' / 'subfinder.exe').resolve())
    assert subfinder.integrity_status(resolved)['status'] == 'verified'


def test_project_local_candidate_is_discovered_without_override(monkeypatch, tmp_path):
    project = tmp_path / 'project'
    binary = project / 'tools' / 'httpx' / 'httpx.exe'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'synthetic executable placeholder')
    monkeypatch.setattr(executables, 'PROJECT_ROOT', project)
    monkeypatch.setattr(executables, 'WINDOWS', True)
    monkeypatch.setattr(executables.shutil, 'which', lambda *args, **kwargs: None)
    monkeypatch.delenv('AVA_HTTPX_PATH', raising=False)

    assert executables.find_argv(httpx_scanner.COMMANDS) == str(binary.resolve())
    assert executables.local_candidate(httpx_scanner.COMMANDS) == binary.resolve()
    monkeypatch.setattr(tool_manager, 'ADAPTERS', {'httpx': httpx_scanner})
    monkeypatch.setattr(tool_manager, 'local_candidate', executables.local_candidate)

    item = tool_manager.inventory(check_versions=False)[0]
    assert item['executable_found'] is True
    assert item['status'] == 'unverified'
    assert item['state'] == 'CONFIGURATION_REQUIRED'
    assert item['version'] is None
    assert item['integrity']['status'] == 'unpinned'


def test_invalid_override_is_configuration_error(monkeypatch):
    monkeypatch.setattr(tool_manager, 'ADAPTERS', {'httpx': httpx_scanner})
    monkeypatch.setattr(tool_manager, 'find_argv', lambda _: None)
    monkeypatch.setattr(tool_manager, 'local_candidate', lambda _: None)
    monkeypatch.setenv('AVA_HTTPX_PATH', 'tools/httpx/missing.exe')

    item = tool_manager.inventory(check_versions=True)[0]
    assert item['executable_found'] is False
    assert item['status'] == 'configuration_required'
    assert 'cannot be resolved' in item['reason']


def test_integrity_failure_never_reports_ready(monkeypatch):
    monkeypatch.setattr(tool_manager, 'ADAPTERS', {'subfinder': subfinder})
    monkeypatch.setattr(tool_manager, 'find_argv', lambda _: 'C:/approved/subfinder.exe')
    monkeypatch.setattr(tool_manager, 'local_candidate', lambda _: None)
    monkeypatch.setattr(subfinder, 'integrity_status', lambda _: {
        'status': 'mismatch', 'expected': 'expected', 'actual': 'actual',
        'message': 'Binary digest does not match the approved digest; execution refused.',
    })

    item = tool_manager.inventory(check_versions=False)[0]
    assert item['status'] == 'configuration_required'
    assert item['integration_ready'] is False
    assert item['integrity']['status'] == 'mismatch'


def test_gitleaks_requires_an_existing_authorized_local_root(monkeypatch, tmp_path):
    monkeypatch.setattr(tool_manager, 'ADAPTERS', {'gitleaks': gitleaks})
    monkeypatch.setattr(tool_manager, 'find_argv', lambda _: 'C:/tools/gitleaks.exe')
    monkeypatch.setattr(tool_manager, 'local_candidate', lambda _: None)
    monkeypatch.setattr(tool_manager, 'diagnose', lambda *_: (True, 'Gitleaks 8.30.1', 'ready', 'Verified.'))

    missing = tool_manager.inventory(check_versions=True, allowed_local_roots=())[0]
    assert missing['state'] == 'CONFIGURATION_REQUIRED'
    assert missing['integration_ready'] is False
    assert missing['runtime_configuration']['status'] == 'configuration_required'
    assert 'AVA_ALLOWED_LOCAL_ROOTS' in missing['reason']

    root = tmp_path / 'authorized-source'
    root.mkdir()
    configured = tool_manager.inventory(check_versions=True, allowed_local_roots=(str(root),))[0]
    assert configured['state'] == 'READY'
    assert configured['runtime_configuration']['status'] == 'configured'


def test_allowed_local_roots_load_from_process_environment(monkeypatch, tmp_path):
    first = tmp_path / 'authorized-one'
    second = tmp_path / 'authorized-two'
    first.mkdir()
    second.mkdir()
    monkeypatch.setenv(
        'AVA_ALLOWED_LOCAL_ROOTS',
        os.pathsep.join((str(first), str(second))),
    )

    settings = Settings.from_env()

    assert settings.allowed_local_roots == (str(first), str(second))
    assert validate_local(str(first), settings.allowed_local_roots) == str(first)
    assert validate_local(str(second), settings.allowed_local_roots) == str(second)


def test_allowed_local_roots_are_a_startup_snapshot(monkeypatch, tmp_path):
    root = tmp_path / 'authorized-source'
    root.mkdir()
    monkeypatch.delenv('AVA_ALLOWED_LOCAL_ROOTS', raising=False)

    settings = Settings.from_env()
    monkeypatch.setenv('AVA_ALLOWED_LOCAL_ROOTS', str(root))

    assert settings.allowed_local_roots == ()


def test_settings_loaded_roots_are_used_for_gitleaks_inventory(monkeypatch, tmp_path):
    root = tmp_path / 'authorized-source'
    root.mkdir()
    monkeypatch.setenv('AVA_ALLOWED_LOCAL_ROOTS', str(root))
    monkeypatch.setattr(tool_manager, 'ADAPTERS', {'gitleaks': gitleaks})
    monkeypatch.setattr(tool_manager, 'find_argv', lambda _: 'C:/tools/gitleaks.exe')
    monkeypatch.setattr(tool_manager, 'local_candidate', lambda _: None)
    monkeypatch.setattr(
        tool_manager, 'diagnose',
        lambda *_: (True, 'Gitleaks 8.30.1', 'ready', 'Verified.'),
    )
    monkeypatch.setattr(
        tool_manager, 'verify_digest',
        lambda *_: {'status': 'unpinned', 'message': 'No approved digest is recorded.'},
    )

    settings = Settings.from_env()
    token = 'SYNTHETIC_PATROLMAN_LOCAL_SCOPE_TEST_TOKEN'
    app = create_app(
        Settings(tmp_path / 'data', token, allowed_local_roots=settings.allowed_local_roots),
    )
    try:
        response = app.test_client().get(
            '/api/tools',
            headers={'Authorization': 'Bearer ' + token},
        )
        assert response.status_code == 200
        item = response.get_json()['data'][0]
        assert item['name'] == 'gitleaks'
        assert item['runtime_configuration']['status'] == 'configured'
        assert item['state'] == 'UNVERIFIED'
        assert validate_local(str(root), settings.allowed_local_roots) == str(root)
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_local_scope_rejects_missing_and_non_exact_configured_roots(tmp_path):
    approved = tmp_path / 'approved'
    approved.mkdir()
    missing = tmp_path / 'missing'

    with pytest.raises(TargetError, match='unavailable'):
        validate_local(str(missing), (str(missing),))
    with pytest.raises(ScopeError, match='exact match'):
        validate_local(str(approved / 'child'), (str(approved),))
    with pytest.raises(TargetError, match='parent traversal'):
        validate_local(str(approved / '..' / 'approved'), (str(approved),))


@pytest.mark.parametrize(
    ('mode', 'attributes'),
    ((stat.S_IFLNK, 0), (stat.S_IFDIR, 0x400)),
)
def test_local_scope_rejects_link_and_reparse_metadata(
    monkeypatch, tmp_path, mode, attributes,
):
    candidate = tmp_path / 'authorized-link'
    original_lstat = Path.lstat

    def lstat(path):
        if path == candidate:
            return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
        return original_lstat(path)

    monkeypatch.setattr(Path, 'lstat', lstat)

    with pytest.raises(ScopeError, match='reparse points'):
        validate_local(str(candidate), (str(candidate),))
