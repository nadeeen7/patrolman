import os
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STARTUP_SCRIPT = PROJECT_ROOT / 'Start-Patrolman.ps1'


def test_startup_script_loopback_mode_is_explicit_and_trivy_is_offline():
    script = STARTUP_SCRIPT.read_text(encoding='utf-8')

    assert '[switch]$LoopbackTesting' in script
    assert "if ($LoopbackTesting) {" in script
    assert "$env:AVA_ALLOWED_TARGETS = '127.0.0.1'" in script
    assert "$env:AVA_ALLOW_PRIVATE_TARGETS = 'true'" in script
    assert "$env:AVA_TRIVY_SCANNERS = 'misconfig,secret'" in script
    assert "$env:AVA_TRIVY_CACHE_DIR = $trivyCache" in script
    assert "'PATROLMAN\\trivy-cache'" in script
    assert 'download-db-only' not in script.lower()
    assert 'AVA_DATA_DIR' not in script
    assert 'previousTargets' in script and 'previousPrivateTargets' in script
    assert 'previousTrivyScanners' in script and 'previousTrivyCache' in script


def test_startup_script_preserves_an_operator_configured_local_root():
    script = STARTUP_SCRIPT.read_text(encoding='utf-8')

    assert '$localRoots = $env:AVA_ALLOWED_LOCAL_ROOTS' in script
    assert 'if (-not [string]::IsNullOrWhiteSpace($localRoots)) {' in script
    assert '$env:AVA_ALLOWED_LOCAL_ROOTS = $localRoots' in script
    assert '$env:AVA_ALLOWED_LOCAL_ROOTS = $gitleaksRoot' not in script
    assert 'does not add or replace local scan roots' in script


def test_startup_script_accepts_an_existing_token_without_generating_one():
    script = STARTUP_SCRIPT.read_text(encoding='utf-8')

    assert '$tokenFromStore' in script
    assert "Join-Path $projectRoot '.env'" in script
    assert 'No token was generated or changed.' in script
    # The script only ever reads an existing token; it never derives one.
    assert 'token_urlsafe' not in script
    assert 'Get-Random' not in script


@pytest.mark.skipif(os.name != 'nt', reason='PowerShell parses the Windows startup script.')
def test_startup_script_still_parses():
    powershell = shutil.which('powershell.exe') or shutil.which('pwsh.exe')
    if not powershell:
        pytest.skip('PowerShell is unavailable.')
    path = str(STARTUP_SCRIPT).replace("'", '')
    command = (
        '$errors = $null; '
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$null, [ref]$errors); "
        'if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Output $_.Message }; exit 1 }'
    )
    result = subprocess.run(
        [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='Windows Credential Manager is Windows-only.')
def test_startup_script_credential_store_self_test():
    powershell = shutil.which('powershell.exe') or shutil.which('pwsh.exe')
    if not powershell:
        pytest.skip('PowerShell is unavailable.')

    environment = os.environ.copy()
    environment.pop('AVA_API_TOKEN', None)
    environment.pop('AVA_ALLOWED_LOCAL_ROOTS', None)
    result = subprocess.run(
        [
            powershell,
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-File',
            str(STARTUP_SCRIPT),
            '-TestCredentialStore',
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert 'Credential Manager self-test passed' in result.stdout
    assert 'synthetic-patrolman-credential-store-self-test' not in result.stdout
    assert 'synthetic-patrolman-credential-store-self-test' not in result.stderr
