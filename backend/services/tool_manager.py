"""Runtime evidence, never a hardcoded policy verdict from another computer."""
import os
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from ..integrations import ADAPTERS
from .process_runner import run, policy_block_evidence
from .results import redact
from .executables import find_argv, local_candidate, path_variable
from .integrity import blocks_execution, verify_digest
from .local_scope import ScopeError, TargetError, validate_local

TOOLS = {name: module.COMMANDS for name, module in ADAPTERS.items()}
SETUP_INSTRUCTIONS = {
 'nmap': 'Install the official Windows Nmap distribution from nmap.org. TCP connect needs no raw-packet privileges.',
 'whatweb': 'Install native Ruby and official WhatWeb with its required gems. Set AVA_WHATWEB_PATH to the actual Ruby script, not a batch shim.',
 'httpx': 'Use the official ProjectDiscovery Windows release, not the Python httpx package. Set AVA_HTTPX_PATH to its executable. If Windows blocks it, request administrator review; do not bypass policy.',
 'subfinder': ('Use the official Windows release. Download subfinder_<version>_windows_amd64.zip together with that release\'s '
               'subfinder_<version>_checksums.txt and confirm the archive SHA-256 matches the published value before use (upstream publishes no '
               'signature or provenance attestation, so this proves the archive matches the published digest, not origin authenticity). Point '
               'AVA_SUBFINDER_PATH at the approved binary. Optional AVA_SUBFINDER_PROVIDER_CONFIG points to your provider YAML; keys inside it '
               'stay in that file and providers without keys may be unavailable. Only explicitly authorized domains may be enumerated.'),
 'nuclei': 'Use the official Windows release and set AVA_NUCLEI_PATH to its executable. Only the bundled reviewed template is authorized; arbitrary templates are not accepted.',
 'sslyze': 'Install SSLyze 6 in the backend Python environment with python -m pip install "sslyze>=6,<7". No Bash required.',
 'wapiti': ('Install Wapiti 3 into the backend Python environment with .venv\\Scripts\\python.exe -m pip install "wapiti3>=3.1,<4" '
            'and confirm .venv\\Scripts\\wapiti.exe --version prints 3.x. Set AVA_WAPITI_ENABLED=true as the explicit operator opt-in. '
            'Optionally set AVA_WAPITI_MODULES to a comma-separated subset of the supported modules (default: '
            'http_headers,cookieflags,csp,methods); unknown, out-of-band and credential modules are refused. Non-loopback targets also '
            'require AVA_WAPITI_ALLOW_REMOTE_TARGETS=true. Keep AVA_WAPITI_SCAN_FORCE paranoid/sneaky/polite and the scan/attack '
            'deadlines within their bounds. Wapiti follows redirects for its own requests, so only scan servers you control.'),
 'gitleaks': 'Install official Windows Gitleaks 8 and set AVA_GITLEAKS_PATH. Use the Local profile and an exact AVA_ALLOWED_LOCAL_ROOTS directory. Working-tree files only.',
 'trivy': 'Install official Windows Trivy and set AVA_TRIVY_PATH. Configure AVA_TRIVY_CACHE_DIR with an official database for vulnerability scans; local scans run offline. Optional AVA_TRIVY_SCANNERS=vuln,misconfig,secret.',
}
PURPOSES = {'nmap': 'TCP discovery and bounded service/version detection.', 'whatweb': 'Passive HTTP technology fingerprints.',
 'httpx': 'HTTP/HTTPS status, title, server and technology probing.', 'subfinder': 'Passive subdomain inventory; never expands scan scope.',
 'nuclei': 'Reviewed template-based web checks.',
 'wapiti': 'Bounded web vulnerability assessment with an explicit module list (safety gated).'}


PATH_IN_TEXT = re.compile(r'(?:[A-Za-z]:|\\\\)[^\s\'\"]+')
PROBE_DETAIL = {'timed_out': 'timed out after 5 seconds', 'output_limit': 'exceeded the probe output limit',
                'cancelled': 'was cancelled', 'failed': 'failed'}


def _diagnostic(result):
    """Bounded first error line: identifies the failure without carrying
    filesystem paths or secret values into the API."""
    line = next((row for row in (result.stderr or '').splitlines() if row.strip()), '')
    return PATH_IN_TEXT.sub('[path]', redact(line.strip()))[:200]


def _probe_outcome(result):
    """Classify one failed version/help probe as (status, reason).

    None means the probe completed and identity checks may proceed.
    BLOCKED requires confirmed policy evidence; a launch Windows refused
    without that evidence is EXECUTION_BLOCKED; every other incomplete probe
    is honestly UNKNOWN with a diagnostic, never a guess at configuration.
    """
    if result.state == 'completed':
        return None
    evidence = policy_block_evidence(result)
    if evidence:
        return 'blocked', evidence
    if result.state == 'unavailable':
        return 'missing', 'Executable or native interpreter was not found at execution time.'
    if result.winerror is not None:
        return 'execution_blocked', ('Executable identity/version verification failed. '
            f'Windows refused to launch the executable (error {result.winerror}); evidence is insufficient to confirm a policy block.')
    detail = PROBE_DETAIL.get(result.state, result.state)
    if result.exit_code is not None:
        detail += f' with exit code {result.exit_code}'
    excerpt = _diagnostic(result)
    return 'unknown', ('Executable identity/version verification failed. '
        f'Version probe {detail}; readiness unknown and no Windows policy-block evidence was found.'
        + (f' Output: {excerpt}' if excerpt else ''))


_VERIFIED_CACHE = {}


def _clear_cache():
    _VERIFIED_CACHE.clear()


def normalize_version(v):
    if not v:
        return ''
    cleaned = re.sub(r'\x1b\[[0-9;]*m', '', str(v)).strip()
    m = re.search(r'v?(\d+(?:\.\d+)+(?:-[a-zA-Z0-9.]+)?|\d+)', cleaned)
    return m.group(1) if m else cleaned.lower()


def versions_match(v1, v2):
    if not v1 or not v2:
        return False
    if v1 == v2:
        return True
    return normalize_version(v1) == normalize_version(v2)


def seed_verified_cache_from_db(engine):
    """Seed in-memory verification cache from persisted database records on startup."""
    if engine is None:
        return
    try:
        from sqlalchemy.orm import Session
        from sqlalchemy import select
        from ..models import ToolVerification
        with Session(engine) as session:
            records = session.scalars(
                select(ToolVerification).where(ToolVerification.verification_status == 'verified')
            ).all()
            for rec in records:
                if rec.tool in ADAPTERS:
                    module = ADAPTERS[rec.tool]
                    exe = find_argv(module.COMMANDS)
                    if exe:
                        _VERIFIED_CACHE[rec.tool] = {
                            'executable': exe,
                            'version': rec.verified_version,
                            'status': 'ready',
                            'verified_at': rec.verified_at,
                            'persisted': True,
                        }
    except Exception:
        pass


def backfill_verifications_from_scans(engine):
    """Backfill ToolVerification table from existing completed scans if table is empty."""
    if engine is None:
        return
    try:
        from sqlalchemy.orm import Session
        from sqlalchemy import select, func
        from ..models import ToolVerification, ToolExecution, Scan, now
        with Session(engine) as session:
            count = session.scalar(select(func.count()).select_from(ToolVerification))
            if count and count > 0:
                return
            completed_subq = (
                select(ToolExecution.tool, func.max(ToolExecution.id).label('execution_id'))
                .where(ToolExecution.state == 'completed')
                .group_by(ToolExecution.tool)
                .subquery()
            )
            rows = session.execute(
                select(ToolExecution, Scan)
                .join(completed_subq, ToolExecution.id == completed_subq.c.execution_id)
                .join(Scan, Scan.id == ToolExecution.scan_id)
            ).all()
            for execution, scan in rows:
                meta = (scan.configuration or {}).get('tool_metadata', {}).get(execution.tool, {})
                ver = meta.get('version')
                if ver:
                    module = ADAPTERS.get(execution.tool)
                    exe = find_argv(module.COMMANDS) if module else None
                    exe_path = str(exe[0]) if isinstance(exe, (list, tuple)) and exe else str(exe) if exe else None
                    session.merge(ToolVerification(
                        tool=execution.tool,
                        verified_version=str(ver),
                        verification_status='verified',
                        verified_at=execution.ended_at or scan.ended_at or now(),
                        executable_path=exe_path,
                        last_execution_id=execution.id,
                        evidence_reference=f"scan:{scan.id}",
                        record_version=1,
                    ))
            session.commit()
    except Exception:
        pass


def persist_tool_verification(engine, name=None, version=None, executable=None, execution_id=None, evidence_reference=None, tool=None, status='verified', verified_at=None, **kwargs):
    """Persist a verified tool record to SQLite and update the in-memory cache."""
    tool_name = name or tool
    if not tool_name or not version:
        return
    if executable is None and tool_name in ADAPTERS:
        executable = find_argv(ADAPTERS[tool_name].COMMANDS)
    _VERIFIED_CACHE[tool_name] = {
        'executable': executable,
        'version': version,
        'status': 'ready' if status == 'verified' else status,
        'persisted': True,
    }
    if engine is None:
        return
    try:
        from sqlalchemy.orm import Session
        from ..models import ToolVerification, now
        exe_path = str(executable[0]) if isinstance(executable, (list, tuple)) and executable else str(executable) if executable else None
        with Session(engine) as session:
            rec = session.get(ToolVerification, tool_name)
            if rec:
                rec.verified_version = str(version)
                rec.verification_status = status or 'verified'
                rec.verified_at = verified_at or now()
                if exe_path:
                    rec.executable_path = exe_path
                if execution_id is not None:
                    rec.last_execution_id = execution_id
                if evidence_reference:
                    rec.evidence_reference = evidence_reference
            else:
                session.add(ToolVerification(
                    tool=tool_name,
                    verified_version=str(version),
                    verification_status=status or 'verified',
                    verified_at=verified_at or now(),
                    executable_path=exe_path,
                    last_execution_id=execution_id,
                    evidence_reference=evidence_reference,
                    record_version=1,
                ))
            session.commit()
    except Exception:
        pass


def diagnose(name, executable):
    adapter = ADAPTERS[name]
    prefix = list(executable) if isinstance(executable, (list, tuple)) else [executable]
    with TemporaryDirectory(prefix='ava-version-') as directory:
        result = run([*prefix, *adapter.VERSION_ARGS], timeout=8, max_output=32768, cwd=directory)
        output = result.stdout + result.stderr
        outcome = _probe_outcome(result)
        if outcome:
            return (False, None) + outcome
        # Adapters whose version probe prints only a bare version number provide
        # their own identity check; the shared rule needs a product word.
        identity = getattr(adapter, 'matches_identity', None)
        valid = (identity(output) if identity
                 else adapter.IDENTITY.lower() in output.lower() and bool(re.search(r'\d+\.\d+', output)))
        help_args = list(getattr(adapter, 'HELP_ARGS', ()) or ())
        help_flags = tuple(getattr(adapter, 'HELP_FLAGS', ()) or ())
        if name in {'httpx', 'gitleaks', 'trivy'}:
            # These three advertise the exact options the adapter builds, so a
            # release that dropped one is reported instead of failing mid-scan.
            help_args = ['-h' if name == 'httpx' else '--help']
            help_flags = {'httpx': ('-probe-all-ips', '-no-fallback-scheme', '-tech-detect'),
                          'gitleaks': ('gitleaks', 'dir', '--redact'), 'trivy': ('trivy', 'filesystem')}[name]
        if valid and help_args:
            help_result = run([*prefix, *help_args], timeout=8, max_output=65536, cwd=directory)
            outcome = _probe_outcome(help_result)
            if outcome:
                return (False, None) + outcome
            help_text = help_result.stdout + help_result.stderr
            valid = all(flag in help_text for flag in help_flags)
    if valid and hasattr(adapter, 'parse_version'):
        parsed_ver = adapter.parse_version(output)
        if parsed_ver:
            version_str = str(parsed_ver)
        else:
            version_line = next((line for line in output.splitlines() if re.search(r'\d+\.\d+', line)), '')
            version_str = re.sub(r'\x1b\[[0-9;]*m', '', version_line).strip()[:300] if valid else None
    elif valid:
        version_line = next((line for line in output.splitlines() if re.search(r'\d+\.\d+', line)), '')
        version_str = re.sub(r'\x1b\[[0-9;]*m', '', version_line).strip()[:300]
    else:
        version_str = None
    if valid and version_str:
        _VERIFIED_CACHE[name] = {
            'executable': executable,
            'version': version_str,
            'status': 'ready',
        }
    return valid, version_str, 'ready' if valid else 'unverified', 'Executable identity/version verification failed.'


def verify(name, executable):
    valid, version, _, _ = diagnose(name, executable)
    return valid, version

# Backward-compatible test hook; checks now refresh to detect changed binaries/policy.
verify.cache_clear = _clear_cache


def inventory(check_versions=False, allowed_local_roots=None):
    """Report installation, configuration, safety gating and readiness.

    A tool's own documented environment gates are read by its adapter, so the
    inventory and the scan worker evaluate the same values.
    """
    if allowed_local_roots is None:
        allowed_local_roots = tuple(
            root for root in os.getenv('AVA_ALLOWED_LOCAL_ROOTS', '').split(os.pathsep) if root
        )

    # Distinguish "no root configured" from "roots configured but unusable".
    # Both keep Gitleaks at configuration_required, but the reason must match
    # what the operator actually did, or the dashboard sends them in circles.
    usable_roots = 0
    unusable_roots = 0
    for root in allowed_local_roots:
        try:
            validate_local(root, allowed_local_roots)
            usable_roots += 1
        except (ScopeError, TargetError):
            unusable_roots += 1
    local_root_available = usable_roots > 0
    if local_root_available:
        local_issue = None
    elif unusable_roots:
        local_issue = (
            f'{unusable_roots} configured AVA_ALLOWED_LOCAL_ROOTS '
            f'entr{"y" if unusable_roots == 1 else "ies"} cannot be used. Each entry must be one '
            'absolute, existing directory, written without quotes or surrounding spaces, and '
            f'entries are separated by "{os.pathsep}" on this host. Links, reparse points, '
            'network shares and parent traversal are refused.'
        )
    else:
        local_issue = (
            'Configure AVA_ALLOWED_LOCAL_ROOTS with an exact, existing local directory before '
            'using Gitleaks. Set it in the PowerShell session that starts the backend, in the '
            'startup script, or in the git-ignored .env file at the project root.'
        )

    def inspect(item):
        name, module = item
        executable = find_argv(module.COMMANDS)
        candidate = local_candidate(module.COMMANDS) if not executable else None
        configured_path = os.getenv(path_variable(module.COMMANDS))
        disabled = getattr(module, 'DISABLED', None)
        issue = module.configuration_error() if hasattr(module, 'configuration_error') else None
        root_issue = local_issue if name == 'gitleaks' else None
        if root_issue:
            issue = issue or root_issue
        version = None
        valid = False
        diagnosed_version = None
        diag_status = None
        diag_reason = None
        # An explicit operator opt-in is its own status and never substitutes for
        # installation, verification or configuration; it is reported separately.
        opt_in = getattr(module, 'opt_in_enabled', None)
        opted_in = opt_in() if opt_in else None
        status = None
        missing_executable = not executable and not (candidate or configured_path)
        if missing_executable:
            status, reason = 'missing', 'Executable or native interpreter not found. Batch launchers are unsupported.'
        elif disabled and opted_in is not True:
            status, reason = 'disabled', disabled
            if check_versions and executable:
                valid, diagnosed_version, diag_status, diag_reason = diagnose(name, executable)
                if valid:
                    version = diagnosed_version
        elif disabled:
            # The operator opted in; the tool's own configuration gate and the
            # per-scan safety checks still apply, and readiness never proves a
            # successful assessment.
            if check_versions and executable:
                valid, diagnosed_version, diag_status, diag_reason = diagnose(name, executable)
                if valid:
                    version = diagnosed_version
                else:
                    status, reason = diag_status, diag_reason
            if status is None:
                if not check_versions:
                    status, reason = 'unverified', 'Executable found; version check not requested.'
                elif issue:
                    status, reason = 'configuration_required', issue
                elif valid:
                    status, reason = 'ready', ('Explicit operator opt-in and a valid conservative configuration are recorded. '
                                               'Each scan still re-validates target authorization, scope, module list and deadlines, '
                                               'and readiness does not prove a successful assessment.')
                else:
                    status, reason = diag_status or 'unverified', diag_reason or 'Executable verification failed.'
        elif not executable and (candidate or configured_path):
            status = 'configuration_required'
            if candidate and configured_path:
                reason = (f'{path_variable(module.COMMANDS)} does not resolve to a usable executable; '
                          'correct the configured path.')
            elif candidate:
                reason = (f'A project-local {name} candidate exists, but {path_variable(module.COMMANDS)} '
                          'is not configured. Set it to the approved executable or script path.')
            else:
                reason = f'{path_variable(module.COMMANDS)} is configured, but the path cannot be resolved.'
        elif not executable:
            status, reason = 'missing', 'Executable or native interpreter not found. Batch launchers are unsupported.'
        elif not check_versions:
            cached = _VERIFIED_CACHE.get(name)
            cached_exe = cached.get('executable') if cached else None
            exe_matches = (
                cached and cached_exe and (
                    cached_exe == executable or
                    (isinstance(executable, (list, tuple)) and isinstance(cached_exe, (list, tuple)) and executable[0] == cached_exe[0]) or
                    (isinstance(executable, (list, tuple)) and not isinstance(cached_exe, (list, tuple)) and executable[0] == cached_exe) or
                    (not isinstance(executable, (list, tuple)) and isinstance(cached_exe, (list, tuple)) and executable == cached_exe[0])
                )
            )
            if cached and exe_matches:
                cached_rec = _VERIFIED_CACHE[name]
                valid = True
                version = cached_rec['version']
                diagnosed_version = version
                status = 'ready'
                reason = 'Executable identity/version verified (cached). Readiness does not prove a successful assessment.'
                if issue: status, reason = 'configuration_required', issue
            else:
                status, reason = 'unverified', 'Executable found; version check not requested.'
        else:
            valid, version, status, reason = diagnose(name, executable)
            diagnosed_version = version
            diag_status = status
            diag_reason = reason
            if valid:
                reason = 'Executable identity/version verified. Readiness does not prove a successful assessment.'
                if issue: status, reason = 'configuration_required', issue
        if root_issue and status in {'ready', 'unverified'}:
            status, reason = 'configuration_required', root_issue
        # Version verification is reported as an independent fact
        if not executable and not (candidate or configured_path):
            v_verif_status = 'not_installed'
            v_verif_msg = 'Executable not found.'
        elif not executable and (candidate or configured_path):
            v_verif_status = 'not_installed'
            v_verif_msg = reason or 'Executable path needs attention.'
        elif not check_versions:
            if valid and version:
                v_verif_status = 'verified'
                v_verif_msg = f'Executable version {version} verified (cached).'
            else:
                v_verif_status = 'unverified'
                v_verif_msg = 'Version check not requested.'
        elif valid and version:
            v_verif_status = 'verified'
            v_verif_msg = f'Executable version {version} verified.'
        else:
            v_verif_status = 'unverified'
            v_verif_msg = diag_reason or reason or 'Executable identity/version verification failed.'

        version_verification = {
            'status': v_verif_status,
            'version': version,
            'message': v_verif_msg,
        }
        # Runtime configuration is reported separately from installation and
        # verification, and never carries configuration values or secrets. A tool
        # may describe its own accurate runtime state; otherwise the shared
        # configuration gate is used.
        runtime = None
        if name == 'gitleaks':
            runtime = {
                'status': 'configured' if local_root_available else 'configuration_required',
                'message': ('An exact existing local directory is approved for bounded working-tree scans.'
                            if local_root_available else root_issue),
                'roots_configured': len(allowed_local_roots),
                'roots_usable': usable_roots,
            }
        elif hasattr(module, 'runtime_status'):
            runtime_status, runtime_message = module.runtime_status()
            runtime = {'status': runtime_status, 'message': runtime_message}
        elif hasattr(module, 'configuration_error'):
            runtime = {'status': 'configuration_required' if issue else 'configured',
                'message': issue or ('Environment configuration is present; it never enables a safety-disabled tool on its own.'
                                     if disabled else 'Environment configuration is present.')}
        if not executable and (candidate or configured_path):
            runtime = {'status': 'configuration_required', 'message': reason}
        # Approved-digest status is reported for every tool, so an unpinned tool
        # is visibly unpinned rather than silently passing as verified.
        integrity_check = getattr(module, 'integrity_status', None)
        integrity_result = (integrity_check(executable or candidate) if integrity_check
                            else verify_digest(name, executable or candidate))
        integrity = {'status': integrity_result['status'], 'expected': integrity_result.get('expected'),
                     'actual': integrity_result.get('actual'), 'message': integrity_result['message']}
        if blocks_execution(integrity['status']) and integrity['status'] != 'missing':
            status = 'configuration_required'
            reason = integrity['message']
            runtime = {'status': 'configuration_required', 'message': reason}
        operator_opt_in = None
        if opt_in is not None:
            operator_opt_in = {
                'status': 'enabled' if opted_in else 'disabled',
                'variable': getattr(module, 'OPT_IN_ENV', None),
                'message': ('Explicit operator opt-in is enabled for this tool.' if opted_in else
                            'Explicit operator opt-in is required and is not set, so this tool stays disabled regardless of installation or configuration.')}
        capabilities = list(getattr(module, 'CAPABILITIES', ()) or ())
        safety = getattr(module, 'SAFETY_RESTRICTIONS', None)
        v_type = getattr(module, 'VERIFICATION_TYPE', 'genuine' if status == 'ready' else 'mocked_fixtures' if disabled else 'none')
        if status == 'unverified' and not configured_path and local_candidate(module.COMMANDS):
            state_val = 'CONFIGURATION_REQUIRED'
        elif status == 'unverified' and check_versions and executable and not valid:
            state_val = 'VERSION_UNVERIFIED'
        elif status == 'unknown' and name == 'wapiti' and check_versions and executable and not valid:
            state_val = 'VERSION_UNVERIFIED'
        else:
            state_val = {'ready':'READY','missing':'NOT_INSTALLED','disabled':'DISABLED_FOR_SAFETY',
                         'unverified':'UNVERIFIED','configuration_required':'CONFIGURATION_REQUIRED',
                         'blocked':'BLOCKED_BY_POLICY','execution_blocked':'EXECUTION_BLOCKED','unknown':'UNKNOWN'}.get(status, 'UNVERIFIED')
        return dict(name=name, purpose=getattr(module, 'PURPOSE', PURPOSES.get(name)),
            executable_found=bool(executable or candidate),
            status=status, state=state_val,
            integration_ready=status == 'ready', version=version, reason=reason, setup=SETUP_INSTRUCTIONS.get(name),
            safety_restrictions=safety, verification_type=v_type, runtime_configuration=runtime,
            operator_opt_in=operator_opt_in, capabilities=capabilities, integrity=integrity,
            version_verification=version_verification)
    with ThreadPoolExecutor(max_workers=3) as pool:
        return list(pool.map(inspect, ADAPTERS.items()))
