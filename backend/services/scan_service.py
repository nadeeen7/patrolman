import ipaddress
import json
import threading

from concurrent.futures import ThreadPoolExecutor
from datetime import timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import Scan, Asset, ToolExecution, Finding, now
from ..integrations import ADAPTERS
from contextlib import nullcontext
from .process_runner import run, policy_block_evidence
from .results import deduplicate, redact, SEVERITIES
from .reports import write_reports
from .target_validation import validate_target
from .integrity import blocks_execution
from .tool_manager import verify, diagnose
from .local_scope import validate_local, snapshot
from .executables import find_argv
from .rate_limiter import coordinator, RateLimitPolicyError, RateLimitCancelledError
from .target_authorization import format_iso

PROFILES = {
    'quick': {'tools': ['nmap', 'httpx', 'whatweb'], 'description': 'Four web ports; service discovery and passive technology identification.'},
    'standard': {'tools': ['nmap', 'subfinder', 'httpx', 'whatweb', 'nuclei', 'sslyze'], 'description': 'Common ports, passive subdomain discovery, bundled header check and TLS protocols.'},
    'comprehensive': {'tools': [n for n in ADAPTERS if n not in {'gitleaks', 'trivy'}], 'description': 'Expanded fixed ports and all enabled checks; Wapiti requires explicit operator opt-in.'},
}
PROFILES['local'] = {'tools': ['gitleaks', 'trivy'], 'description': 'Authorized local working-tree snapshot; secrets, dependencies and configured file checks. No web assessment or Git history.'}
TERMINAL = {'completed', 'completed_with_errors', 'failed', 'cancelled'}
# One bound for a single tool invocation, enforced by the shared runner. It must
# exceed Nmap's 120s per-host timeout so a slow sweep is reported with its real
# results rather than being cut off by the runner first.
TOOL_TIMEOUT = 150


def timestamp(value):
    return format_iso(value)


def serialize(session, scan, details=True):
    data = dict(id=scan.id, target=scan.target, profile=scan.profile, state=scan.state,
                created_by=getattr(scan, 'created_by', None),
                created_at=timestamp(scan.created_at), started_at=timestamp(scan.started_at), ended_at=timestamp(scan.ended_at),
                configuration=scan.configuration, finding_count=len(scan.findings))
    executions = [dict(id=e.id, tool=e.tool, state=e.state, error=e.error, exit_code=e.exit_code,
                       started_at=timestamp(e.started_at), ended_at=timestamp(e.ended_at)) for e in scan.executions]
    processed = sum(e['state'] not in {'queued', 'running'} for e in executions)
    data['progress'] = {'processed': processed, 'total': len(executions),
                        'current_tool': next((e['tool'] for e in executions if e['state'] == 'running'), None)}
    for execution in executions:
        meta = scan.configuration.get('tool_metadata', {}).get(execution['tool'], {})
        execution.update(meta)
        execution['outcome'] = ({'completed': ('COMPLETED_WITH_FINDINGS' if meta.get('finding_count') else 'COMPLETED_WITHOUT_FINDINGS') if 'finding_count' in meta else 'COMPLETED',
            'unavailable': 'NOT_INSTALLED', 'blocked': 'BLOCKED_BY_POLICY', 'configuration_required': 'CONFIGURATION_REQUIRED',
            'skipped': 'DISABLED_FOR_SAFETY' if meta.get('disabled') else 'SKIPPED',
            'failed': 'FAILED', 'timed_out': 'TIMED_OUT'}.get(execution['state'], execution['state'].upper()))
    data['executions'] = executions
    data['coverage'] = {'completed': [e['tool'] for e in executions if e['state'] == 'completed'],
        'untested_or_incomplete': [e['tool'] for e in executions if e['state'] != 'completed'],
        'not_selected': [name for name in ADAPTERS if name not in [e['tool'] for e in executions]]}
    data['severities'] = {key: sum(f.severity == key for f in scan.findings) for key in SEVERITIES}
    if details:
        data['assets'] = [dict(id=a.id, address=a.address, kind=a.kind, details=a.details) for a in scan.assets]
        data['findings'] = [dict(id=f.id, fingerprint=f.fingerprint, title=f.title, severity=f.severity,
                                 first_seen=timestamp(f.first_seen), last_seen=timestamp(f.last_seen), details=f.details) for f in scan.findings]
    return data


class ScanManager:
    """Single-process bounded local worker; SQLite remains the source of history."""
    def __init__(self, engine, settings):
        self.engine, self.settings = engine, settings
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='ava-scan')
        self.capacity = threading.BoundedSemaphore(8)
        self.lock = threading.RLock()
        self.events = {}
        self.rate_coordinator = coordinator
        # No unsafe automatic replay after a process restart.
        with Session(engine) as session:
            for scan in session.scalars(select(Scan).where(Scan.state.in_(['running', 'queued']))):
                scan.state, scan.ended_at = 'failed', now()
                scan.configuration = dict(scan.configuration, failure='Server restarted; incomplete job was not replayed.')
                for execution in scan.executions:
                    if execution.state in {'queued', 'running'}:
                        execution.state, execution.error, execution.ended_at = 'failed', 'Interrupted by server restart.', now()
            session.commit()

    def submit(self, scan_id):
        event = threading.Event()
        self.events[scan_id] = event
        self.pool.submit(self.work, scan_id, event)

    def cancel(self, scan_id):
        with self.lock:
            event = self.events.get(scan_id)
            if event:
                event.set()
            with Session(self.engine) as session:
                scan = session.get(Scan, scan_id)
                if scan and scan.state not in TERMINAL:
                    scan.configuration = dict(scan.configuration, cancellation_requested=True)
                    session.commit()

    def cancel_target_scans(self, target_id, reason='Target scope revoked or deactivated.'):
        """Cancel all running/queued scans bound to an authorized target."""
        with self.lock:
            with Session(self.engine) as session:
                active_scans = session.scalars(
                    select(Scan).where(Scan.state.in_(['queued', 'running']))
                ).all()
                matching_ids = []
                for s in active_scans:
                    if (s.configuration or {}).get('authorized_target_id') == target_id:
                        matching_ids.append(s.id)
                        s.configuration = dict(s.configuration, cancellation_requested=True, cancellation_reason=reason)
                session.commit()
            for sid in matching_ids:
                ev = self.events.get(sid)
                if ev:
                    ev.set()

    def execution(self, execution_id, state, error=None, exit_code=None):
        with Session(self.engine) as session:
            execution = session.get(ToolExecution, execution_id)
            execution.state, execution.error, execution.exit_code = state, redact(error), exit_code
            if state == 'running': execution.started_at = now()
            else: execution.ended_at = now()
            session.commit()

    def metadata(self, scan_id, name, **values):
        with Session(self.engine) as session:
            scan = session.get(Scan, scan_id)
            metadata = dict(scan.configuration.get('tool_metadata', {}))
            metadata[name] = dict(metadata.get(name, {}), **redact(values))
            scan.configuration = dict(scan.configuration, tool_metadata=metadata)
            session.commit()

    def work(self, scan_id, cancel):
        try:
            with Session(self.engine) as session:
                scan = session.get(Scan, scan_id)
                scan.state, scan.started_at = 'running', now()
                session.commit()
                target, profile, config = scan.target, scan.profile, dict(scan.configuration)
                target_port = config.get('target_port')
                target_scheme = config.get('target_scheme')
                canonical_endpoint = config.get('canonical_endpoint')
                if not canonical_endpoint and target and target.startswith(('http://', 'https://')):
                    canonical_endpoint = target
                executions = [(e.id, e.tool) for e in scan.executions]
            auth_target_id = None
            target_obj = None
            if profile == 'local':
                validate_local(target, self.settings.allowed_local_roots)
                addresses = ()
            else:
                checked = validate_target(target, self.settings.allowed_targets, self.settings.allow_private_targets)
                if sorted(checked.addresses) != sorted(config['addresses']):
                    raise ValueError('DNS addresses changed after authorization; create a new scan.')
                addresses = checked.addresses
                if target_port is None and checked.port is not None:
                    target_port = checked.port
                if target_scheme is None and checked.scheme is not None:
                    target_scheme = checked.scheme
                if canonical_endpoint is None and checked.canonical_endpoint:
                    canonical_endpoint = checked.canonical_endpoint
                if canonical_endpoint and (target_port is None or target_scheme is None):
                    from .target_validation import parse_target_endpoint
                    try:
                        ep = parse_target_endpoint(canonical_endpoint)
                        if target_port is None and ep.port is not None:
                            target_port = ep.port
                        if target_scheme is None and ep.scheme is not None:
                            target_scheme = ep.scheme
                    except Exception:
                        pass
                if len(addresses) > 4:
                    raise ValueError('A maximum of four resolved addresses is supported per scan.')
                # Phase 2: re-verify the authorization record is still active
                # before executing tools, guarding against revocations/expirations
                # that occurred while the scan was queued.
                auth_target_id = config.get('authorized_target_id')
                if auth_target_id:
                    from .scope_validator import audit_authorization_failure, recheck_authorized_target
                    try:
                        with Session(self.engine) as auth_session:
                            target_obj = recheck_authorized_target(
                                auth_target_id, auth_session, target, config.get('tools', [])
                            )
                    except Exception as auth_error:
                        audit_authorization_failure(self.engine, auth_target_id, scan_id, str(auth_error))
                        raise

            all_assets, all_findings, web_services = [], [], []
            canonical_reach_err = None
            if canonical_endpoint and canonical_endpoint.startswith(('http://', 'https://')):
                from .reachability import check_endpoint_reachability
                reachable, reach_err = check_endpoint_reachability(canonical_endpoint, timeout=2.0)
                if reachable:
                    if canonical_endpoint not in web_services:
                        web_services.append(canonical_endpoint)
                else:
                    canonical_reach_err = reach_err
            for current_idx, (execution_id, name) in enumerate(executions):
                if cancel.is_set():
                    self.execution(execution_id, 'cancelled', 'Cancelled before execution.')
                    continue
                # Re-verify authorization immediately before each tool executes.
                if auth_target_id:
                    from .scope_validator import audit_authorization_failure, recheck_authorized_target
                    try:
                        with Session(self.engine) as auth_session:
                            target_obj = recheck_authorized_target(
                                auth_target_id, auth_session, target, config.get('tools', [])
                            )
                    except Exception as auth_err:
                        audit_authorization_failure(self.engine, auth_target_id, scan_id, str(auth_err))
                        self.execution(execution_id, 'blocked', f'Authorization invalidated before execution: {redact(str(auth_err))}')
                        for remaining_id, _ in executions[current_idx + 1:]:
                            self.execution(remaining_id, 'blocked', 'Target authorization is no longer valid.')
                        break
                adapter = ADAPTERS[name]
                # A tool may stay safety-disabled behind an explicit operator
                # opt-in read by its adapter, so installation alone never enables
                # it. The recorded metadata carries no configured values.
                opt_in = getattr(adapter, 'opt_in_enabled', None)
                opted_in = opt_in() if opt_in else True
                if hasattr(adapter, 'DISABLED') and not opted_in:
                    self.metadata(scan_id, name, disabled=True)
                    self.execution(execution_id, 'skipped', adapter.DISABLED); continue
                if opt_in is not None:
                    self.metadata(scan_id, name, opt_in=True)
                executable = find_argv(adapter.COMMANDS)
                if not executable:
                    self.execution(execution_id, 'unavailable', 'Executable not found on PATH.'); continue
                # Approved-digest pinning: hash the artifact before anything runs.
                # A mismatch, a missing pinned binary or an unreadable digest
                # refuses execution here, and no binary is ever replaced.
                integrity = getattr(adapter, 'integrity_status', None)
                if integrity:
                    integrity_res = integrity(executable)
                    self.metadata(scan_id, name, integrity=redact(integrity_res['status']),
                                  integrity_expected=redact(integrity_res.get('expected')),
                                  integrity_actual=redact(integrity_res.get('actual')))
                    if blocks_execution(integrity_res['status']):
                        self.execution(execution_id, 'configuration_required', integrity_res['message']); continue
                valid, version = verify(name, executable)
                if not valid:
                    _, _, status, reason = diagnose(name, executable)
                    self.execution(execution_id, {'blocked': 'blocked', 'missing': 'unavailable'}.get(status, 'failed'), reason); continue
                self.metadata(scan_id, name, version=version)
                issue = getattr(adapter, 'configuration_error', lambda: None)()
                if issue:
                    self.execution(execution_id, 'configuration_required', issue); continue
                skip_reason = None
                if profile == 'local':
                    inputs = [target]
                elif name == 'nmap':
                    inputs = list(addresses)
                elif name == 'subfinder':
                    from .target_validation import parse_target_endpoint
                    try:
                        host_to_check = parse_target_endpoint(canonical_endpoint or target).host
                    except Exception:
                        host_to_check = target
                    try:
                        ipaddress.ip_address(host_to_check)
                        inputs = []
                        skip_reason = 'Target is an IP address; subdomain enumeration is only applicable to domain targets.'
                    except ValueError:
                        inputs = [host_to_check]
                elif name == 'httpx':
                    if canonical_endpoint and canonical_endpoint.startswith(('http://', 'https://')):
                        if canonical_endpoint not in web_services and not canonical_reach_err:
                            from .reachability import check_endpoint_reachability
                            reachable, reach_err = check_endpoint_reachability(canonical_endpoint, timeout=2.0)
                            if reachable:
                                web_services.append(canonical_endpoint)
                            else:
                                canonical_reach_err = reach_err
                    if web_services:
                        inputs = sorted(set(web_services))
                    else:
                        inputs = []
                        if canonical_reach_err:
                            skip_reason = f"Target web service is unreachable: '{canonical_endpoint}' ({canonical_reach_err})."
                        else:
                            skip_reason = 'No relevant in-scope service discovered by prerequisite tools.'
                else:
                    web_candidates = {a['address'] for a in all_assets if a['kind'] == 'web'}
                    if not web_candidates:
                        httpx_attempted = any(executions[i][1] == 'httpx' for i in range(current_idx))
                        if not httpx_attempted and canonical_endpoint and canonical_endpoint in web_services:
                            web_candidates = {canonical_endpoint}
                    inputs = sorted(web_candidates)
                    if name == 'sslyze':
                        https_candidates = [url for url in inputs if url.startswith('https://')]
                        if not https_candidates and inputs:
                            skip_reason = 'Target is an HTTP-only service; TLS/SSL auditing requires an HTTPS service.'
                        inputs = https_candidates
                    elif not inputs and canonical_reach_err:
                        skip_reason = f"Target web service is unreachable: '{canonical_endpoint}' ({canonical_reach_err})."


                if not inputs:
                    reason = skip_reason or 'No relevant in-scope service discovered by prerequisite tools.'
                    self.execution(execution_id, 'skipped', reason); continue
                self.execution(execution_id, 'running')
                state, error, exit_code = 'completed', None, None
                finding_start = len(all_findings)
                attempts = 0
                for destination in inputs:
                    if cancel.is_set(): state = 'cancelled'; break
                    with TemporaryDirectory(prefix='ava-tool-') as temporary:
                        output = Path(temporary) / 'result.json'
                        scan_destination = destination
                        if profile == 'local':
                            validate_local(target, self.settings.allowed_local_roots)
                            scan_destination = str(Path(temporary) / 'source')
                            info = snapshot(target, scan_destination, cancel)
                            self.metadata(scan_id, name, snapshot=info)
                        else:
                            fresh = validate_target(target, self.settings.allowed_targets, self.settings.allow_private_targets)
                            if sorted(fresh.addresses) != sorted(addresses):
                                raise ValueError('DNS changed before invocation.')
                        if auth_target_id:
                            from .scope_validator import audit_authorization_failure, check_destination_excluded, recheck_authorized_target
                            try:
                                with Session(self.engine) as auth_session:
                                    target_obj = recheck_authorized_target(
                                        auth_target_id, auth_session, target, config.get('tools', [])
                                    )
                            except Exception as auth_err:
                                audit_authorization_failure(self.engine, auth_target_id, scan_id, str(auth_err))
                                state, error = 'blocked', f'{name}: Authorization invalidated before execution: {redact(str(auth_err))}'
                                break
                            exclusion_msg = check_destination_excluded(scan_destination, target_obj)
                            if exclusion_msg:
                                state, error = 'blocked', exclusion_msg
                                break
                        target_rps = target_obj.rate_limit_rps if target_obj else 10
                        try:
                            claim_ctx = (
                                coordinator.claim(
                                    target_id=auth_target_id,
                                    configured_rps=target_rps,
                                    tool=name,
                                    cancel=cancel,
                                    timeout=TOOL_TIMEOUT,
                                )
                                if auth_target_id
                                else nullcontext(None)
                            )
                            with claim_ctx as allocated_rps:
                                # Post-wait recheck: authorization may have expired or been revoked while waiting for rate budget
                                if auth_target_id:
                                    from .scope_validator import recheck_authorized_target
                                    with Session(self.engine) as auth_session:
                                        target_obj = recheck_authorized_target(
                                            auth_target_id, auth_session, target, config.get('tools', [])
                                        )
                                    from .scope_validator import ScopeAuthorizationError, check_destination_excluded
                                    exclusion_msg = check_destination_excluded(scan_destination, target_obj)
                                    if exclusion_msg:
                                        raise ScopeAuthorizationError(exclusion_msg)

                                if cancel.is_set():
                                    state = 'cancelled'; break

                                effective_rps = allocated_rps if allocated_rps is not None else target_rps
                                if name in {'nmap', 'httpx', 'nuclei', 'subfinder'}:
                                    if name == 'nmap' and target_port is not None:
                                        # pyrefly: ignore[unexpected-keyword]
                                        command = adapter.command(executable, scan_destination, profile, output, rate_limit=effective_rps, target_port=target_port)
                                    else:
                                        # pyrefly: ignore[unexpected-keyword]
                                        command = adapter.command(executable, scan_destination, profile, output, rate_limit=effective_rps)
                                else:
                                    command = adapter.command(executable, scan_destination, profile, output)

                                attempts += 1
                                self.metadata(scan_id, name, attempted_invocations=attempts)
                                result = run(command, timeout=TOOL_TIMEOUT, cancel=cancel, cwd=temporary, output_files=(output,))
                                exit_code = result.exit_code
                                if result.state != 'completed':
                                    evidence = policy_block_evidence(result)
                                    state = 'blocked' if evidence else result.state
                                    detail = (f'Confirmed Windows policy block: {redact(evidence)}.' if evidence
                                              else redact(result.stderr[-1000:]))
                                    error = f'{name}: {state}. ' + ('Diagnostic output withheld for local scans to protect secret values.' if profile == 'local' or name == 'subfinder' else detail)
                                    break
                                if getattr(adapter, 'FILE_OUTPUT', False):
                                    if not output.is_file() or output.stat().st_size > 2_000_000:
                                        state, error = 'failed', 'Missing or oversized machine-readable output.'; break
                                    text = output.read_text(encoding='utf-8')
                                else: text = result.stdout
                        except RateLimitCancelledError:
                            state, error = 'cancelled', 'Cancelled while waiting for target rate budget.'
                            break
                        except RateLimitPolicyError as policy_err:
                            state, error = 'blocked', str(policy_err)
                            break
                        except TimeoutError as to_err:
                            state, error = 'timed_out', str(to_err)
                            break
                        except ValueError as recheck_err:
                            from .scope_validator import ScopeAuthorizationError, audit_authorization_failure
                            if isinstance(recheck_err, ScopeAuthorizationError):
                                audit_authorization_failure(
                                    self.engine, auth_target_id, scan_id, str(recheck_err)
                                )
                                state, error = 'blocked', f'Authorization invalidated: {redact(str(recheck_err))}'
                                break
                            state, error = 'configuration_required', 'Tool configuration is incomplete or invalid; see setup instructions.'
                            break
                        except Exception as recheck_err:
                            state, error = 'failed', f'{name}: invocation failed ({type(recheck_err).__name__}).'
                            break
                        try:
                            parsed = adapter.parse(text, scan_destination)
                            if profile == 'local':
                                for item in parsed.findings: item['target'] = target
                                for item in parsed.assets: item['address'] = target
                        except (ValueError, KeyError, TypeError, AttributeError, SyntaxError) as exc:
                            state, error = 'failed', f'Unsupported or malformed {name} output ({type(exc).__name__}).'; break
                        all_assets.extend(parsed.assets)
                        all_findings.extend(parsed.findings)
                        if parsed.errors:
                            state = 'failed'
                            error = f'{name}: requested checks did not complete ({", ".join(parsed.errors)}).'
                            break
                        if name == 'nmap':
                            for asset in parsed.assets:
                                port = asset['details'].get('port')
                                if asset['kind'] == 'port':
                                    is_target_port = (target_port is not None and port == target_port)
                                    is_std_web = port in {80, 443, 3000, 8000, 8443}
                                    service_name = str(asset['details'].get('service', {}).get('name', '')).lower()
                                    is_web_service = is_target_port or is_std_web or service_name in {'http', 'https', 'ssl', 'http-proxy', 'http-alt'}
                                    if is_web_service:
                                        host = '[' + destination + ']' if ':' in destination else destination
                                        if is_target_port and target_scheme:
                                            scheme = target_scheme
                                        elif port in {443, 8443} or service_name in {'https', 'ssl'}:
                                            scheme = 'https'
                                        else:
                                            scheme = 'http'
                                        svc_url = f'{scheme}://{host}:{port}'
                                        if svc_url not in web_services:
                                            web_services.append(svc_url)
                            if canonical_endpoint and canonical_endpoint.startswith(('http://', 'https://')):
                                from .reachability import check_endpoint_reachability
                                if canonical_endpoint not in web_services:
                                    reachable, _ = check_endpoint_reachability(canonical_endpoint, timeout=3.0)
                                    if reachable:
                                        web_services.append(canonical_endpoint)
                self.metadata(scan_id, name, finding_count=len(all_findings) - finding_start,
                    limitations=('Passive sources may omit results when keys/providers are unavailable; empty output is not proof of complete enumeration.' if name == 'subfinder' else None))
                self.execution(execution_id, state, error, exit_code)
                if state == 'completed':
                    try:
                        from .tool_manager import persist_tool_verification
                        persist_tool_verification(
                            self.engine, name, version=version, executable=executable,
                            execution_id=execution_id, evidence_reference=f"scan:{scan_id}"
                        )
                    except Exception:
                        pass
                if state == 'completed' and 'text' in locals() and text:
                    try:
                        from .evidence_service import store_evidence
                        store_evidence(
                            target=self.engine,
                            data_dir=self.settings.data_dir,
                            scan_id=scan_id,
                            tool=name,
                            evidence_type='raw_output',
                            content=text,
                            filename=f'{name}_output.txt',
                            execution_id=execution_id,
                            redacted=(profile == 'local' or name == 'subfinder'),
                        )
                    except Exception:
                        pass
                # Commit intermediate results, so the monitor reflects real work.
                with Session(self.engine) as session:
                    scan = session.get(Scan, scan_id)
                    seen = {json.dumps({'address': a.address, 'kind': a.kind, 'details': a.details}, sort_keys=True) for a in scan.assets}
                    for asset in all_assets:
                        safe_asset = redact(asset)
                        key = json.dumps(safe_asset, sort_keys=True)
                        if key not in seen:
                            seen.add(key); scan.assets.append(Asset(**safe_asset))
                    existing = {finding.fingerprint: finding for finding in scan.findings}
                    for finding in deduplicate(all_findings):
                        saved = existing.get(finding['fingerprint'])
                        if saved:
                            saved.title, saved.severity, saved.details = finding['title'], finding['severity'], finding
                            saved.last_seen = now()
                        else:
                            scan.findings.append(Finding(fingerprint=finding['fingerprint'], title=finding['title'],
                                                         severity=finding['severity'], details=finding))
                    session.commit()
            with self.lock, Session(self.engine) as session:
                scan = session.get(Scan, scan_id)
                states = [e.state for e in scan.executions]
                if cancel.is_set():
                    scan.state = 'cancelled'
                elif 'completed' not in states:
                    scan.state = 'failed'
                elif any(s not in {'completed', 'skipped'} for s in states):
                    scan.state = 'completed_with_errors'
                else:
                    scan.state = 'completed'
                scan.ended_at = now()
                session.commit()
                scan_data = serialize(session, scan)
                scan_state = scan.state
                scan_target = scan.target
                scan_profile = scan.profile
                scan_findings_len = len(scan.findings)

                try:
                    write_reports(self.settings.data_dir, scan_data)
                except Exception:
                    pass
            try:
                from .audit_service import log_event
                log_event(
                    target=self.engine,
                    event_type=f'scan_{scan_state}',
                    actor='worker',
                    resource_type='scan',
                    resource_id=scan_id,
                    details={'state': scan_state, 'target': scan_target, 'profile': scan_profile, 'findings': scan_findings_len},
                )
            except Exception:
                pass
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error("Worker exception in scan %s: %s", scan_id, exc, exc_info=True)
            # Do not expose tracebacks, scanner internals or service credentials.


            with Session(self.engine) as session:
                scan = session.get(Scan, scan_id)
                if scan:
                    scan.state, scan.ended_at = ('cancelled' if cancel.is_set() else 'failed'), now()
                    scan.configuration = dict(scan.configuration, failure='Scan could not finish. Check scope, dependencies and supported output formats.')
                    for execution in scan.executions:
                        if execution.state in {'running', 'queued'}:
                            execution.state, execution.error, execution.ended_at = scan.state, 'Workflow interrupted.', now()
                    session.commit()
                    try: write_reports(self.settings.data_dir, serialize(session, scan))
                    except OSError: pass
        finally:
            with self.lock: self.events.pop(scan_id, None)
            self.capacity.release()

    def shutdown(self):
        for event in list(self.events.values()): event.set()
        self.pool.shutdown(wait=True, cancel_futures=False)
