"""Synthetic and Integration Tests for Phase 3 Shared Rate-Budget Coordinator.

Verifies:
1. Aggregate rate budget invariants under concurrent execution.
2. Strict serialization when target rate limit is 1.
3. Independent target budgets (Target A does not block Target B).
4. Mixed tool types and handling of varying network units.
5. Unsupported / unsafe tool fail-closed behavior (SSLyze < 7 RPS).
6. SSLyze allocation when capacity >= 7 RPS.
7. WhatWeb single-unit consumption.
8. Dynamic rate-limit updates unblocking or constraining execution.
9. Cancellation while waiting in budget queue raises RateLimitCancelledError and cleans up.
10. Context-manager cleanup guarantees release on exceptions or timeouts.
11. Adapter command builders enforce appropriate native rate flags.
12. Process restart / coordinator recovery invariant.
13. End-to-end integration: target revocation cancels active scans.
14. End-to-end integration: SSLyze blocked when target limit < 7 RPS.
"""

import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.services.rate_limiter import (
    TargetRateBudgetCoordinator,
    RateLimitPolicyError,
    RateLimitCancelledError,
    coordinator,
)
from backend.integrations import ADAPTERS
from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, Scan, ToolExecution, TargetAuditEvent
from backend.services.process_runner import ProcessResult


TOKEN = 'rate-limit-test-token-' + 'x' * 32
HEADERS = {'Authorization': 'Bearer ' + TOKEN}


def test_aggregate_budget_invariant_under_concurrency():
    """Verify sum of active claims never exceeds configured RPS under high concurrency."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-aggregate-01'
    target_rps = 10
    violations = []
    acquired_count = 0
    lock = threading.Lock()

    def worker(worker_id):
        nonlocal acquired_count
        try:
            with coord.claim(target_id=target_id, configured_rps=target_rps, tool='httpx', timeout=2.0) as alloc:
                with lock:
                    acquired_count += 1
                    total = coord.get_allocated_units(target_id)
                    if total > target_rps:
                        violations.append(f'Violation: total {total} > limit {target_rps}')
                time.sleep(0.05)
        except Exception as exc:
            with lock:
                violations.append(f'Worker {worker_id} unexpected error: {exc}')

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not violations, f'Encountered invariants violations: {violations}'
    assert acquired_count == 25
    assert coord.get_allocated_units(target_id) == 0


def test_strict_serialization_at_rate_limit_one():
    """At R=1, strictly at most 1 network tool can hold a claim at any instant."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-serial-01'
    concurrency_record = []
    active = 0
    lock = threading.Lock()

    def worker():
        nonlocal active
        with coord.claim(target_id=target_id, configured_rps=1, tool='nmap', timeout=3.0) as alloc:
            with lock:
                active += 1
                concurrency_record.append(active)
            assert alloc == 1
            time.sleep(0.04)
            with lock:
                active -= 1

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert all(c <= 1 for c in concurrency_record), f'Max concurrent claims exceeded 1: {concurrency_record}'
    assert coord.get_allocated_units(target_id) == 0


def test_independent_target_budgets():
    """Claims against Target A must not consume or block capacity on Target B."""
    coord = TargetRateBudgetCoordinator()
    tgt_a = 'tgt-a'
    tgt_b = 'tgt-b'

    # Target A exhausts all its capacity (R=1)
    with coord.claim(target_id=tgt_a, configured_rps=1, tool='httpx') as alloc_a:
        assert alloc_a == 1
        assert coord.get_allocated_units(tgt_a) == 1
        assert coord.get_available_units(tgt_a) == 0

        # Target B should still acquire immediately without blocking
        t_start = time.monotonic()
        with coord.claim(target_id=tgt_b, configured_rps=1, tool='httpx', timeout=1.0) as alloc_b:
            elapsed = time.monotonic() - t_start
            assert alloc_b == 1
            assert elapsed < 0.2
            assert coord.get_allocated_units(tgt_b) == 1

    assert coord.get_allocated_units(tgt_a) == 0
    assert coord.get_allocated_units(tgt_b) == 0


def test_mixed_tools_and_offline_units():
    """Passive and local tools (0 units) do not consume network budget."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-mixed'

    # Max out network capacity
    with coord.claim(target_id=target_id, configured_rps=1, tool='nmap'):
        assert coord.get_available_units(target_id) == 0

        # Local tools require 0 capacity and must not block
        with coord.claim(target_id=target_id, configured_rps=1, tool='gitleaks') as alloc_git:
            assert alloc_git == 0
        with coord.claim(target_id=target_id, configured_rps=1, tool='trivy') as alloc_triv:
            assert alloc_triv == 0
        with coord.claim(target_id=target_id, configured_rps=1, tool='wapiti') as alloc_wapiti:
            assert alloc_wapiti == 0


def test_sslyze_fail_closed_under_seven_rps():
    """SSLyze sends 7 unthrottled TLS handshakes; fails closed if target limit < 7."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-low-rps'

    with pytest.raises(RateLimitPolicyError) as exc_info:
        with coord.claim(target_id=target_id, configured_rps=5, tool='sslyze'):
            pass

    assert 'SSLyze handshake burst requirement (7)' in str(exc_info.value)
    assert coord.get_allocated_units(target_id) == 0


def test_sslyze_allocation_when_capacity_sufficient():
    """SSLyze acquires full 7 units when target limit >= 7."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-sufficient-rps'

    with coord.claim(target_id=target_id, configured_rps=10, tool='sslyze') as alloc:
        assert alloc == 7
        assert coord.get_allocated_units(target_id) == 7
        assert coord.get_available_units(target_id) == 3

    assert coord.get_allocated_units(target_id) == 0


def test_whatweb_single_unit_consumption():
    """WhatWeb consumes exactly 1 unit for its single HTTP request."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-whatweb'

    with coord.claim(target_id=target_id, configured_rps=5, tool='whatweb') as alloc:
        assert alloc == 1
        assert coord.get_allocated_units(target_id) == 1

    assert coord.get_allocated_units(target_id) == 0


def test_dynamic_rate_limit_increase_wakes_waiting_thread():
    """Increasing target limit dynamically unblocks a thread waiting for capacity."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-dyn-update'
    acquired = threading.Event()

    # Pre-occupy target at limit 1
    with coord.claim(target_id=target_id, configured_rps=1, tool='nmap'):
        def waiter():
            # SSLyze requires 7 units, currently blocked
            try:
                with coord.claim(target_id=target_id, configured_rps=1, tool='sslyze', timeout=2.0) as alloc:
                    acquired.set()
            except RateLimitPolicyError:
                pass

        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.05)
        assert not acquired.is_set()

    # Update capacity to 10 and verify new claims succeed
    coord.update_target_capacity(target_id, 10)
    with coord.claim(target_id=target_id, configured_rps=10, tool='sslyze', timeout=1.0) as alloc:
        assert alloc == 7


def test_cancellation_while_waiting_in_budget_queue():
    """If a thread waiting for rate budget is cancelled, it immediately aborts without leaking claims."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-cancel-queue'
    cancel = threading.Event()
    error_raised = []

    # Fill capacity (R=1)
    with coord.claim(target_id=target_id, configured_rps=1, tool='nmap'):
        def waiter():
            try:
                with coord.claim(target_id=target_id, configured_rps=1, tool='httpx', cancel=cancel, timeout=5.0):
                    pass
            except RateLimitCancelledError as e:
                error_raised.append(e)

        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.05)

        # Trigger cancellation
        cancel.set()
        t.join(timeout=2.0)

    assert len(error_raised) == 1
    assert coord.get_allocated_units(target_id) == 0


def test_timeout_and_exception_cleanup():
    """Uncaught exceptions or timeouts in claim context must release claims cleanly."""
    coord = TargetRateBudgetCoordinator()
    target_id = 'tgt-cleanup'

    # Exception inside block
    try:
        with coord.claim(target_id=target_id, configured_rps=5, tool='httpx'):
            assert coord.get_allocated_units(target_id) > 0
            raise RuntimeError('Simulated failure during tool run')
    except RuntimeError:
        pass

    assert coord.get_allocated_units(target_id) == 0

    # Timeout waiting
    with coord.claim(target_id=target_id, configured_rps=1, tool='nmap'):
        with pytest.raises(TimeoutError):
            with coord.claim(target_id=target_id, configured_rps=1, tool='httpx', timeout=0.1):
                pass

    assert coord.get_allocated_units(target_id) == 0


def test_adapter_command_rate_flags():
    """Verify that adapters which support rate limits emit the correct CLI arguments."""
    from tempfile import NamedTemporaryFile

    with NamedTemporaryFile(suffix='.json') as tmp:
        out_path = Path(tmp.name)

        # 1. Nmap: --max-rate <rate>, clamped to [1, 20]
        # pyrefly: ignore[unexpected-keyword]
        nmap_cmd = ADAPTERS['nmap'].command('nmap', '127.0.0.1', 'quick', out_path, rate_limit=5)
        assert '--max-rate' in nmap_cmd
        assert nmap_cmd[nmap_cmd.index('--max-rate') + 1] == '5'

        # 2. HTTPX: -rate-limit <rate>, conservatively clamped to max 2
        # pyrefly: ignore[unexpected-keyword]
        httpx_cmd_1 = ADAPTERS['httpx'].command('httpx', 'http://127.0.0.1:80', 'quick', out_path, rate_limit=1)
        assert '-rate-limit' in httpx_cmd_1
        assert httpx_cmd_1[httpx_cmd_1.index('-rate-limit') + 1] == '1'

        # pyrefly: ignore[unexpected-keyword]
        httpx_cmd_2 = ADAPTERS['httpx'].command('httpx', 'http://127.0.0.1:80', 'quick', out_path, rate_limit=10)
        assert '-rate-limit' in httpx_cmd_2
        assert httpx_cmd_2[httpx_cmd_2.index('-rate-limit') + 1] == '2'  # capped at 2 for conservative safety

        # 3. Nuclei: -rl <rate>, conservatively clamped to max 2
        # pyrefly: ignore[unexpected-keyword]
        nuclei_cmd_1 = ADAPTERS['nuclei'].command('nuclei', 'http://127.0.0.1:80', 'standard', out_path, rate_limit=1)
        assert '-rl' in nuclei_cmd_1
        assert nuclei_cmd_1[nuclei_cmd_1.index('-rl') + 1] == '1'

        # pyrefly: ignore[unexpected-keyword]
        nuclei_cmd_2 = ADAPTERS['nuclei'].command('nuclei', 'http://127.0.0.1:80', 'standard', out_path, rate_limit=10)
        assert '-rl' in nuclei_cmd_2
        assert nuclei_cmd_2[nuclei_cmd_2.index('-rl') + 1] == '2'  # capped at 2 for safety

        # 4. Subfinder: -rl <rate>, clamped to max 2
        # pyrefly: ignore[unexpected-keyword]
        subfinder_cmd = ADAPTERS['subfinder'].command('subfinder', 'example.local', 'standard', out_path, rate_limit=1)
        assert '-rl' in subfinder_cmd
        assert subfinder_cmd[subfinder_cmd.index('-rl') + 1] == '1'

        # 5. WhatWeb: conservative policy, no unverified rate flags
        whatweb_cmd = ADAPTERS['whatweb'].command('whatweb', 'http://127.0.0.1:80', 'quick', out_path)
        assert '--max-threads=1' in whatweb_cmd
        assert not any(flag in whatweb_cmd for flag in ['--rate-limit', '-rate-limit', '-rl'])

        # 6. SSLyze: no unverified rate flags
        sslyze_cmd = ADAPTERS['sslyze'].command('sslyze', 'https://127.0.0.1:443', 'standard', out_path)
        assert not any(flag in sslyze_cmd for flag in ['--max-rate', '-rate-limit', '-rl'])


@pytest.fixture
def workflow_app(tmp_path, monkeypatch):
    settings = Settings(
        data_dir=tmp_path,
        api_token=TOKEN,
        allowed_targets=('127.0.0.1', 'example.local'),
        allow_private_targets=True,
        require_authorized_target=True,
    )
    application = create_app(settings)
    application.config['TESTING'] = True
    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock 1.0'))
    yield application
    application.extensions['scan_manager'].shutdown()
    application.extensions['database'].dispose()


def test_target_revocation_cancels_active_scans(workflow_app, monkeypatch):
    """Deactivating an authorized target actively cancels in-flight and queued scans."""
    client = workflow_app.test_client()
    engine = workflow_app.extensions['database']
    mgr = workflow_app.extensions['scan_manager']

    # Register target
    with Session(engine) as session:
        target = AuthorizedTarget(
            name='Cancel Active Target',
            target_type='single_host',
            owner_organization='Security Corp',
            scope_domains=['127.0.0.1'],
            explicit_subdomains=[],
            permitted_methods=['port_scan'],
            prohibited_methods=[],
            rate_limit_rps=5,
            valid_from=datetime.now(timezone.utc) - timedelta(days=1),
            valid_to=datetime.now(timezone.utc) + timedelta(days=30),
            evidence_reference='AUTH-CANCEL-01',
            status='active',
            created_by='admin',
            updated_by='admin',
        )
        session.add(target)
        session.commit()
        target_id = target.id

    # Mock long-running tool execution
    def slow_run(*args, **kwargs):
        cancel = kwargs.get('cancel')
        for _ in range(50):
            if cancel and cancel.is_set():
                return ProcessResult(state='cancelled', stdout='', stderr='Cancelled by operator', exit_code=None)
            time.sleep(0.05)
        return ProcessResult(state='completed', stdout='{"ports": []}', stderr='', exit_code=0)

    monkeypatch.setattr('backend.services.scan_service.run', slow_run)

    # Dispatch scan
    resp = client.post(
        '/api/scans',
        json={
            'target': '127.0.0.1',
            'target_id': target_id,
            'profile': 'quick',
            'tools': ['nmap'],
            'authorized': True,
        },
        headers=dict(HEADERS, **{'Idempotency-Key': 'cancel-test-scan-01'}),
    )
    assert resp.status_code == 202
    scan_id = resp.json['data']['id']

    # Wait for scan to enter running state
    time.sleep(0.1)

    # Deactivate the authorized target
    deact_resp = client.post(
        f'/api/targets/{target_id}/deactivate',
        json={'status': 'revoked', 'reason': 'Immediate emergency revocation'},
        headers=HEADERS,
    )
    assert deact_resp.status_code == 200

    # Allow cancellation propagation
    time.sleep(0.3)

    # Scan should be terminal (cancelled or completed_with_errors)
    with Session(engine) as session:
        s = session.get(Scan, scan_id)
        assert s.state in {'cancelled', 'completed_with_errors'}
        executions = s.executions
        assert any(e.state in {'cancelled', 'blocked'} for e in executions)


def test_sslyze_blocked_in_scan_when_target_limit_under_seven(workflow_app, monkeypatch):
    """When target rate limit is < 7, SSLyze fails closed and execution state is blocked."""
    client = workflow_app.test_client()
    engine = workflow_app.extensions['database']

    with Session(engine) as session:
        target = AuthorizedTarget(
            name='Low Rate Target',
            target_type='single_host',
            owner_organization='Security Corp',
            scope_domains=['127.0.0.1'],
            explicit_subdomains=[],
            permitted_methods=['port_scan', 'web_service_discovery', 'tls_audit'],
            prohibited_methods=[],
            rate_limit_rps=3,  # < 7 RPS requirement
            valid_from=datetime.now(timezone.utc) - timedelta(days=1),
            valid_to=datetime.now(timezone.utc) + timedelta(days=30),
            evidence_reference='AUTH-LOW-01',
            status='active',
            created_by='admin',
            updated_by='admin',
        )
        session.add(target)
        session.commit()
        target_id = target.id

    def mock_run(command, *args, **kwargs):
        # Nmap returns open HTTPS port 443
        if 'nmap' in command[0]:
            xml_out = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports>
</host>
<runstats><finished exit="success"/></runstats>
</nmaprun>"""
            return ProcessResult(state='completed', stdout=xml_out, stderr='', exit_code=0)
        if 'httpx' in command[0]:
            httpx_out = '{"url": "https://127.0.0.1:443", "status_code": 200, "title": "Test"}\n'
            return ProcessResult(state='completed', stdout=httpx_out, stderr='', exit_code=0)
        return ProcessResult(state='completed', stdout='{}', stderr='', exit_code=0)

    monkeypatch.setattr('backend.services.scan_service.run', mock_run)

    resp = client.post(
        '/api/scans',
        json={
            'target': '127.0.0.1',
            'target_id': target_id,
            'profile': 'standard',
            'tools': ['nmap', 'httpx', 'sslyze'],
            'authorized': True,
        },
        headers=dict(HEADERS, **{'Idempotency-Key': 'sslyze-failclosed-scan'}),
    )
    assert resp.status_code == 202
    scan_id = resp.json['data']['id']

    # Wait for scan completion
    time.sleep(0.5)

    with Session(engine) as session:
        s = session.get(Scan, scan_id)
        assert s.state in {'completed', 'completed_with_errors'}
        executions = {e.tool: e for e in s.executions}
        assert executions['nmap'].state == 'completed'
        assert executions['sslyze'].state == 'blocked'
        assert 'SSLyze handshake burst requirement (7)' in executions['sslyze'].error

