"""Phase 3 - Shared Per-Authorized-Target Rate Budget Coordinator.

Provides thread-safe, aggregate rate budgeting across concurrent assessments
and tools operating against the same authorized target.

Design Invariants:
1. Independent Budgets: Target A's claims never consume or block Target B's capacity.
2. Aggregate Invariant: For any target T, sum(active_claims(T)) <= T.rate_limit_rps.
3. Unit Realism:
   - Nmap: packet probe rate (--max-rate)
   - HTTPX: HTTP request rate (-rate-limit)
   - Nuclei: template request rate (-rl)
   - Subfinder: passive provider API queries (-rl; 0 direct target requests)
   - WhatWeb: single unredirected root request (1 unit capacity)
   - SSLyze: 7 rapid unthrottled TLS handshakes; fails closed if target < 7 RPS
   - Wapiti: 0 units; its own conservative task/scan-force/deadline flags bound
     request volume, and it has no request-rate option to allocate
   - Local (Gitleaks, Trivy): 0 network capacity required
4. Strict Serialization at R = 1: Exactly 1 network tool can run at a time.
5. Guaranteed Cleanup: Context manager guarantees claim release on exit, cancel, or crash.
6. Single-Process Scope: Coordinates threads within the PATROLMAN backend process.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional
from uuid import uuid4


class RateLimitPolicyError(Exception):
    """Raised when a tool cannot safely comply with the target's rate limit."""
    pass


class RateLimitCancelledError(Exception):
    """Raised when a thread waiting for rate budget is cancelled."""
    pass


@dataclass
class TargetBudget:
    target_id: str
    configured_rps: int
    # claim_id -> allocated_units
    active_claims: Dict[str, int] = field(default_factory=dict)

    @property
    def allocated_units(self) -> int:
        return sum(self.active_claims.values())

    @property
    def available_units(self) -> int:
        return max(0, self.configured_rps - self.allocated_units)


# Required capacity units per tool
TOOL_MIN_CAPACITY = {
    'nmap': 1,
    'httpx': 1,
    'nuclei': 1,
    'subfinder': 1,
    'whatweb': 1,
    'sslyze': 7,    # SSLyze performs 7 unthrottled handshakes
    'wapiti': 0,    # Conservative internal rate flags; no --rate-limit option
    'gitleaks': 0,  # Local filesystem
    'trivy': 0,     # Local filesystem
}


class TargetRateBudgetCoordinator:
    """Thread-safe aggregate rate-budget coordinator for authorized targets.

    Valid strictly for single-process backend architectures. Uses threading.Condition
    to synchronize worker threads without busy-waiting.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        # target_id -> TargetBudget
        self._budgets: Dict[str, TargetBudget] = {}

    def get_or_create_budget(self, target_id: str, configured_rps: int) -> TargetBudget:
        with self._lock:
            budget = self._budgets.get(target_id)
            if budget is None:
                budget = TargetBudget(target_id=target_id, configured_rps=max(1, int(configured_rps)))
                self._budgets[target_id] = budget
            else:
                budget.configured_rps = max(1, int(configured_rps))
            return budget

    def update_target_capacity(self, target_id: str, configured_rps: int) -> None:
        """Update target limit dynamically; notifies waiting threads if capacity increased."""
        with self._lock:
            if target_id in self._budgets:
                self._budgets[target_id].configured_rps = max(1, int(configured_rps))
                self._cv.notify_all()

    def get_allocated_units(self, target_id: str) -> int:
        with self._lock:
            budget = self._budgets.get(target_id)
            return budget.allocated_units if budget else 0

    def get_available_units(self, target_id: str) -> int:
        with self._lock:
            budget = self._budgets.get(target_id)
            return budget.available_units if budget else 0

    def get_active_claim_count(self, target_id: str) -> int:
        with self._lock:
            budget = self._budgets.get(target_id)
            return len(budget.active_claims) if budget else 0

    def _calculate_claim_allocation(self, budget: TargetBudget, tool: str) -> int:
        """Calculate the units to allocate for a tool, or 0 if insufficient capacity."""
        needed = TOOL_MIN_CAPACITY.get(tool, 1)
        if needed == 0:
            return 0  # Offline / passive tool requires no network budget

        # Fail-closed for SSLyze if configured aggregate limit is below its handshake burst
        if tool == 'sslyze':
            if budget.configured_rps < 7:
                raise RateLimitPolicyError(
                    f'Target rate limit ({budget.configured_rps} req/s) is below the SSLyze '
                    f'handshake burst requirement (7). Method tls_audit is blocked for this target.'
                )
            if budget.available_units >= 7:
                return 7
            return 0  # Wait for full 7 units

        if tool == 'whatweb':
            # Single HTTP request
            return 1 if budget.available_units >= 1 else 0

        # Nmap, HTTPX, Nuclei, Subfinder: variable native limit
        if budget.available_units < 1:
            return 0  # Must wait

        # Integer partition among active claimants
        active_count = len(budget.active_claims) + 1
        fair_share = max(1, budget.configured_rps // active_count)
        allocation = min(budget.available_units, fair_share)
        return max(1, allocation)

    def acquire(
        self,
        target_id: str,
        configured_rps: int,
        tool: str,
        claim_id: Optional[str] = None,
        timeout: Optional[float] = None,
        cancel: Optional[threading.Event] = None,
    ) -> tuple[str, int]:
        """Acquire a slice of the target's rate budget, blocking safely if capacity is exhausted.

        Returns
        -------
        (claim_id, allocated_rps)
        """
        claim_id = claim_id or str(uuid4())
        needed = TOOL_MIN_CAPACITY.get(tool, 1)

        # Tools requiring 0 units bypass lock acquisition
        if needed == 0:
            return claim_id, 0

        deadline = (time.monotonic() + timeout) if timeout else None

        with self._lock:
            budget = self.get_or_create_budget(target_id, configured_rps)

            # Check policy requirements before entering queue
            if tool == 'sslyze' and budget.configured_rps < 7:
                raise RateLimitPolicyError(
                    f'Target rate limit ({budget.configured_rps} req/s) is below the SSLyze '
                    f'handshake burst requirement (7). Method tls_audit is blocked for this target.'
                )

            while True:
                if cancel and cancel.is_set():
                    raise RateLimitCancelledError('Cancelled while waiting for target rate budget.')

                alloc = self._calculate_claim_allocation(budget, tool)
                if alloc > 0:
                    budget.active_claims[claim_id] = alloc
                    return claim_id, alloc

                # Wait for capacity with periodic poll to respect cancellation and timeouts
                wait_time = 0.1
                if deadline:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(f'Timed out waiting for rate budget on target {target_id}.')
                    wait_time = min(wait_time, remaining)

                self._cv.wait(timeout=wait_time)

    def release(self, target_id: str, claim_id: str) -> None:
        """Release an allocated claim and notify waiting claimants."""
        with self._lock:
            budget = self._budgets.get(target_id)
            if budget and claim_id in budget.active_claims:
                del budget.active_claims[claim_id]
                self._cv.notify_all()

    @contextmanager
    def claim(
        self,
        target_id: str,
        configured_rps: int,
        tool: str,
        claim_id: Optional[str] = None,
        timeout: Optional[float] = None,
        cancel: Optional[threading.Event] = None,
    ) -> Iterator[int]:
        """Context manager guaranteeing claim release on normal return, error, or cancellation."""
        cid, allocated_rps = self.acquire(
            target_id, configured_rps, tool, claim_id=claim_id, timeout=timeout, cancel=cancel
        )
        try:
            yield allocated_rps
        finally:
            self.release(target_id, cid)

    def reset(self) -> None:
        """Discard all state; used in tests and simulated process restart."""
        with self._lock:
            self._budgets.clear()
            self._cv.notify_all()


# Process-wide coordinator singleton
coordinator = TargetRateBudgetCoordinator()
