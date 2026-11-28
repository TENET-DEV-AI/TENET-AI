"""Human approval queue for actions whose policy verdict is ``require_approval``.

An approval-gated action waits here. It runs only if a person approves it before the timeout;
a denial, a timeout or an unknown request id all mean it does not run. Nothing is approved by
default and a decision, once made, cannot be changed.

Timeouts are measured on a monotonic clock so that changing the system time cannot stretch or cut
an approval window. ``created_at`` and ``decided_at`` are wall-clock times for the audit trail.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from dataclasses import dataclass, replace
from typing import Callable, Optional

from .policy import ALLOW, BLOCK, REQUIRE_APPROVAL, Decision, PolicyEngine

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"
USED = "used"  # approved, and already spent on one execution


class ApprovalError(RuntimeError):
    """A request was decided twice, or does not exist."""


@dataclass
class ApprovalRequest:
    id: str
    action: str
    tool: str
    scope: str
    rule_id: Optional[str]
    created_at: float  # wall clock
    expires_at: float  # monotonic deadline
    status: str = PENDING
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None
    note: str = ""
    settled_at: Optional[float] = None  # monotonic; drives retention


class ApprovalQueue:
    def __init__(
        self,
        timeout_seconds: float = 900.0,
        clock: Callable[[], float] = time.monotonic,
        retention_seconds: float = 3600.0,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive, finite number")
        if not math.isfinite(retention_seconds) or retention_seconds < 0:
            raise ValueError("retention_seconds must be a non-negative, finite number")
        self.timeout_seconds = timeout_seconds
        self.retention_seconds = retention_seconds
        self._clock = clock
        self._wall_clock = wall_clock
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def submit(self, action: str, tool: str, scope: str, rule_id: Optional[str] = None) -> ApprovalRequest:
        now = self._clock()
        request = ApprovalRequest(
            id=uuid.uuid4().hex, action=action, tool=tool, scope=scope, rule_id=rule_id,
            created_at=self._wall_clock(), expires_at=now + self.timeout_seconds,
        )
        with self._lock:
            self._prune(now)
            self._requests[request.id] = request
            return replace(request)

    def _prune(self, now: float) -> None:
        """Drop settled requests once they are older than the retention period."""
        for request_id, request in list(self._requests.items()):
            self._expire_if_due(request, now)
            if request.status != PENDING and now - request.settled_at >= self.retention_seconds:
                del self._requests[request_id]

    def _expire_if_due(self, request: ApprovalRequest, now: float) -> None:
        if request.status == PENDING and now >= request.expires_at:
            request.status = EXPIRED
            request.decided_at = request.created_at + self.timeout_seconds
            request.settled_at = request.expires_at

    def get(self, request_id: str) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise ApprovalError(f"unknown approval request {request_id}")
            self._expire_if_due(request, self._clock())
            return replace(request)

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            now = self._clock()
            self._prune(now)
            return [replace(r) for r in self._requests.values() if r.status == PENDING]

    def decide(self, request_id: str, approve: bool, approver: str, note: str = "") -> ApprovalRequest:
        if not isinstance(approve, bool):
            raise ApprovalError("approve must be True or False")
        if not approver.strip():
            raise ApprovalError("a decision needs a named approver")
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise ApprovalError(f"unknown approval request {request_id}")
            now = self._clock()  # one reading for the expiry check and the timestamp
            self._expire_if_due(request, now)
            if request.status != PENDING:
                raise ApprovalError(f"request {request_id} is already {request.status}")
            request.status = APPROVED if approve else DENIED
            request.decided_by = approver
            request.decided_at = self._wall_clock()
            request.settled_at = now
            request.note = note
            return replace(request)

    def may_run(self, request_id: str) -> bool:
        """True only for a request a person approved in time and that has not been used yet."""
        try:
            return self.get(request_id).status == APPROVED
        except ApprovalError:
            return False

    def consume(self, request_id: str, action: str, tool: str, scope: str) -> bool:
        """Spend an approval on one execution of exactly this action, tool and scope.

        Returns True once per approved request; a second call, or a request approved for a
        different action, returns False.
        """
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                return False
            now = self._clock()
            self._expire_if_due(request, now)
            if request.status != APPROVED:
                return False
            if (request.action, request.tool, request.scope) != (action, tool, scope):
                return False
            request.status = USED
            return True


@dataclass(frozen=True)
class GateResult:
    decision: Decision
    request_id: Optional[str]
    action: str
    tool: str
    scope: str


class ActionGate:
    """Policy plus approvals: the single place that says whether an action may execute."""

    def __init__(self, policy: PolicyEngine, queue: ApprovalQueue) -> None:
        self.policy = policy
        self.queue = queue

    def check(self, action: str, tool: str, scope: str) -> GateResult:
        decision = self.policy.evaluate(action, tool, scope)
        request_id = None
        if decision.verdict == REQUIRE_APPROVAL:
            request_id = self.queue.submit(action, tool, scope, decision.rule_id).id
        return GateResult(decision, request_id, action, tool, scope)

    def may_execute(self, result: GateResult) -> bool:
        """Re-derive the verdict from policy rather than trusting the result's own claim.

        A gated action runs once: the approval is spent on the first call and must belong to
        this exact action, tool and scope.
        """
        verdict = self.policy.evaluate(result.action, result.tool, result.scope).verdict
        if verdict == BLOCK:
            return False
        if verdict == ALLOW:
            return True
        if result.request_id is None:
            return False
        return self.queue.consume(result.request_id, result.action, result.tool, result.scope)
