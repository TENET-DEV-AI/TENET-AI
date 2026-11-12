"""Human approval queue for actions whose policy verdict is ``require_approval``.

An approval-gated action waits here. It runs only if a person approves it before the timeout;
a denial, a timeout or an unknown request id all mean it does not run. Nothing is approved by
default and a decision, once made, cannot be changed.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from .policy import ALLOW, BLOCK, REQUIRE_APPROVAL, Decision, PolicyEngine

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"


class ApprovalError(RuntimeError):
    """A request was decided twice, or does not exist."""


@dataclass
class ApprovalRequest:
    id: str
    action: str
    tool: str
    scope: str
    rule_id: Optional[str]
    created_at: float
    expires_at: float
    status: str = PENDING
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None
    note: str = ""


class ApprovalQueue:
    def __init__(self, timeout_seconds: float = 900.0, clock: Callable[[], float] = time.time) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds
        self._clock = clock
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def submit(self, action: str, tool: str, scope: str, rule_id: Optional[str] = None) -> ApprovalRequest:
        now = self._clock()
        request = ApprovalRequest(
            id=uuid.uuid4().hex, action=action, tool=tool, scope=scope, rule_id=rule_id,
            created_at=now, expires_at=now + self.timeout_seconds,
        )
        with self._lock:
            self._requests[request.id] = request
        return request

    def _expire_if_due(self, request: ApprovalRequest) -> None:
        if request.status == PENDING and self._clock() >= request.expires_at:
            request.status = EXPIRED
            request.decided_at = request.expires_at

    def get(self, request_id: str) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise ApprovalError(f"unknown approval request {request_id}")
            self._expire_if_due(request)
            return request

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            for request in self._requests.values():
                self._expire_if_due(request)
            return [r for r in self._requests.values() if r.status == PENDING]

    def decide(self, request_id: str, approve: bool, approver: str, note: str = "") -> ApprovalRequest:
        if not approver.strip():
            raise ApprovalError("a decision needs a named approver")
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise ApprovalError(f"unknown approval request {request_id}")
            self._expire_if_due(request)
            if request.status != PENDING:
                raise ApprovalError(f"request {request_id} is already {request.status}")
            request.status = APPROVED if approve else DENIED
            request.decided_by = approver
            request.decided_at = self._clock()
            request.note = note
            return request

    def may_run(self, request_id: str) -> bool:
        """True only for a request a person approved in time."""
        try:
            return self.get(request_id).status == APPROVED
        except ApprovalError:
            return False


@dataclass(frozen=True)
class GateResult:
    decision: Decision
    request_id: Optional[str] = None

    @property
    def runs_now(self) -> bool:
        return self.decision.verdict == ALLOW


class ActionGate:
    """Policy plus approvals: the single place that says whether an action may execute."""

    def __init__(self, policy: PolicyEngine, queue: ApprovalQueue) -> None:
        self.policy = policy
        self.queue = queue

    def check(self, action: str, tool: str = "*", scope: str = "*") -> GateResult:
        decision = self.policy.evaluate(action, tool, scope)
        if decision.verdict == REQUIRE_APPROVAL:
            request = self.queue.submit(action, tool, scope, decision.rule_id)
            return GateResult(decision, request.id)
        return GateResult(decision)

    def may_execute(self, result: GateResult) -> bool:
        if result.decision.verdict == BLOCK:
            return False
        if result.decision.verdict == ALLOW:
            return True
        return result.request_id is not None and self.queue.may_run(result.request_id)
