"""Approval gating: a gated action waits, runs only on approval, and never on timeout or denial."""

import dataclasses

import pytest

from services.security.approvals import (
    APPROVED, DENIED, EXPIRED, PENDING, USED, GateResult, ActionGate, ApprovalError, ApprovalQueue,
)
from services.security.policy import ALLOW, BLOCK, REQUIRE_APPROVAL, PolicyEngine, Rule


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(timeout=60.0):
    clock = Clock()
    policy = PolicyEngine([
        Rule("ok", ALLOW, action="read.*"),
        Rule("gate", REQUIRE_APPROVAL, action="deploy.*"),
        Rule("deny", BLOCK, action="wipe.*"),
    ])
    return ActionGate(policy, ApprovalQueue(timeout, clock)), clock


def test_allowed_action_runs_without_a_request():
    gate, _ = make()
    result = gate.check("read.file", "ci", "dev/x")
    assert result.runs_now and result.request_id is None and gate.may_execute(result)
    assert gate.queue.pending() == []


def test_blocked_action_never_executes():
    gate, _ = make()
    result = gate.check("wipe.disk", "ci", "dev/x")
    assert result.decision.verdict == BLOCK and not result.runs_now and not gate.may_execute(result)
    assert gate.queue.pending() == []


def test_gated_action_waits_for_a_decision():
    gate, _ = make()
    result = gate.check("deploy.prod", "ci", "prod/api")
    assert result.decision.verdict == REQUIRE_APPROVAL and not result.runs_now
    assert not gate.may_execute(result)
    [pending] = gate.queue.pending()
    assert pending.id == result.request_id and pending.status == PENDING and pending.rule_id == "gate"


def test_approval_lets_the_action_run():
    gate, _ = make()
    result = gate.check("deploy.prod", "ci", "dev/x")
    gate.queue.decide(result.request_id, True, "alice", "ticket 42")
    assert gate.may_execute(result)
    assert gate.queue.get(result.request_id).decided_by == "alice"


def test_denial_stops_the_action():
    gate, _ = make()
    result = gate.check("deploy.prod", "ci", "dev/x")
    gate.queue.decide(result.request_id, False, "alice")
    assert gate.queue.get(result.request_id).status == DENIED and not gate.may_execute(result)


def test_timeout_expires_the_request_and_the_action_does_not_run():
    gate, clock = make(timeout=60)
    result = gate.check("deploy.prod", "ci", "dev/x")
    clock.now += 61
    assert gate.queue.get(result.request_id).status == EXPIRED
    assert not gate.may_execute(result) and gate.queue.pending() == []


def test_late_approval_is_refused():
    gate, clock = make(timeout=60)
    result = gate.check("deploy.prod", "ci", "dev/x")
    clock.now += 61
    with pytest.raises(ApprovalError):
        gate.queue.decide(result.request_id, True, "alice")
    assert not gate.may_execute(result)


def test_a_decision_cannot_be_changed():
    gate, _ = make()
    result = gate.check("deploy.prod", "ci", "dev/x")
    gate.queue.decide(result.request_id, False, "alice")
    with pytest.raises(ApprovalError):
        gate.queue.decide(result.request_id, True, "bob")
    assert not gate.may_execute(result)


def test_unknown_request_and_anonymous_approver_are_refused():
    gate, _ = make()
    with pytest.raises(ApprovalError):
        gate.queue.decide("nope", True, "alice")
    result = gate.check("deploy.prod", "ci", "dev/x")
    with pytest.raises(ApprovalError):
        gate.queue.decide(result.request_id, True, "  ")
    assert not gate.queue.may_run("nope")


def test_each_gated_call_gets_its_own_request():
    gate, _ = make()
    a, b = gate.check("deploy.a", "ci", "dev/x"), gate.check("deploy.b", "ci", "dev/x")
    assert a.request_id != b.request_id
    gate.queue.decide(a.request_id, True, "alice")
    assert gate.may_execute(a) and not gate.may_execute(b)


def test_decision_reads_the_clock_once():
    ticks = iter([1000.0, 1059.0, 1061.0, 1061.0])  # a second read would land past the deadline
    queue = ApprovalQueue(60, lambda: next(ticks))
    request = queue.submit("deploy.x", "ci", "dev/x")
    decided = queue.decide(request.id, True, "alice")
    assert decided.status == APPROVED and decided.decided_at == 1059.0 < request.expires_at


def test_decide_never_stamps_a_decision_after_the_deadline():
    clock = Clock()
    queue = ApprovalQueue(60, clock)
    request = queue.submit("deploy.x", "ci", "dev/x")
    clock.now = request.expires_at
    with pytest.raises(ApprovalError):
        queue.decide(request.id, True, "alice")
    assert queue.get(request.id).status == EXPIRED


def test_returned_requests_are_copies():
    gate, _ = make()
    result = gate.check("deploy.prod", "ci", "dev/x")
    gate.queue.get(result.request_id).status = APPROVED
    gate.queue.pending()[0].status = APPROVED
    assert not gate.queue.may_run(result.request_id) and not gate.may_execute(result)
    decided = gate.queue.decide(result.request_id, False, "alice")
    decided.status = APPROVED
    assert gate.queue.get(result.request_id).status == DENIED


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0, -5])
def test_timeout_must_be_positive_and_finite(bad):
    with pytest.raises(ValueError):
        ApprovalQueue(bad)


def test_settled_requests_are_pruned_after_retention():
    clock = Clock()
    queue = ApprovalQueue(60, clock, retention_seconds=100)
    old = queue.submit("deploy.a", "ci", "dev/x")
    queue.decide(old.id, True, "alice")
    clock.now += 99
    queue.pending()
    assert queue.get(old.id).status == APPROVED
    clock.now += 2
    queue.pending()
    with pytest.raises(ApprovalError):
        queue.get(old.id)
    assert len(queue._requests) == 0


def test_expired_requests_are_pruned_too():
    clock = Clock()
    queue = ApprovalQueue(60, clock, retention_seconds=10)
    request = queue.submit("deploy.a", "ci", "dev/x")
    clock.now += 71
    queue.submit("deploy.b", "ci", "dev/x")
    assert request.id not in queue._requests


def test_an_approval_runs_the_action_once():
    gate, _ = make()
    result = gate.check("deploy.prod", "ci", "dev/x")
    gate.queue.decide(result.request_id, True, "alice")
    assert gate.may_execute(result)
    assert gate.queue.get(result.request_id).status == USED
    assert not gate.may_execute(result)


def test_an_approval_cannot_authorize_a_different_action():
    gate, _ = make()
    a = gate.check("deploy.a", "ci", "dev/x")
    b = gate.check("deploy.b", "ci", "dev/x")
    gate.queue.decide(a.request_id, True, "alice")
    forged = dataclasses.replace(b, request_id=a.request_id)
    assert not gate.may_execute(forged)
    other_scope = GateResult(a.decision, a.request_id, "deploy.a", "ci", "prod/api")
    assert not gate.may_execute(other_scope)
    assert gate.may_execute(a)


def test_a_forged_allow_verdict_does_not_run_a_blocked_action():
    gate, _ = make()
    blocked = gate.check("wipe.disk", "ci", "dev/x")
    forged = dataclasses.replace(blocked, decision=gate.check("read.file", "ci", "dev/x").decision)
    assert not gate.may_execute(forged)


def test_gate_requires_tool_and_scope():
    gate, _ = make()
    with pytest.raises(TypeError):
        gate.check("read.file")
