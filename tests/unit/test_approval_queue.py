"""Approval gating: a gated action waits, runs only on approval, and never on timeout or denial."""

import pytest

from services.security.approvals import (
    DENIED, EXPIRED, PENDING, ActionGate, ApprovalError, ApprovalQueue,
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
    result = gate.check("read.file")
    assert result.runs_now and result.request_id is None and gate.may_execute(result)
    assert gate.queue.pending() == []


def test_blocked_action_never_executes():
    gate, _ = make()
    result = gate.check("wipe.disk")
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
    result = gate.check("deploy.prod")
    gate.queue.decide(result.request_id, True, "alice", "ticket 42")
    assert gate.may_execute(result)
    assert gate.queue.get(result.request_id).decided_by == "alice"


def test_denial_stops_the_action():
    gate, _ = make()
    result = gate.check("deploy.prod")
    gate.queue.decide(result.request_id, False, "alice")
    assert gate.queue.get(result.request_id).status == DENIED and not gate.may_execute(result)


def test_timeout_expires_the_request_and_the_action_does_not_run():
    gate, clock = make(timeout=60)
    result = gate.check("deploy.prod")
    clock.now += 61
    assert gate.queue.get(result.request_id).status == EXPIRED
    assert not gate.may_execute(result) and gate.queue.pending() == []


def test_late_approval_is_refused():
    gate, clock = make(timeout=60)
    result = gate.check("deploy.prod")
    clock.now += 61
    with pytest.raises(ApprovalError):
        gate.queue.decide(result.request_id, True, "alice")
    assert not gate.may_execute(result)


def test_a_decision_cannot_be_changed():
    gate, _ = make()
    result = gate.check("deploy.prod")
    gate.queue.decide(result.request_id, False, "alice")
    with pytest.raises(ApprovalError):
        gate.queue.decide(result.request_id, True, "bob")
    assert not gate.may_execute(result)


def test_unknown_request_and_anonymous_approver_are_refused():
    gate, _ = make()
    with pytest.raises(ApprovalError):
        gate.queue.decide("nope", True, "alice")
    result = gate.check("deploy.prod")
    with pytest.raises(ApprovalError):
        gate.queue.decide(result.request_id, True, "  ")
    assert not gate.queue.may_run("nope")


def test_each_gated_call_gets_its_own_request():
    gate, _ = make()
    a, b = gate.check("deploy.a"), gate.check("deploy.b")
    assert a.request_id != b.request_id
    gate.queue.decide(a.request_id, True, "alice")
    assert gate.may_execute(a) and not gate.may_execute(b)
