"""Policy evaluation: matching, precedence, fail-closed defaults and file loading."""

import json

import pytest

from services.security.policy import (
    ALLOW, BLOCK, REQUIRE_APPROVAL, PolicyEngine, PolicyError, Rule, load_policy, parse_rule,
)


def engine(*rules, default=BLOCK):
    return PolicyEngine(rules, default_effect=default)


def test_matching_rule_decides():
    e = engine(Rule("r1", ALLOW, action="file.read"))
    d = e.evaluate("file.read")
    assert d.verdict == ALLOW and d.rule_id == "r1" and d.allowed


def test_unmatched_action_fails_closed_by_default():
    d = engine(Rule("r1", ALLOW, action="file.read")).evaluate("file.delete")
    assert d.verdict == BLOCK and d.rule_id is None and not d.allowed


def test_default_effect_can_be_relaxed_explicitly():
    assert engine(default=ALLOW).evaluate("anything").verdict == ALLOW


def test_block_beats_a_broader_allow_whatever_the_order():
    allow_all = Rule("allow-all", ALLOW)
    block_prod = Rule("no-prod", BLOCK, action="db.*", scope="prod/*")
    for rules in ((allow_all, block_prod), (block_prod, allow_all)):
        d = engine(*rules).evaluate("db.drop", scope="prod/main")
        assert d.verdict == BLOCK and d.rule_id == "no-prod"
        assert set(d.matched) == {"allow-all", "no-prod"}


def test_require_approval_beats_allow_but_loses_to_block():
    allow = Rule("a", ALLOW)
    gate = Rule("g", REQUIRE_APPROVAL, action="deploy.*")
    block = Rule("b", BLOCK, action="deploy.prod")
    assert engine(allow, gate).evaluate("deploy.stage").verdict == REQUIRE_APPROVAL
    assert engine(allow, gate, block).evaluate("deploy.prod").verdict == BLOCK


def test_tool_and_scope_narrow_a_rule():
    e = engine(Rule("r", ALLOW, action="run", tool="shell", scope="sandbox/*"))
    assert e.evaluate("run", "shell", "sandbox/a").verdict == ALLOW
    assert e.evaluate("run", "python", "sandbox/a").verdict == BLOCK
    assert e.evaluate("run", "shell", "prod/a").verdict == BLOCK


def test_matching_is_case_sensitive():
    assert engine(Rule("r", ALLOW, action="File.Read")).evaluate("file.read").verdict == BLOCK


def test_reason_is_carried_into_the_decision():
    d = engine(Rule("r", BLOCK, action="x", reason="needs a ticket")).evaluate("x")
    assert d.reason == "needs a ticket"


@pytest.mark.parametrize(
    "raw",
    [
        {"id": "r", "effect": "maybe"},
        {"effect": "allow"},
        {"id": "", "effect": "allow"},
        {"id": "r", "effect": "allow", "action": 5},
        {"id": "r", "effect": "allow", "colour": "red"},
        "not a mapping",
    ],
)
def test_malformed_rules_are_rejected(raw):
    with pytest.raises(PolicyError):
        parse_rule(raw)


def test_duplicate_ids_and_bad_default_are_rejected():
    with pytest.raises(PolicyError):
        engine(Rule("r", ALLOW), Rule("r", BLOCK))
    with pytest.raises(PolicyError):
        PolicyEngine([], default_effect="whatever")


def test_load_json_policy(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"default": "block", "rules": [{"id": "r", "effect": "allow", "action": "ok"}]}))
    assert load_policy(path).evaluate("ok").verdict == ALLOW


def test_load_policy_reports_bad_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(PolicyError):
        load_policy(bad)
    nolist = tmp_path / "nolist.json"
    nolist.write_text(json.dumps({"rules": "x"}))
    with pytest.raises(PolicyError):
        load_policy(nolist)


def test_load_yaml_policy_when_available(tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"rules": [{"id": "r", "effect": "require_approval", "action": "pay.*"}]}))
    assert load_policy(path).evaluate("pay.out").verdict == REQUIRE_APPROVAL
