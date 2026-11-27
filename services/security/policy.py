"""Declarative action policy: decide whether an action is allowed, blocked or needs a human.

Rules match on action, tool and scope using shell-style wildcards. When several rules match,
the strictest effect wins (block over require_approval over allow), so a broad allow rule can
never override a specific block. An action that matches no rule gets ``default_effect``, which
is ``block`` unless the caller says otherwise: unknown actions fail closed.

Rules are plain dicts so they load from JSON anywhere and from YAML when PyYAML is installed::

    rules:
      - id: no-prod-delete
        effect: block
        action: "db.delete*"
        scope: "prod/*"
        reason: production deletes need a change ticket
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Union

ALLOW = "allow"
BLOCK = "block"
REQUIRE_APPROVAL = "require_approval"
EFFECTS = (ALLOW, BLOCK, REQUIRE_APPROVAL)

# Higher number wins when several rules match.
_STRICTNESS = {ALLOW: 0, REQUIRE_APPROVAL: 1, BLOCK: 2}


class PolicyError(ValueError):
    """The policy document is malformed."""


def _field_matches(pattern: str, value: Optional[str], effect: str) -> bool:
    if value is None:
        return effect != ALLOW or pattern == "*"
    return fnmatch.fnmatchcase(value, pattern)


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str
    action: str = "*"
    tool: str = "*"
    scope: str = "*"
    reason: str = ""

    def matches(self, action: str, tool: Optional[str] = None, scope: Optional[str] = None) -> bool:
        """Match an action. ``tool`` or ``scope`` of None means the caller did not say.

        An unknown tool or scope could be anything, so a block or require_approval rule applies
        whatever it narrows to, while an allow rule only applies if it does not narrow that field.
        """
        if not fnmatch.fnmatchcase(action, self.action):
            return False
        return _field_matches(self.tool, tool, self.effect) and _field_matches(self.scope, scope, self.effect)


@dataclass(frozen=True)
class Decision:
    verdict: str
    rule_id: Optional[str]
    reason: str
    matched: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW


def parse_rule(raw: Any, index: int = 0) -> Rule:
    if not isinstance(raw, dict):
        raise PolicyError(f"rule {index} must be a mapping, got {type(raw).__name__}")
    effect = raw.get("effect")
    if effect not in EFFECTS:
        raise PolicyError(f"rule {raw.get('id', index)!r}: effect must be one of {', '.join(EFFECTS)}, got {effect!r}")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PolicyError(f"rule {index} needs a non-empty string id")
    values = {}
    for key in ("action", "tool", "scope", "reason"):
        value = raw.get(key, "" if key == "reason" else "*")
        if not isinstance(value, str):
            raise PolicyError(f"rule {rule_id!r}: {key} must be a string")
        values[key] = value
    unknown = set(raw) - {"id", "effect", "action", "tool", "scope", "reason"}
    if unknown:
        raise PolicyError(f"rule {rule_id!r}: unknown field(s) {', '.join(sorted(unknown))}")
    return Rule(id=rule_id, effect=effect, **values)


class PolicyEngine:
    def __init__(self, rules: Iterable[Rule], default_effect: str = BLOCK) -> None:
        if default_effect not in EFFECTS:
            raise PolicyError(f"default_effect must be one of {', '.join(EFFECTS)}, got {default_effect!r}")
        self.rules = tuple(rules)
        for rule in self.rules:
            if rule.effect not in EFFECTS:
                raise PolicyError(f"rule {rule.id!r}: effect must be one of {', '.join(EFFECTS)}, got {rule.effect!r}")
        ids = [r.id for r in self.rules]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise PolicyError(f"duplicate rule id(s): {', '.join(duplicates)}")
        self.default_effect = default_effect

    @classmethod
    def from_document(cls, document: Any) -> "PolicyEngine":
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            raise PolicyError("policy must be a mapping with a 'rules' list")
        unknown = set(document) - {"rules", "default"}
        if unknown:
            raise PolicyError(f"policy has unknown field(s) {', '.join(sorted(map(str, unknown)))}")
        rules = [parse_rule(raw, i) for i, raw in enumerate(document["rules"])]
        return cls(rules, default_effect=document.get("default", BLOCK))

    def evaluate(self, action: str, tool: Optional[str] = None, scope: Optional[str] = None) -> Decision:
        matched = [r for r in self.rules if r.matches(action, tool, scope)]
        if not matched:
            return Decision(self.default_effect, None, "no rule matched; default applies")
        winner = max(matched, key=lambda r: _STRICTNESS[r.effect])
        return Decision(
            winner.effect, winner.id, winner.reason or f"matched rule {winner.id}",
            tuple(r.id for r in matched),
        )


def _reject_duplicate_pairs(pairs: list) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate key {key!r} in policy")
        result[key] = value
    return result


def _strict_yaml_loader(yaml: Any) -> Any:
    class StrictLoader(yaml.SafeLoader):  # type: ignore[misc,name-defined]
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict:
        # Only keys written in this mapping count: a "<<" merge may be overridden on purpose.
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = loader.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError as exc:
                raise PolicyError(f"policy keys must be plain values, got {key!r}") from exc
            if duplicate:
                raise PolicyError(f"duplicate key {key!r} in policy")
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    return StrictLoader


def load_policy(path: Union[str, Path]) -> PolicyEngine:
    """Load a policy file. JSON always works; YAML needs PyYAML."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise PolicyError("YAML policies need PyYAML (pip install pyyaml); JSON policies need nothing") from exc
        try:
            document = yaml.load(text, Loader=_strict_yaml_loader(yaml))  # noqa: S506 - SafeLoader subclass
        except yaml.YAMLError as exc:
            raise PolicyError(f"{p.name} is not valid YAML: {exc}") from exc
    else:
        try:
            document = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{p.name} is not valid JSON: {exc}") from exc
    return PolicyEngine.from_document(document)
