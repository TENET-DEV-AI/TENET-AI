"""
Rule loading for the heuristic detector.

Rules live in a YAML file (``rules.yaml`` next to this module by default).
Point ``TENET_RULES_PATH`` at your own file to use custom rules. If the file
is missing or invalid we log the problem and fall back to the built-in rules,
so the analyzer never fails to start because of a bad rules file.

Usage from the command line (run inside services/analyzer):

    python -m model.rules check [path]
    python -m model.rules test-rule "some prompt" [--rules path]
"""
import argparse
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

logger = logging.getLogger(__name__)

RULES_PATH_ENV = "TENET_RULES_PATH"
DEFAULT_RULES_PATH = Path(__file__).with_name("rules.yaml")

CATEGORIES = ("prompt_injection", "jailbreak", "data_extraction", "phishing")


class RulesError(ValueError):
    """Raised when a rules file cannot be loaded or fails validation."""


class Rule(BaseModel):
    """A single detection rule."""

    model_config = ConfigDict(extra="forbid")

    phrase: str
    category: str
    score: float
    enabled: bool = True

    @field_validator("phrase")
    @classmethod
    def _phrase_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("phrase must not be empty")
        return value

    @field_validator("category")
    @classmethod
    def _known_category(cls, value: str) -> str:
        if value not in CATEGORIES:
            raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
        return value

    @field_validator("score")
    @classmethod
    def _score_in_range(cls, value: float) -> float:
        if not 0 <= value <= 1:
            raise ValueError("score must be between 0 and 1")
        return value


def _describe(err: dict) -> str:
    msg = err["msg"]
    if msg.startswith("Value error, "):
        msg = msg[len("Value error, "):]
    field = ".".join(str(p) for p in err["loc"])
    if err["type"] == "missing":
        return f"missing field '{field}'"
    if err["type"] == "extra_forbidden":
        return f"unknown field '{field}'"
    if err["type"] in ("float_parsing", "float_type"):
        return "score must be a number between 0 and 1" if field == "score" else msg
    if err["type"] == "bool_parsing" or err["type"] == "bool_type":
        return f"{field} must be true or false"
    return msg


def parse_rules(data) -> List[Rule]:
    """Validate parsed YAML and return a list of Rule objects.

    Rules are numbered from 1 in error messages, in file order.
    """
    if not isinstance(data, dict) or "rules" not in data:
        raise RulesError("rules file must contain a top-level 'rules' list")
    raw = data["rules"]
    if not isinstance(raw, list):
        raise RulesError("'rules' must be a list")

    rules: List[Rule] = []
    problems: List[str] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            problems.append(f"rule {index}: must be a mapping with phrase, category, score")
            continue
        try:
            rules.append(Rule(**item))
        except ValidationError as exc:
            for err in exc.errors():
                problems.append(f"rule {index}: {_describe(err)}")
    if problems:
        raise RulesError("; ".join(problems))
    return rules


def load_rules_file(path) -> List[Rule]:
    """Load and validate a rules file. Raises RulesError on any problem."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RulesError(f"cannot read rules file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RulesError(f"invalid YAML in {path}: {exc}") from exc
    return parse_rules(data)


def resolve_rules_path(path: Optional[str] = None) -> Path:
    """Explicit path wins, then TENET_RULES_PATH, then the bundled default."""
    chosen = path or os.getenv(RULES_PATH_ENV)
    return Path(chosen) if chosen else DEFAULT_RULES_PATH


def group_rules(rules: List[Rule]) -> Dict[str, Dict[str, float]]:
    """Group enabled rules by category as {category: {phrase: score}}.

    Phrases are lowercased because the detector matches against lowercased
    input. If a phrase appears twice in a category the higher score wins.
    """
    grouped: Dict[str, Dict[str, float]] = {c: {} for c in CATEGORIES}
    for rule in rules:
        if not rule.enabled:
            continue
        phrase = rule.phrase.lower()
        current = grouped[rule.category].get(phrase)
        if current is None or rule.score > current:
            grouped[rule.category][phrase] = rule.score
    return grouped


def match_rules(prompt: str, rules: List[Rule]) -> List[Tuple[Rule, bool]]:
    """Return every rule with whether it matched (used by the dry-run command)."""
    lowered = prompt.lower()
    return [(r, r.enabled and r.phrase.lower() in lowered) for r in rules]


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m model.rules")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate a rules file")
    check.add_argument("path", nargs="?")

    test = sub.add_parser("test-rule", help="show which rules match a prompt")
    test.add_argument("prompt")
    test.add_argument("--rules", dest="path")

    args = parser.parse_args(argv)
    path = resolve_rules_path(args.path)
    try:
        rules = load_rules_file(path)
    except RulesError as exc:
        print(f"error: {exc}")
        return 1

    if args.command == "check":
        enabled = sum(1 for r in rules if r.enabled)
        print(f"ok: {len(rules)} rules ({enabled} enabled) in {path}")
        return 0

    hits = [r for r, matched in match_rules(args.prompt, rules) if matched]
    if not hits:
        print("no rules matched")
        return 0
    for r in sorted(hits, key=lambda r: r.score, reverse=True):
        print(f"{r.score:.2f}  {r.category:16} {r.phrase!r}")
    print(f"max score: {max(r.score for r in hits):.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
