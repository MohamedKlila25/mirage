"""Test every LLM-written Sigma rule before a human sees it.

pySigma parses the rule (bad YAML / bad Sigma -> rejected). We then evaluate its parsed
condition tree directly against our JSON events:

    passes  <=>  fires on the attack it was written for (incl. at least one cited event)
            AND  fires on zero benign events from the real host

Unsupported Sigma features fail closed (rule rejected), never silently "pass".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sigma.conditions import (
    ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT,
    ConditionOR, ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaNull, SigmaNumber, SigmaRegularExpression, SigmaString


class UnsupportedRule(Exception):
    pass


def _get(ev: dict, field_path: str):
    cur = ev
    for part in field_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _match_value(value, actual) -> bool:
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(value, SigmaString):
        if value.contains_special():
            return re.fullmatch(str(value.to_regex().regexp), str(actual), re.IGNORECASE | re.DOTALL) is not None
        return str(value).lower() == str(actual).lower()
    if isinstance(value, SigmaRegularExpression):
        flags = re.IGNORECASE if any("IGNORECASE" in str(f) for f in value.flags) else 0
        return re.search(str(value.regexp), str(actual), flags | re.DOTALL) is not None
    if isinstance(value, SigmaNumber):
        try:
            return float(actual) == float(value.number)
        except (TypeError, ValueError):
            return False
    raise UnsupportedRule(f"value type {type(value).__name__} is not supported by the validator")


def _eval(node, ev: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, ev) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, ev) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], ev)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(node.value, _get(ev, node.field))
    if isinstance(node, ConditionValueExpression):  # keyword search over all string fields
        return any(isinstance(v, str) and _match_value(node.value, v) for v in ev.values())
    raise UnsupportedRule(f"condition node {type(node).__name__} is not supported")


def compile_rule(yaml_text: str):
    rule = SigmaRule.from_yaml(yaml_text)
    conditions = [c.parse() for c in rule.detection.parsed_condition]
    return rule, conditions


def rule_matches(conditions, ev: dict) -> bool:
    return any(_eval(c, ev) for c in conditions)


@dataclass
class RuleValidation:
    passed: bool
    title: str = ""
    attack_hits: list[str] = field(default_factory=list)
    benign_hits: list[str] = field(default_factory=list)
    cited_hits: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def validate_rule(yaml_text: str, attack_events: list[dict], benign_events: list[dict],
                  cited_event_ids: list[str]) -> RuleValidation:
    try:
        rule, conditions = compile_rule(yaml_text)
    except Exception as e:  # any parse problem = rejected (fail closed)
        return RuleValidation(False, reasons=[f"invalid Sigma rule: {type(e).__name__}: {str(e)[:200]}"])
    try:
        attack = [e["event_id"] for e in attack_events if rule_matches(conditions, e)]
        benign = [e["event_id"] for e in benign_events if rule_matches(conditions, e)]
    except UnsupportedRule as e:
        return RuleValidation(False, rule.title, reasons=[f"rejected (fail closed): {e}"])
    cited = [i for i in attack if i in set(cited_event_ids)]
    reasons = []
    if not attack:
        reasons.append("rule does not fire on the recorded attack")
    elif not cited:
        reasons.append("rule fires on the attack but not on the events it claims to detect")
    if benign:
        reasons.append(f"rule fires on {len(benign)} benign event(s): false positives")
    return RuleValidation(not reasons, rule.title, attack, benign, cited, reasons)
