import re

import yaml

VALID_ACTIONS = {"allow", "ask", "block"}
KNOWN_TOOL_KEYS = {
    "action", "blocked_path_patterns", "allowed_recipient_domains",
    "blocked_attachment_patterns", "allowed_payees", "max_amount",
    # Phase 4
    "max_calls", "max_total_amount", "max_body_chars", "blocked_body_patterns",
}
_POSITIVE_NUMBERS = ("max_amount", "max_total_amount")
_POSITIVE_INTS = ("max_calls", "max_body_chars")
_STRING_LISTS = ("blocked_path_patterns", "allowed_recipient_domains", "blocked_attachment_patterns",
                 "allowed_payees", "blocked_body_patterns")


def validate_policy(policy: dict) -> dict:
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a YAML mapping")
    policy.setdefault("default_action", "block")
    policy.setdefault("tools", {})
    if policy["default_action"] not in VALID_ACTIONS:
        raise ValueError(f"default_action must be one of {sorted(VALID_ACTIONS)}")
    if not isinstance(policy["tools"], dict):
        raise ValueError("'tools' must be a mapping")
    for tool, rules in policy["tools"].items():
        if not isinstance(rules, dict):
            raise ValueError(f"Rules for '{tool}' must be a mapping")
        unknown = set(rules) - KNOWN_TOOL_KEYS
        if unknown:
            raise ValueError(f"Unknown keys for '{tool}': {sorted(unknown)}")
        if rules.get("action", "block") not in VALID_ACTIONS:
            raise ValueError(f"Invalid action for '{tool}'")
        for key in _POSITIVE_NUMBERS:
            if key in rules and (isinstance(rules[key], bool) or not isinstance(rules[key], (int, float))
                                 or rules[key] <= 0):
                raise ValueError(f"'{tool}.{key}' must be a positive number")
        for key in _POSITIVE_INTS:
            if key in rules and (isinstance(rules[key], bool) or not isinstance(rules[key], int)
                                 or rules[key] <= 0):
                raise ValueError(f"'{tool}.{key}' must be a positive whole number")
        for key in _STRING_LISTS:
            if key in rules and (not isinstance(rules[key], list)
                                 or not all(isinstance(x, str) for x in rules[key])):
                raise ValueError(f"'{tool}.{key}' must be a list of strings")
        for pattern in rules.get("blocked_body_patterns", []):
            try:
                re.compile(pattern, re.I)
            except re.error as e:
                raise ValueError(f"Bad regex in '{tool}.blocked_body_patterns': {pattern!r} ({e})") from e
    return policy


def load_policy(path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return validate_policy(yaml.safe_load(f))
