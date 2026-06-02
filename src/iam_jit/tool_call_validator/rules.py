"""Heuristic rules for tool-call argument inspection.

These run AFTER the schema-corpus lookup, on calls whose name was
either found in the corpus OR flagged as hallucinated. The rules are
intentionally narrow + structural (no LLM, no semantic reasoning) so
the same rule set ports 1:1 to Go.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------
# Placeholder credential / sample value patterns.
#
# Real values rarely look like the token "YOUR_API_KEY"; LLMs hallucinate
# these CONSTANTLY when they don't have the real credential. We treat
# this as a HIGH-severity indicator because legitimate calls never carry
# them (an operator's redaction layer that wrote a placeholder over a
# real value would be visible upstream of the validator, not inside the
# call shape).
# ---------------------------------------------------------------------

_PLACEHOLDER_REGEX = re.compile(
    r"^("
    r"your[\-_]?(api|secret|access|aws|openai|anthropic)[\-_]?(key|token|secret)?|"
    r"replace[\-_]?(me|this|with[\-_].+)|"
    r"<\s*(your|insert|fill|enter|replace|api|secret|token).+?>|"
    r"xxx+|"
    r"placeholder.*|"
    r"example[\-_](key|token|api[\-_]?key)|"
    r"sk[\-_]?xxxxxxx+|"
    r"example\.com[/\w]*|"
    r"foo|bar|baz|qux|quux|"
    r"todo|tbd|tba"
    r")$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------
# Hallucination tell — names that mix camelCase + snake_case in a way
# that real APIs rarely emit. Caught: "send_emailToUser",
# "GetUserData_v2", "fetch_DataAsync".
#
# Real APIs commit to ONE casing inside a single identifier.
# ---------------------------------------------------------------------

_NAME_MIX_REGEX = re.compile(
    # snake_case followed by camelCase chunk
    r"^[a-z]+(_[a-z]+)+[A-Z]|"
    # camelCase followed by underscore
    r"^[a-z]+[A-Z][a-z]+(_[a-zA-Z])"
)


def is_placeholder_value(value: Any) -> bool:
    """Return True if `value` looks like an LLM-emitted placeholder."""
    if not isinstance(value, str):
        return False
    if len(value) > 256:  # real placeholders are short; long strings skip
        return False
    stripped = value.strip()
    if not stripped:
        return False
    return bool(_PLACEHOLDER_REGEX.match(stripped))


def has_naming_style_mix(name: str) -> bool:
    """Return True if `name` mixes snake_case + camelCase."""
    if not name or len(name) < 4:
        return False
    return bool(_NAME_MIX_REGEX.search(name))


def required_minus_present(
    required: tuple[str, ...], args: dict[str, Any]
) -> list[str]:
    """Return required fields not present in `args`."""
    if not required:
        return []
    present = set(args.keys()) if isinstance(args, dict) else set()
    return [r for r in required if r not in present]


def present_minus_allowed(
    required: tuple[str, ...],
    optional: tuple[str, ...],
    args: dict[str, Any],
) -> list[str]:
    """Return arg keys not in `required` ∪ `optional`.

    When neither required nor optional is set (the corpus entry leaves
    both empty), we DON'T flag — that means the schema is permissive
    (e.g., `tools/list` accepts no args but doesn't forbid them either,
    and many providers tolerate extras).
    """
    if not required and not optional:
        return []
    allowed = set(required) | set(optional)
    present = list(args.keys()) if isinstance(args, dict) else []
    return [k for k in present if k not in allowed]
