"""#724 — declarative chain RULES (the YAML at ``~/.iam-jit/chains/``).

A chain rule maps a TRIGGER (a signal kind a producing bouncer raises)
to an ACTION (how THIS consuming bouncer tightens) for a SCOPE
(currently always ``agent_session``). Per the task spec::

    # ~/.iam-jit/chains/pii-egress.yaml
    - trigger: dbounce.pii_detected
      scope: agent_session
      action: ibounce.tighten_egress
      ttl: 1h

Honest scope (per ``[[ibounce-honest-positioning]]``)
-----------------------------------------------------
The Python side ships ONE consumer action — ``ibounce.tighten_egress``
(and its gbounce-port-compatible alias ``gbounce.tighten_egress``).
Other actions parse + validate but are recorded as "not implemented on
this bouncer" so the Go ports can adopt them additively without a
format change. We never silently ignore an unknown action — load
rejects it loudly so an operator's typo can't become a silent no-op.

Trigger grammar: ``<source_bouncer>.<event>``. The ``<event>`` half
maps to a canonical signal kind in :mod:`.signal_store`. We accept the
spec's human-facing ``pii_detected`` as well as the on-wire
``pii_observed`` kind so the operator-facing YAML reads naturally while
the wire stays stable.

Tightening-only invariant: there is intentionally NO ``loosen`` action.
The action vocabulary contains only tightening verbs. A chain rule can
never widen a bouncer's posture.
"""

from __future__ import annotations

import dataclasses
import logging
import pathlib
import re
from typing import Any

from .signal_store import (
    SIGNAL_KIND_PII_OBSERVED,
    SIGNAL_KIND_SECRET_OBSERVED,
)

logger = logging.getLogger(__name__)

_DEFAULT_CHAINS_DIR = "~/.iam-jit/chains"

# Map operator-facing trigger event names -> canonical wire signal kind.
# Both the human-friendly "_detected" form (spec example) and the
# on-wire "_observed" form resolve to the same kind.
_TRIGGER_EVENT_TO_KIND = {
    "pii_detected": SIGNAL_KIND_PII_OBSERVED,
    "pii_observed": SIGNAL_KIND_PII_OBSERVED,
    "secret_detected": SIGNAL_KIND_SECRET_OBSERVED,
    "secret_observed": SIGNAL_KIND_SECRET_OBSERVED,
}

# Consumer actions this bouncer understands. ``tighten_egress`` is the
# only one IMPLEMENTED on the Python (ibounce) side today; the others
# are reserved for the Go ports and validate but are flagged
# unimplemented-here so the operator gets honest feedback.
_TIGHTEN_EGRESS = "tighten_egress"
_KNOWN_ACTIONS = {_TIGHTEN_EGRESS}

# Bouncers we recognise as action targets. ``ibounce`` is the HTTP
# egress bouncer (this process). ``gbounce`` is its Go sibling and uses
# the SAME tighten_egress semantics — a rule written `gbounce.tighten_
# egress` is honoured by an ibounce consumer too (they are the same
# protocol family), which is what makes the canonical PDF chain work
# whether the operator names the HTTP bouncer ibounce or gbounce.
_EGRESS_BOUNCERS = {"ibounce", "gbounce"}

_SCOPE_AGENT_SESSION = "agent_session"
_KNOWN_SCOPES = {_SCOPE_AGENT_SESSION}

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}
_DEFAULT_TTL_SECONDS = 3600  # 1h, matches the spec example


class ChainRulesError(ValueError):
    """Raised when a chain-rule file is malformed."""


@dataclasses.dataclass(frozen=True)
class ChainRule:
    """One validated chain rule."""

    trigger_source: str          # e.g. "dbounce"
    trigger_kind: str            # canonical signal kind, e.g. "pii_observed"
    scope: str                   # "agent_session"
    action_bouncer: str          # e.g. "ibounce"
    action_verb: str             # e.g. "tighten_egress"
    ttl_seconds: int
    raw_trigger: str
    raw_action: str

    @property
    def applies_to_egress(self) -> bool:
        """True iff this rule's action tightens HTTP egress on an
        egress-family bouncer (ibounce/gbounce) — i.e. the Python
        consumer hook acts on it."""
        return (
            self.action_bouncer in _EGRESS_BOUNCERS
            and self.action_verb == _TIGHTEN_EGRESS
        )


def _parse_duration(raw: Any) -> int:
    if raw is None:
        return _DEFAULT_TTL_SECONDS
    if isinstance(raw, bool):
        raise ChainRulesError("ttl must be a duration, not a boolean")
    if isinstance(raw, int):
        if raw <= 0:
            raise ChainRulesError(f"ttl must be > 0; got {raw}")
        return raw
    if not isinstance(raw, str):
        raise ChainRulesError(
            f"ttl must be a duration string like '1h' or positive int "
            f"seconds; got {type(raw).__name__}"
        )
    m = _DURATION_RE.match(raw)
    if not m:
        raise ChainRulesError(f"ttl must be like '1h' / '30m' / '90s'; got {raw!r}")
    seconds = int(m.group(1)) * _DURATION_UNITS[m.group(2) or "s"]
    if seconds <= 0:
        raise ChainRulesError(f"ttl must be > 0; got {raw!r}")
    return seconds


def _split_dotted(value: Any, *, field: str) -> tuple[str, str]:
    if not isinstance(value, str) or "." not in value:
        raise ChainRulesError(
            f"{field} must be '<bouncer>.<verb>' (e.g. 'dbounce.pii_detected'); "
            f"got {value!r}"
        )
    bouncer, _, verb = value.partition(".")
    bouncer = bouncer.strip().lower()
    verb = verb.strip().lower()
    if not bouncer or not verb:
        raise ChainRulesError(f"{field} must be '<bouncer>.<verb>'; got {value!r}")
    return bouncer, verb


def parse_rule(entry: Any) -> ChainRule:
    """Validate one rule dict into a :class:`ChainRule`."""
    if not isinstance(entry, dict):
        raise ChainRulesError(f"chain rule must be a mapping; got {type(entry).__name__}")

    allowed = {"trigger", "scope", "action", "ttl"}
    extra = set(entry) - allowed
    if extra:
        raise ChainRulesError(
            f"chain rule has unknown key(s) {sorted(extra)}; allowed: {sorted(allowed)}"
        )

    if "trigger" not in entry:
        raise ChainRulesError("chain rule missing required key 'trigger'")
    if "action" not in entry:
        raise ChainRulesError("chain rule missing required key 'action'")

    raw_trigger = entry["trigger"]
    trigger_source, trigger_event = _split_dotted(raw_trigger, field="trigger")
    kind = _TRIGGER_EVENT_TO_KIND.get(trigger_event)
    if kind is None:
        raise ChainRulesError(
            f"unknown trigger event {trigger_event!r}; known: "
            f"{sorted(_TRIGGER_EVENT_TO_KIND)}"
        )

    scope = str(entry.get("scope", _SCOPE_AGENT_SESSION)).strip().lower()
    if scope not in _KNOWN_SCOPES:
        raise ChainRulesError(
            f"unsupported scope {scope!r}; supported: {sorted(_KNOWN_SCOPES)}"
        )

    raw_action = entry["action"]
    action_bouncer, action_verb = _split_dotted(raw_action, field="action")
    if action_verb not in _KNOWN_ACTIONS:
        raise ChainRulesError(
            f"unknown action verb {action_verb!r}; known: {sorted(_KNOWN_ACTIONS)}"
        )

    ttl_seconds = _parse_duration(entry.get("ttl"))

    return ChainRule(
        trigger_source=trigger_source,
        trigger_kind=kind,
        scope=scope,
        action_bouncer=action_bouncer,
        action_verb=action_verb,
        ttl_seconds=ttl_seconds,
        raw_trigger=str(raw_trigger),
        raw_action=str(raw_action),
    )


def default_chains_dir() -> pathlib.Path:
    import os
    override = os.environ.get("IAM_JIT_CHAINS_DIR")
    if override:
        return pathlib.Path(override).expanduser()
    return pathlib.Path(_DEFAULT_CHAINS_DIR).expanduser()


def load_chain_rules(
    chains_dir: pathlib.Path | str | None = None,
) -> list[ChainRule]:
    """Load + validate all chain rules from ``*.yaml`` / ``*.yml`` in
    the chains directory.

    A missing directory is NOT an error — it means "no chains
    configured" (returns ``[]``). A malformed file IS an error
    (:class:`ChainRulesError`) so an operator's typo surfaces loudly
    rather than silently disabling protection. Each file may contain a
    single rule dict or a list of rule dicts.
    """
    base = (
        pathlib.Path(chains_dir).expanduser()
        if chains_dir is not None
        else default_chains_dir()
    )
    if not base.exists():
        return []
    if not base.is_dir():
        raise ChainRulesError(f"chains path {base} is not a directory")

    try:
        import yaml
    except ImportError as e:  # pragma: no cover - PyYAML is a hard dep
        raise ChainRulesError(
            "PyYAML is required to load chain rules but is not installed"
        ) from e

    rules: list[ChainRule] = []
    for path in sorted(base.glob("*.y*ml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as e:
            raise ChainRulesError(f"failed to read chain file {path}: {e}") from e
        if doc is None:
            continue
        entries = doc if isinstance(doc, list) else [doc]
        for entry in entries:
            try:
                rules.append(parse_rule(entry))
            except ChainRulesError as e:
                raise ChainRulesError(f"{path}: {e}") from e
    return rules


__all__ = [
    "ChainRule",
    "ChainRulesError",
    "default_chains_dir",
    "load_chain_rules",
    "parse_rule",
]
