"""#582 HIGH — bouncer-kind validation at MCP dispatch entry.

Per UAT-A 2026-05-25: ``iam_jit_improve_profile({bouncer: "nonexistent"})``
silently returned ``status="no_change"`` with NO error. Agent typos
(e.g. ``"kbounce"`` vs ``"kbouncer"``, ``"dbouncer"`` vs ``"dbounce"``)
were undetectable — same MRR-2 Pattern B silent-degradation shape
per ``[[ibounce-honest-positioning]]``.

This module surfaces invalid bouncer kinds at MCP dispatch entry with
an actionable JSON-RPC ``-32602`` (Invalid params) error that names
the valid options + flags the common typos. Per ``[[cross-product-
agent-parity]]`` every MCP tool that accepts a bouncer parameter
calls into the same helper so adding a new tool to the contract is
mechanical.

Canonical accepted set
----------------------

Per ``[[bounce-suite-rename]]`` (2026-05-17) the canonical suite
short-names are ``ibounce`` / ``kbounce`` / ``dbounce`` / ``gbounce``.
The legacy ``kbouncer`` alias is ALSO accepted because three pre-#582
MCP inputSchema enums advertise it (``iam_jit_improve_profile``,
``iam_jit_consider_tightening``, ``bounce_simulate_profile``,
``bounce_grade_profile_for_workflow``). Accepting both keeps the
schema contract honest without breaking existing agents that picked
the schema-advertised value.
"""

from __future__ import annotations

# The runtime-canonical set per ``DEFAULT_BOUNCERS`` keys in
# ``cli_audit_query`` — these are what the pipelines actually probe.
_CANONICAL_BOUNCER_KINDS = frozenset({"ibounce", "kbounce", "dbounce", "gbounce"})

# Legacy aliases ALSO accepted (advertised by existing MCP inputSchema
# enums). Mapping is kept here so the canonical form is discoverable.
_BOUNCER_KIND_ALIASES = {
    # ``kbouncer`` predates the bounce-suite rename; the schemas at
    # iam_jit_improve_profile + iam_jit_consider_tightening +
    # bounce_simulate_profile + bounce_grade_profile_for_workflow still
    # list it as a valid enum value.
    "kbouncer": "kbounce",
}

# Combined accepted set — what validate_bouncer_kind() lets through.
VALID_BOUNCER_KINDS = frozenset(
    _CANONICAL_BOUNCER_KINDS | set(_BOUNCER_KIND_ALIASES)
)

# Common typo → suggested canonical form. Used to enrich the error
# message so agents see a corrective hint, not just a generic list.
# Keys are NOT in VALID_BOUNCER_KINDS — they fail validation AND get
# the suggestion.
_COMMON_TYPOS: dict[str, str] = {
    "dbouncer": "dbounce",
    "ibouncer": "ibounce",
    "gbouncer": "gbounce",
    # Note: ``kbounce`` ↔ ``kbouncer`` are BOTH already accepted as
    # equivalents so neither lands here as a typo. We still expose the
    # equivalence in the generic error message so operators understand
    # why both forms work.
}

# JSON-RPC 2.0 error code for "Invalid params" per spec §5.1.
JSON_RPC_INVALID_PARAMS = -32602


class InvalidBouncerKindError(ValueError):
    """Raised when an MCP tool received a ``bouncer`` / ``bouncer_kind``
    argument outside :data:`VALID_BOUNCER_KINDS`.

    Carries the tool name + field name + the bad value so the MCP
    dispatch site can translate to a JSON-RPC ``-32602`` response with
    a structured message.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str,
        field_name: str,
        bad_value: object,
    ) -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.field_name = field_name
        self.bad_value = bad_value


def validate_bouncer_kind(
    value: object,
    *,
    tool_name: str,
    field_name: str = "bouncer_kind",
) -> str:
    """Validate ``value`` is a recognised bouncer short-name.

    Returns the validated string on success (always a ``str``). Raises
    :class:`InvalidBouncerKindError` with an actionable message on
    failure — message names the canonical accepted set + flags the
    bad value + offers a typo suggestion when one is registered for
    the bad input.

    The MCP dispatch site translates the raised exception to a
    JSON-RPC ``-32602`` (Invalid params) response per spec §5.1.

    Why dispatch-time validation (instead of schema-only):
        MCP clients are NOT required to enforce inputSchema before
        calling — the spec marks schema enforcement as a client
        responsibility (host-dependent). At least one observed shape
        (UAT-A 2026-05-25 #582) passed an unknown bouncer kind
        straight to the handler, which silently no-op'd with
        ``status="no_change"``. Belt-and-suspenders runtime validation
        closes that hole regardless of client behaviour.
    """
    if not isinstance(value, str) or not value:
        raise InvalidBouncerKindError(
            f"{tool_name}: {field_name!r} is required and must be a "
            f"non-empty string naming one of "
            f"{sorted(VALID_BOUNCER_KINDS)}. "
            f"Got {type(value).__name__}={value!r}.",
            tool_name=tool_name,
            field_name=field_name,
            bad_value=value,
        )
    if value in VALID_BOUNCER_KINDS:
        return value
    # Build a corrective message. Surface a targeted hint when the bad
    # value matches a known typo, otherwise just enumerate the valid
    # set. Always note the kbounce/kbouncer equivalence so operators
    # know both forms work (and that "kbounce" is the post-rename
    # canonical form per [[bounce-suite-rename]]).
    typo_hint = ""
    if value in _COMMON_TYPOS:
        typo_hint = (
            f" Did you mean {_COMMON_TYPOS[value]!r}? "
            f"(common typo: {value!r} → {_COMMON_TYPOS[value]!r})."
        )
    raise InvalidBouncerKindError(
        f"{tool_name}: unknown {field_name}={value!r}. "
        f"Supported: {sorted(VALID_BOUNCER_KINDS)} "
        f"('kbounce' is the post-rename canonical form per "
        f"[[bounce-suite-rename]]; 'kbouncer' is accepted as an "
        f"alias).{typo_hint}",
        tool_name=tool_name,
        field_name=field_name,
        bad_value=value,
    )


__all__ = [
    "JSON_RPC_INVALID_PARAMS",
    "InvalidBouncerKindError",
    "VALID_BOUNCER_KINDS",
    "validate_bouncer_kind",
]
