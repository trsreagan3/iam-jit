"""#582 HIGH — bouncer-kind validation at MCP dispatch entry.

UAT-A 2026-05-25 caught ``iam_jit_improve_profile({bouncer: "nonexistent"})``
silently returning ``status="no_change"`` with NO error — agent typos
(``"kbounce"`` vs ``"kbouncer"``, ``"dbouncer"`` vs ``"dbounce"``) were
undetectable. Same MRR-2 Pattern B silent-degradation shape per
``[[ibounce-honest-positioning]]``.

These tests assert OBSERVABLE state on the JSON-RPC wire per
``docs/CONTRIBUTING.md`` state-verification convention:

  * For invalid inputs the response carries ``error.code == -32602``
    (Invalid params per JSON-RPC §5.1) and ``error.message`` names the
    valid options + (when applicable) flags the common typo.
  * For valid inputs the validator MUST NOT intercept — the response
    flows through the normal tool handler (regression guard).
  * Sabotage check: monkeypatching the validator to a pass-through
    breaks the invalid-input assertions (proves the validator is
    load-bearing, not a no-op decoration).

Per ``[[cross-product-agent-parity]]`` the test parametrises across
every MCP tool that accepts a bouncer parameter so adding a new tool
to the contract automatically inherits the validation guarantees.
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit import mcp_bouncer_validation, mcp_server


# Snapshot of the validation contract under test. Mirrors
# ``mcp_server._BOUNCER_KIND_VALIDATION_FIELDS`` — a divergence would
# itself be a #582 regression so we assert the snapshot below.
# Tuple is (tool_name, field_name, required_in_schema). When a tool
# does NOT require the field in its inputSchema, missing/empty values
# are passed through to the handler's default (preserves backward
# compat) — only explicit non-empty values get validated.
_TOOLS_UNDER_TEST: list[tuple[str, str, bool]] = [
    ("iam_jit_improve_profile", "bouncer", False),
    ("iam_jit_consider_tightening", "bouncer_kind", True),
    ("bounce_simulate_profile", "bouncer_kind", True),
    ("bounce_grade_profile_for_workflow", "bouncer_kind", True),
]


def _call_tool(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    req_id: int = 7,
) -> dict:
    """Drive the real ``_handle_request`` with a ``tools/call`` request
    and return the parsed JSON-RPC response. We talk to the same entry
    point ``main()`` uses so the validator runs inside the actual
    dispatch path, not in isolation."""
    req = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    resp = mcp_server._handle_request(req)
    assert resp is not None, "tools/call must produce a response (not a notification)"
    return resp


def test_validation_contract_matches_snapshot() -> None:
    """The dispatch-time validation table is the source of truth.
    This test asserts the snapshot used by every other test in this
    module matches the registered contract, so adding a new entry to
    the dispatch table requires adding a corresponding parametrise
    entry here (forcing the new tool to inherit the tests below)."""
    registered = {
        (tool, field, required)
        for tool, (field, required) in
        mcp_server._BOUNCER_KIND_VALIDATION_FIELDS.items()
    }
    snapshot = set(_TOOLS_UNDER_TEST)
    missing_from_snapshot = registered - snapshot
    extra_in_snapshot = snapshot - registered
    assert not missing_from_snapshot, (
        f"new MCP tool(s) joined the bouncer-kind contract without "
        f"corresponding tests: {missing_from_snapshot}. "
        f"Add to _TOOLS_UNDER_TEST so the parametrised cases below "
        f"cover them per [[cross-product-agent-parity]]."
    )
    assert not extra_in_snapshot, (
        f"_TOOLS_UNDER_TEST references tools NOT in the dispatch "
        f"validation table: {extra_in_snapshot}"
    )


@pytest.mark.parametrize("tool_name,field_name,_required", _TOOLS_UNDER_TEST)
def test_invalid_bouncer_kind_returns_jsonrpc_invalid_params(
    tool_name: str, field_name: str, _required: bool,
) -> None:
    """Test 1 — every bouncer-kind-accepting MCP tool MUST return
    JSON-RPC ``-32602`` (Invalid params) when handed an unknown
    bouncer kind. The message MUST name the valid options. This is
    the inverse of the UAT-A 2026-05-25 silent ``no_change`` shape."""
    resp = _call_tool(
        tool_name,
        {field_name: "nonexistent-bouncer", "profile": {}, "events": [], "audit_events": []},
    )
    assert "error" in resp, (
        f"{tool_name}: invalid {field_name} must be rejected at "
        f"dispatch; got non-error response: {resp!r}"
    )
    err = resp["error"]
    assert err["code"] == mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS, (
        f"{tool_name}: expected JSON-RPC -32602 (Invalid params); "
        f"got code={err.get('code')!r} message={err.get('message')!r}"
    )
    msg = err["message"]
    # Message names the valid options so the agent can self-correct.
    for canonical in ("ibounce", "kbounce", "dbounce", "gbounce"):
        assert canonical in msg, (
            f"{tool_name}: error message must name canonical bouncer "
            f"{canonical!r} so agents can self-correct. Got: {msg!r}"
        )
    # Message names the offending field so multi-arg tools surface
    # which arg was wrong.
    assert field_name in msg, (
        f"{tool_name}: error message must name the offending field "
        f"{field_name!r}. Got: {msg!r}"
    )
    # Message includes the bad value so operators see what was typo'd.
    assert "nonexistent-bouncer" in msg, (
        f"{tool_name}: error message must echo the bad value so "
        f"operators see what was typo'd. Got: {msg!r}"
    )
    # The validator must not have run the tool — assert NO `result`
    # field came back (per JSON-RPC 2.0 §5: response is EITHER result
    # OR error, never both).
    assert "result" not in resp, (
        f"{tool_name}: error response must not also carry a result; "
        f"got: {resp!r}"
    )


@pytest.mark.parametrize("tool_name,field_name,_required", _TOOLS_UNDER_TEST)
def test_typo_dbouncer_suggests_dbounce(
    tool_name: str, field_name: str, _required: bool,
) -> None:
    """Test 2 — the common typo ``dbouncer`` (extra trailing 'r')
    surfaces a targeted correction hint per
    ``[[ibounce-honest-positioning]]``: error messages must be
    actionable, not generic."""
    resp = _call_tool(
        tool_name,
        {field_name: "dbouncer", "profile": {}, "events": [], "audit_events": []},
    )
    assert "error" in resp, f"{tool_name}: dbouncer typo must be rejected"
    err = resp["error"]
    assert err["code"] == mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS
    msg = err["message"]
    assert "dbounce" in msg, (
        f"{tool_name}: 'dbouncer' typo must surface 'dbounce' as the "
        f"corrected form. Got: {msg!r}"
    )
    # The hint phrasing is "Did you mean 'dbounce'?" — assert the
    # corrective signal not just the canonical mention.
    assert "did you mean" in msg.lower(), (
        f"{tool_name}: typo error must include a 'Did you mean ...' "
        f"hint. Got: {msg!r}"
    )


@pytest.mark.parametrize("tool_name,field_name,_required", _TOOLS_UNDER_TEST)
def test_typo_gbouncer_suggests_gbounce(
    tool_name: str, field_name: str, _required: bool,
) -> None:
    """Test 3 — the common typo ``gbouncer`` (extra trailing 'r')
    surfaces a targeted correction hint. Parallel to dbouncer above
    so the pattern coverage is symmetric across the suite."""
    resp = _call_tool(
        tool_name,
        {field_name: "gbouncer", "profile": {}, "events": [], "audit_events": []},
    )
    assert "error" in resp, f"{tool_name}: gbouncer typo must be rejected"
    err = resp["error"]
    assert err["code"] == mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS
    msg = err["message"]
    assert "gbounce" in msg, (
        f"{tool_name}: 'gbouncer' typo must surface 'gbounce' as the "
        f"corrected form. Got: {msg!r}"
    )
    assert "did you mean" in msg.lower(), (
        f"{tool_name}: typo error must include a 'Did you mean ...' "
        f"hint. Got: {msg!r}"
    )


@pytest.mark.parametrize("tool_name,field_name,_required", _TOOLS_UNDER_TEST)
def test_kbouncer_is_accepted_alias_for_kbounce(
    tool_name: str, field_name: str, _required: bool,
) -> None:
    """Test 4 — ``kbouncer`` is the legacy form three pre-#582 MCP
    inputSchema enums advertise; it MUST stay accepted (alias for
    ``kbounce`` per [[bounce-suite-rename]]) so existing agents
    targeting the schema-advertised value don't break. The validator
    is the one component that knows the alias mapping — assert it
    does NOT intercept this value."""
    resp = _call_tool(
        tool_name,
        {field_name: "kbouncer", "profile": {}, "events": [], "audit_events": []},
    )
    # The validator must let this through. The downstream handler may
    # still return its own status/error (e.g. empty events → no_change)
    # but the response MUST NOT be the -32602 from the validator.
    if "error" in resp:
        assert resp["error"]["code"] != mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS, (
            f"{tool_name}: kbouncer is an accepted alias for kbounce "
            f"per [[bounce-suite-rename]] and MUST NOT trigger -32602. "
            f"Got: {resp['error']!r}"
        )


@pytest.mark.parametrize("tool_name,field_name,_required", _TOOLS_UNDER_TEST)
def test_valid_bouncer_kind_proceeds_to_handler(
    tool_name: str, field_name: str, _required: bool,
) -> None:
    """Test 5 (regression) — a VALID bouncer kind MUST NOT trigger
    the validator's -32602; the request flows through to the
    tool handler. The handler may emit its own status (no_change,
    error, etc.) — that's fine. The assertion is specifically that
    the validator did not intercept."""
    resp = _call_tool(
        tool_name,
        {field_name: "ibounce", "profile": {}, "events": [], "audit_events": []},
    )
    if "error" in resp:
        assert resp["error"]["code"] != mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS, (
            f"{tool_name}: 'ibounce' is canonical and MUST NOT trigger "
            f"the bouncer-kind validator. Got: {resp['error']!r}"
        )


@pytest.mark.parametrize("tool_name,field_name,required", _TOOLS_UNDER_TEST)
def test_missing_bouncer_kind_honours_schema_required(
    tool_name: str, field_name: str, required: bool,
) -> None:
    """Test 6 — missing-field behaviour MUST follow the tool's
    inputSchema ``required`` declaration.

    For tools where the field is REQUIRED (bounce_simulate_profile,
    bounce_grade_profile_for_workflow, iam_jit_consider_tightening)
    omitting the field MUST surface a -32602 — silently falling back
    to a fabricated default would itself be the no_change/silent-no-op
    shape the bug closes.

    For tools where the field is OPTIONAL (iam_jit_improve_profile —
    schema declares ``default: ibounce``) omitting the field MUST
    pass through to the handler's default. The validator MUST NOT
    invent a -32602 in that case (preserves backward compat with
    every existing caller that relied on the schema-advertised
    default)."""
    resp = _call_tool(
        tool_name,
        {"profile": {}, "events": [], "audit_events": []},
    )
    if required:
        assert "error" in resp, (
            f"{tool_name}: {field_name} is REQUIRED — omitting it "
            f"must surface a -32602, not silently default. Got: {resp!r}"
        )
        err = resp["error"]
        assert err["code"] == mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS, (
            f"{tool_name}: missing required {field_name} → expected "
            f"-32602; got: {err!r}"
        )
        assert field_name in err["message"]
    else:
        # Optional — the validator MUST NOT block; the handler applies
        # its documented default. Any -32602 here would be a regression
        # against [[cross-product-agent-parity]] backward-compat.
        if "error" in resp:
            assert resp["error"]["code"] != mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS, (
                f"{tool_name}: {field_name} is OPTIONAL and the validator "
                f"must NOT intercept missing values; let the handler "
                f"apply its default. Got: {resp['error']!r}"
            )


# ---------------------------------------------------------------------------
# Sabotage check — proves the validator is load-bearing per CONTRIBUTING.md.
# ---------------------------------------------------------------------------


def test_sabotage_check_validator_is_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per ``docs/CONTRIBUTING.md`` state-verification convention: an
    assertion is only meaningful if breaking the production code
    breaks the test. Replace ``validate_bouncer_kind`` with a
    pass-through and assert the canonical invalid-input test would
    NO LONGER catch the silent no-op (proves the production
    validation is the thing the tests depend on, not coincidental
    behaviour of the downstream handlers)."""

    def _pass_through(value, **_kwargs):  # noqa: ANN001
        return str(value)

    monkeypatch.setattr(
        mcp_bouncer_validation, "validate_bouncer_kind", _pass_through,
    )
    # mcp_server reaches into mcp_bouncer_validation via a local import
    # inside the dispatch — monkeypatching the source module is enough.
    resp = _call_tool(
        "iam_jit_improve_profile",
        {"bouncer": "nonexistent-bouncer"},
    )
    # With validation neutered, the request flows through to
    # improve_profile_for_mcp which is the silent-no-op the bug
    # report describes. Either no error OR a non-(-32602) error proves
    # the validator was load-bearing — production code would NEVER let
    # the request reach the handler intact.
    if "error" in resp:
        assert resp["error"]["code"] != mcp_bouncer_validation.JSON_RPC_INVALID_PARAMS, (
            "sabotage failed: validator still firing despite "
            "monkeypatch — the dispatch wiring is not actually "
            "calling through the patched symbol, so the tests above "
            "are not proving what they claim."
        )
    else:
        # No error → the silent-no-op the bug report describes. The
        # production validation closes this path; sabotage re-opens it.
        # That proves the validator is the load-bearing component.
        assert "result" in resp, (
            "sabotage produced neither error nor result; the dispatch "
            "shape changed unexpectedly: {resp!r}"
        )
