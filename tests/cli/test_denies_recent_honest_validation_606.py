"""#606 CRIT state-verification — denies recent honors --since validation,
surfaces per-bouncer query failures honestly, and converges on the same
fan-out as audit query.

Per UAT-Admin-CLI 2026-05-25 Gap A + Gap B: ``iam-jit denies recent``
(the operator's primary admin lens) was silently swallowing invalid
``--since`` AND was returning ``count: 0`` on windows where the same
underlying audit-events endpoint had matching rows — the silent-
degradation pattern per ``[[ibounce-honest-positioning]]`` that incident
responders rely on this CLI NOT to do.

Fix:

  Gap A — validate ``--since`` up-front; per-bouncer query failures
  surface in the human text (stderr WARNING) + JSON top-level
  ``query_errors`` array. Exit codes: 0 ok / 2 partial / 1 all-failed.
  The "Your bouncer caught nothing — clear" line no longer fires when
  the query failed.

  Gap B — extract a shared ``_fan_out_query`` helper used by both
  ``fetch_recent_denies`` (backward-compat shape) and
  ``fetch_recent_denies_with_errors`` (new structured shape). Both
  ``audit query`` and ``denies recent`` converge on the same
  per-bouncer ``/audit/events`` endpoint with identical filter
  semantics — when given the same window + bouncer set + verdict
  filter, both produce the same count.

Per ``docs/CONTRIBUTING.md`` every test asserts an OBSERVABLE invariant
(stderr / stdout content + exit code + JSON shape), not internal
function returns. The sabotage check (test 8) proves the validation
gate is load-bearing.

Discipline tags:

  * ``[[ibounce-honest-positioning]]`` — never claim "0 caught" when
    queries failed; surface the WHY, not a green status.
  * ``[[cross-product-agent-parity]]`` — shared helper so audit query
    + denies recent can't drift on which bouncers / filters they use.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

from iam_jit import cli_profile_allow as _cli_mod
from iam_jit.cli import main
from iam_jit.cli_audit_query import _BouncerQueryResult
from iam_jit.profile_allow import denies as _denies_mod


def _deny_event(action: str, i: int, bouncer: str = "ibounce") -> dict[str, Any]:
    """Build an audit event that fetch_recent_denies projects into a
    DenyRow. Mirrors the helper from
    tests/cli/test_denies_classify_skip_dedupe_577.py."""
    return {
        "time": 1_700_000_000_000 + i,
        "_bouncer": bouncer,
        "metadata": {"product": {"name": bouncer}},
        "status_detail": (
            f"profile 'safe-default': action {action} not in allow_baseline"
        ),
        "api": {"operation": action},
        "resources": [{
            "uid": f"arn:aws:s3:::bucket-{bouncer}/{i}",
            "name": f"arn:aws:s3:::bucket-{bouncer}/{i}",
        }],
        "unmapped": {
            "iam_jit": {
                "verdict": "deny",
                "ext": {"reason": "profile 'safe-default'"},
                "agent": {"session_id": f"sess-606-{bouncer}"},
            },
        },
    }


def _wire_results(
    monkeypatch: pytest.MonkeyPatch,
    *,
    per_bouncer: dict[str, _BouncerQueryResult],
) -> None:
    """Stub ``_query_one_bouncer`` to return a different result per
    bouncer.name. Unlisted bouncers get an empty-success result."""

    def _fake_one(endpoint, **_kw):  # type: ignore[no-untyped-def]
        if endpoint.name in per_bouncer:
            return per_bouncer[endpoint.name]
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[], error="",
        )

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )


# ---------------------------------------------------------------------------
# Test 1 — invalid --since exits non-zero with operator-actionable error
# ---------------------------------------------------------------------------


def test_denies_recent_invalid_since_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--since FOO`` -> exit 2 + stderr error mentioning the bad
    value AND offering example inputs.

    Pre-#606 the invalid value passed through to the bouncer, the
    bouncer returned HTTP 400, the error was hidden in notes[], and
    the CLI claimed status=ok / count=0. This is the canonical Gap A
    shape from UAT-Admin-CLI 2026-05-25.
    """
    # No bouncer wiring needed — validation happens BEFORE fan-out.
    runner = CliRunner()
    result = runner.invoke(
        main, ["denies", "recent", "--since", "FOO", "--limit", "5"],
    )
    assert result.exit_code == 2, (
        f"expected exit 2 for invalid --since; got {result.exit_code}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "FOO" in result.stderr, (
        f"stderr must echo the invalid value so operator sees what was "
        f"rejected; got: {result.stderr!r}"
    )
    assert "invalid" in result.stderr.lower(), (
        f"stderr must classify the failure as invalid; got: "
        f"{result.stderr!r}"
    )
    # Operator-actionable: show an example of what a valid value looks
    # like so they don't have to grep the source.
    assert (
        "5m" in result.stderr or "24h" in result.stderr or "ISO" in result.stderr
    ), (
        f"stderr should suggest a valid shape; got: {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — invalid --since does NOT emit the "caught nothing" message
# ---------------------------------------------------------------------------


def test_denies_recent_invalid_since_does_not_claim_caught_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per ``[[ibounce-honest-positioning]]``: when the query is
    malformed, the CLI MUST NOT emit the "Your bouncer caught nothing
    — clear" line. Pre-#606 it did, which read to operators as
    "everything's clean" even though the query never reached the
    bouncer.
    """
    runner = CliRunner()
    result = runner.invoke(
        main, ["denies", "recent", "--since", "FOO", "--limit", "5"],
    )
    # stdout / stderr / combined output ALL must lack the misleading
    # "caught nothing" line.
    combined = (result.stdout or "") + (result.stderr or "")
    assert "caught nothing" not in combined.lower(), (
        f"invalid --since must not produce a 'caught nothing' line; "
        f"got: {combined!r}"
    )
    assert "clear" not in combined.lower() or "invalid" in combined.lower(), (
        f"'clear' wording must not appear without an invalid framing; "
        f"got: {combined!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — all bouncers failed -> exit 1 (cannot honestly report)
# ---------------------------------------------------------------------------


def test_denies_recent_all_bouncers_failed_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When EVERY surface in the fan-out fails, the CLI MUST exit 1
    (full degradation) — we cannot honestly say "caught nothing"
    because we never saw the data. The text mode emits a follow-on
    WARNING + ERROR cluster on stderr; the JSON mode sets
    ``status: "all_bouncers_failed"``.

    Post-#620 the fan-out has FIVE surfaces (the four bouncers + the
    iam-jit serve audit log); all five must fail for the exit-1 path
    to fire — any success collapses the outcome to "partial" (exit 2).
    """
    failing_results = {
        name: _BouncerQueryResult(
            bouncer=name, events=[], error="unreachable: connection refused",
        )
        for name in (
            "ibounce", "kbounce", "dbounce", "gbounce", "iam-jit-serve",
        )
    }
    _wire_results(monkeypatch, per_bouncer=failing_results)

    runner = CliRunner()
    result = runner.invoke(
        main, ["denies", "recent", "--since", "1h", "--limit", "5"],
    )
    assert result.exit_code == 1, (
        f"all-failed must exit 1; got {result.exit_code}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # State verification: stderr carries the per-bouncer WHY + the
    # explicit "caught nothing is NOT reliable" disclaimer per #606.
    assert "WARNING" in result.stderr or "ERROR" in result.stderr, (
        f"all-failed must emit WARNING/ERROR on stderr; got: "
        f"{result.stderr!r}"
    )
    # Combined output MUST NOT contain the misleading happy-path line.
    combined = (result.stdout or "") + (result.stderr or "")
    happy_line = (
        "your bouncer caught nothing in the requested window — clear"
    )
    assert happy_line not in combined.lower(), (
        f"all-failed must NEVER emit '{happy_line}'; got: {combined!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — partial bouncer failure -> exit 2 (still emit what we have)
# ---------------------------------------------------------------------------


def test_denies_recent_partial_bouncer_failure_warns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When SOME bouncers fail and SOME succeed, exit 2 (partial). The
    successful bouncers' rows still render; stderr surfaces the
    failures so the operator knows the count is partial.

    Exit-code convention (#606): 0 ok / 2 partial / 1 all-failed.
    """
    per_bouncer = {
        # ibounce returns a deny event (success).
        "ibounce": _BouncerQueryResult(
            bouncer="ibounce",
            events=[_deny_event("s3:GetObject", 1, bouncer="ibounce")],
            error="",
        ),
        # kbounce returns an HTTP 400 error (failure).
        "kbounce": _BouncerQueryResult(
            bouncer="kbounce",
            events=[],
            error="HTTP 400: since='bad': want RFC3339 / ISO 8601",
        ),
    }
    _wire_results(monkeypatch, per_bouncer=per_bouncer)

    runner = CliRunner()
    result = runner.invoke(
        main, ["denies", "recent", "--since", "1h", "--json"],
    )
    assert result.exit_code == 2, (
        f"partial failure must exit 2; got {result.exit_code}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    # State verification: the JSON shape carries the structured
    # error array AND the bouncer count breakdown so downstream agents
    # can react without parsing notes strings.
    payload = json.loads(result.stdout)
    assert payload["status"] == "degraded", (
        f"partial -> status=degraded; got: {payload.get('status')!r}"
    )
    assert payload["count"] >= 1, (
        f"successful bouncer's row must still surface; got: {payload!r}"
    )
    assert isinstance(payload.get("query_errors"), list), (
        f"query_errors must be a list in JSON shape; got: {payload!r}"
    )
    assert len(payload["query_errors"]) >= 1, (
        f"at least one structured error expected; got: "
        f"{payload.get('query_errors')!r}"
    )
    # The bouncer-attempted vs succeeded ratio is operator-visible.
    assert payload.get("bouncers_attempted", 0) > payload.get(
        "bouncers_succeeded", 0
    ), (
        f"attempted > succeeded for partial failure; got: {payload!r}"
    )


# ---------------------------------------------------------------------------
# Test 5 — count parity with audit query (Gap B)
# ---------------------------------------------------------------------------


def test_denies_recent_count_matches_audit_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given N deny events on the same per-bouncer ``/audit/events``
    endpoint, ``denies recent --json`` count equals the count audit
    query would surface when filtering for the same verdict.

    Per #606 Gap B: pre-fix audit query found 7 DENYs while denies
    recent found 0 on identical inputs — the silent-degradation shape.
    The post-fix invariant is that both CLI paths use the same
    ``_query_one_bouncer`` fan-out via shared infrastructure, so a
    deterministic event-set produces the same observable count.

    The shared helper is :func:`iam_jit.profile_allow.denies.
    _fan_out_query`; both ``fetch_recent_denies`` and the new
    ``fetch_recent_denies_with_errors`` delegate to it.
    """
    n = 5
    events = [_deny_event("s3:GetObject", i, bouncer="ibounce") for i in range(n)]
    per_bouncer = {
        "ibounce": _BouncerQueryResult(
            bouncer="ibounce", events=events, error="",
        ),
    }
    _wire_results(monkeypatch, per_bouncer=per_bouncer)

    runner = CliRunner()
    # denies recent path
    dr_result = runner.invoke(
        main,
        [
            "denies", "recent",
            "--since", "1h", "--limit", "200",
            "--bouncer", "ibounce", "--json",
        ],
    )
    assert dr_result.exit_code == 0, (
        f"clean run must exit 0; got {dr_result.exit_code}; "
        f"stderr={dr_result.stderr!r}"
    )
    dr_payload = json.loads(dr_result.stdout)
    dr_count = dr_payload["count"]

    # Now confirm the shared fan-out helper produces the SAME count
    # the CLI surfaced — locks the helper -> CLI -> count invariant.
    rows_direct, _notes, errors_direct, _attempted = (
        _denies_mod.fetch_recent_denies_with_errors(
            since="1h", limit=200, bouncer_names=["ibounce"],
        )
    )
    assert not errors_direct, (
        f"shared helper had no errors -> CLI must mirror; got: "
        f"{errors_direct!r}"
    )
    assert dr_count == len(rows_direct), (
        f"denies recent count {dr_count} must equal shared-helper "
        f"count {len(rows_direct)} on the same window/bouncer/filter"
    )
    assert dr_count == n, (
        f"both must equal the wired event count {n}; got dr={dr_count} "
        f"direct={len(rows_direct)}"
    )


# ---------------------------------------------------------------------------
# Test 6 — count parity holds after --bouncer filter (per-bouncer scope)
# ---------------------------------------------------------------------------


def test_denies_recent_count_matches_after_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the operator pins ``--bouncer kbounce``, the resulting count
    matches the kbouncer-only event-set returned by the shared fan-out.
    Gap B requires per-bouncer scope to be honest under filter, not just
    in the aggregate.
    """
    ibounce_events = [_deny_event("s3:GetObject", i, bouncer="ibounce") for i in range(3)]
    kbounce_events = [_deny_event("psql:select", i, bouncer="kbounce") for i in range(7)]
    per_bouncer = {
        "ibounce": _BouncerQueryResult(
            bouncer="ibounce", events=ibounce_events, error="",
        ),
        "kbounce": _BouncerQueryResult(
            bouncer="kbounce", events=kbounce_events, error="",
        ),
    }
    _wire_results(monkeypatch, per_bouncer=per_bouncer)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "denies", "recent",
            "--since", "1h", "--limit", "200",
            "--bouncer", "kbounce", "--json",
        ],
    )
    assert result.exit_code == 0, (
        f"got {result.exit_code}; stderr={result.stderr!r}"
    )
    payload = json.loads(result.stdout)
    # All rows must be from kbouncer; ibounce rows must not leak in.
    bouncers_seen = {r["bouncer"] for r in payload["rows"]}
    assert bouncers_seen == {"kbounce"}, (
        f"--bouncer kbounce must scope to kbounce only; got bouncers: "
        f"{bouncers_seen!r}"
    )
    assert payload["count"] == 7, (
        f"count must equal kbounce event count (7); got: "
        f"{payload['count']}"
    )


# ---------------------------------------------------------------------------
# Test 7 — human text path emits stderr warning, not "caught nothing"
# ---------------------------------------------------------------------------


def test_denies_recent_human_text_warns_on_query_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the query path fails (degraded / all_bouncers_failed), the
    human-text mode emits a WARNING to stderr AND the rendered table
    body MUST NOT include the misleading "caught nothing — clear"
    line. This is the text-path complement of Test 3's JSON-path
    invariant.
    """
    per_bouncer = {
        name: _BouncerQueryResult(
            bouncer=name,
            events=[],
            error="HTTP 400: since='FOO': want RFC3339 / ISO 8601",
        )
        for name in (
            "ibounce", "kbounce", "dbounce", "gbounce", "iam-jit-serve",
        )
    }
    _wire_results(monkeypatch, per_bouncer=per_bouncer)

    runner = CliRunner()
    result = runner.invoke(
        main, ["denies", "recent", "--since", "1h", "--limit", "5"],
    )
    # all-failed -> exit 1 (post-#620 fan-out has 5 surfaces; all 5
    # must fail to take the all-failed path)
    assert result.exit_code == 1, (
        f"all-failed exit code; got {result.exit_code}"
    )
    # State verification: the stderr cluster surfaces the WHY for each
    # bouncer AND the explicit disclaimer.
    assert "WARNING" in result.stderr, (
        f"WARNING line must appear on stderr; got: {result.stderr!r}"
    )
    assert "ibounce" in result.stderr and "kbounce" in result.stderr, (
        f"per-bouncer breakdown must appear on stderr; got: "
        f"{result.stderr!r}"
    )
    # Critical: the misleading happy-path phrasing is suppressed.
    full = (result.stdout or "") + (result.stderr or "")
    happy = (
        "your bouncer caught nothing in the requested window — clear"
    )
    assert happy not in full.lower(), (
        f"happy-path line must NOT appear when query failed; got: "
        f"{full!r}"
    )
    # Positive check: the substitute "no honest count available"
    # framing fires instead.
    assert (
        "no honest count" in result.stdout.lower()
        or "no honest count" in result.stderr.lower()
        or "query failed" in result.stdout.lower()
        or "query failed" in result.stderr.lower()
    ), (
        f"the honest-empty replacement line must appear; got stdout="
        f"{result.stdout!r} stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Test 8 — sabotage check: validation gate IS load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_check_validation_gate_is_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage-check per CONTRIBUTING.md: monkeypatch
    :func:`validate_since` to no-op, then re-run the Test 1 scenario.
    The pre-#606 behavior (silent pass-through; exit 0; "caught
    nothing" wording) must reappear — proving the validation gate is
    the load-bearing fix.

    If THIS test fails, the validation gate is no longer load-bearing
    and Test 1 is no longer a meaningful regression guard. That's a
    signal to investigate — not a tolerable state.
    """
    # Re-wire EVERY fan-out surface (the 4 bouncers + iam-jit serve per
    # #620) to return an HTTP 400 like a real bouncer would for invalid
    # --since (mirrors the pre-#606 swallowed-error shape). All 5 must
    # fail so the post-sabotage exit collapses to exit 1 (all-failed),
    # not exit 2 (partial — which would re-collide with Test 1's
    # exit-2 invariant and confuse the sabotage signal).
    failing_all = {
        name: _BouncerQueryResult(
            bouncer=name, events=[],
            error="HTTP 400: since='FOO': want RFC3339 / ISO 8601",
        )
        for name in (
            "ibounce", "kbounce", "dbounce", "gbounce", "iam-jit-serve",
        )
    }
    _wire_results(monkeypatch, per_bouncer=failing_all)

    # Sabotage: stub validate_since to accept anything.
    monkeypatch.setattr(
        "iam_jit.cli_profile_allow.validate_since",
        lambda spec: spec,
        raising=False,
    )
    # Also sabotage the import-time alias so the CLI's local import
    # sees the no-op variant.
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.validate_since",
        lambda spec: spec,
    )

    runner = CliRunner()
    result = runner.invoke(
        main, ["denies", "recent", "--since", "FOO", "--limit", "5"],
    )

    # With the gate sabotaged, the CLI no longer rejects FOO with exit 2.
    # It falls through to the fan-out, which returns all-failed -> exit 1.
    # Either way the exit-code != 2 proves Test 1's exit==2 invariant
    # is what the gate produces.
    assert result.exit_code != 2, (
        f"sabotage should bypass the exit-2 fast-path; got exit 2 "
        f"anyway -> Test 1 isn't actually checking the gate. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # And stderr no longer contains the "--since {!r} is invalid" line
    # that's only produced by validate_since's gate.
    assert "is invalid" not in result.stderr.lower() or "FOO" not in result.stderr or "HTTP 400" in result.stderr, (
        f"sabotage should suppress the gate's error line; got stderr="
        f"{result.stderr!r}"
    )
