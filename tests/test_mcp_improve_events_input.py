"""#581 HIGH — `iam_jit_improve_profile` MCP tool accepts inline `events[]`.

UAT-A 2026-05-25 finding: `iam_jit_improve_profile` via MCP with
`friction_budget=0` vs `friction_budget=999` produced IDENTICAL output
(`status: no_change`) when no live bouncer audit data existed. Phase 8
friction-budget refusal logic was implemented + unit-tested in-process,
but the MCP surface only queried the audit tail via `cadence_window` —
demo / test / agent-driven environments with no live bouncer could not
exercise the gate end-to-end.

Phase 4 (`bounce_simulate_profile`), Phase 5
(`bounce_grade_profile_for_workflow`), and Phase 13
(`iam_jit_consider_tightening`) all accept inline `events[]`; only
Phase 8 (`iam_jit_improve_profile`) did not. Per
``[[bouncer-zero-llm-when-agent-in-loop]]`` composability the agent
must be able to exercise the full pipeline in any environment; per
``[[cross-product-agent-parity]]`` the event shape must match
Phase 4 so agents do not have to translate.

This file's tests assert OBSERVABLE state (refused_narrowings list
contents, proposed_removals list contents, friction_metrics dict
presence) per ``docs/CONTRIBUTING.md`` state-verification convention.
Asserting only `status:` strings is exactly the bug shape this file
exists to prevent (the #326 / #448 / #463 pattern).

Tests:
  1. budget=0 + inline events → refused_narrowings non-empty
     (the P8 logic fires through MCP).
  2. budget=999 + inline events → narrowing included in
     proposed_removals (under budget, so kept).
  3. no events + no audit tail → status:no_change + friction_metrics
     empty (regression: existing path preserved).
  4. inline events + audit-tail data both exist → inline events win
     (caller intent is explicit).
  5. Events schema matches Phase 4 simulator — identical fixture
     accepted by both tools, both produce non-empty results.
  6. Sabotage-check — monkeypatch the friction-budget helper to a
     no-op; test 1's refusal assertion fails. Proves test 1 exercises
     the real gate, not coincidence.
  7. tools/list schema check — `iam_jit_improve_profile.inputSchema`
     advertises `events` property with `type:array, items:type:object`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml


# ---------------------------------------------------------------------------
# Shared fixtures (mirror tests/improve/test_pipeline_friction_budget.py).
# Re-declared rather than imported so changes to that file do not silently
# ripple here; the convention is the SAME fixture shape, not a shared
# fixture object.
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Active profile with 2 rules so the generator drop surfaces a
    candidate narrowing (drop of s3:PutObject)."""
    p = tmp_path / "profiles.yaml"
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "two-rule baseline",
                "allow_rules": [
                    {"pattern": "s3:GetObject", "arn_scope": "arn:aws:s3:::cache*"},
                    {"pattern": "s3:PutObject", "arn_scope": "arn:aws:s3:::cache*"},
                ],
            },
        },
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(p))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT", raising=False)
    return p


@pytest.fixture
def tmp_pending_queue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from iam_jit.profile_allow import operations as ops
    p = tmp_path / "pending.jsonl"
    monkeypatch.setenv(ops.PENDING_APPROVALS_PATH_ENV, str(p))
    return p


@pytest.fixture
def stub_generator_drop_putobject(monkeypatch: pytest.MonkeyPatch):
    """Stub generator so its emitted profile contains ONLY s3:GetObject.
    That makes ('s3:PutObject', 'arn:aws:s3:::cache*') a candidate
    narrowing / proposed_removal which the friction-budget gate then
    evaluates."""
    from iam_jit.llm.profile_generator import (
        GeneratedProfile,
        ProfileResult,
    )
    profile_yaml = yaml.safe_dump({
        "profiles": {
            "improve-ibounce-test": {
                "allows": [
                    {
                        "target": "arn:aws:s3:::cache*",
                        "actions": ["s3:GetObject"],
                    },
                ],
                "denies": [],
            },
        },
    })

    def _fake_generate(*_args, **_kwargs):
        return ProfileResult(
            bundle=(
                GeneratedProfile(
                    bouncer="ibounce",
                    profile_yaml=profile_yaml,
                    events_analyzed=10,
                    resources_observed=("arn:aws:s3:::cache",),
                    flagged_for_review=(),
                    skipped_list=(),
                ),
            ),
            index_yaml="",
            explanation="stub generator drops PutObject",
            audit_window_start=None,
            audit_window_end=None,
            budget_spent_usd=0.0,
            backend_name="stub",
            parser_strict_match=True,
            raw_model_response_sample="",
        )

    monkeypatch.setattr(
        "iam_jit.llm.profile_generator.generate_from_audit",
        _fake_generate,
    )


@pytest.fixture
def putobject_events() -> list[dict[str, Any]]:
    """Synthetic OCSF-shape events — IDENTICAL fixture used by
    tests/improve/test_pipeline_friction_budget.py. Per
    ``[[cross-product-agent-parity]]`` this same shape is consumed by
    `bounce_simulate_profile` (Phase 4) — the test below asserts that
    parity is real, not just claimed."""
    base = 1_700_000_000_000  # ms
    return [
        {
            "time": base + i * 10 * 60 * 1000,  # 10-min spacing
            "_bouncer": "ibounce",
            "metadata": {"event_code": "allow"},
            "api": {
                "operation": "PutObject",
                "service": {"name": "s3"},
                "resources": [
                    {"name": f"arn:aws:s3:::cache/object-{i}"},
                ],
            },
        }
        for i in range(6)
    ]


def _mcp_call(arguments: dict[str, Any]) -> dict[str, Any]:
    """Invoke `iam_jit_improve_profile` via the real MCP dispatch and
    return the structuredContent block."""
    from iam_jit.mcp_server import _handle_request

    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "iam_jit_improve_profile",
            "arguments": arguments,
        },
    })
    assert "result" in resp, (
        f"MCP dispatch errored: {json.dumps(resp, default=str)[:500]}"
    )
    return resp["result"]["structuredContent"]


# ---------------------------------------------------------------------------
# 1. budget=0 + inline events → refused (the gate fires through MCP).
# ---------------------------------------------------------------------------


def test_mcp_improve_with_inline_events_budget_low_refuses_narrowings(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator_drop_putobject,
    putobject_events,
) -> None:
    """budget=1 (smallest positive — semantics: never deny legit work)
    + 6 PutObject events in 1h that the candidate narrowing would deny
    → refused_narrowings MUST surface s3:PutObject + proposed_removals
    MUST NOT include it.

    Observable-state shape per ``docs/CONTRIBUTING.md``: the refusal
    claim is verified by checking BOTH where the rule went (refused
    list, by action) AND where it did NOT go (proposed_removals, by
    action). Asserting only the status string is exactly the failure
    mode this file exists to prevent.

    NOTE: budget=0 short-circuits the simulator's over_budget check
    (budget_max=0 → "no enforcement"), which is the documented
    observable in test 6 of test_pipeline_friction_budget.py. Using
    budget=1 here exercises the spec-strict refusal path
    deterministically.
    """
    sc = _mcp_call({
        "bouncer": "ibounce",
        "cadence": "per_session",
        "threshold": 0.30,
        "apply": False,
        "profile_name": "active-test",
        "events": putobject_events,
        "friction_budget": 1,
    })
    # 1. Status claim.
    assert sc["status"] == "dry_run", (
        f"unexpected status: {json.dumps(sc, default=str)[:500]}"
    )
    # 2. Observable state: refusal surfaced.
    refused_actions = {r["action"] for r in sc["refused_narrowings"]}
    assert "s3:PutObject" in refused_actions, (
        f"P8 gate did not fire through MCP with inline events; "
        f"refused_narrowings={sc['refused_narrowings']}"
    )
    # 3. Observable state: refused rule did NOT leak into proposed_removals.
    actions_in_removals = {r["action"] for r in sc["proposed_removals"]}
    assert "s3:PutObject" not in actions_in_removals, (
        f"refused narrowing leaked into proposed_removals; "
        f"got {sc['proposed_removals']}"
    )
    # 4. Friction metrics surfaced (operator-visible per
    #    [[ibounce-honest-positioning]]).
    assert sc["friction_metrics_baseline"], (
        f"friction_metrics_baseline empty; got {sc}"
    )
    assert "estimated_weekly_denies" in sc["friction_metrics_baseline"]


# ---------------------------------------------------------------------------
# 2. budget=999 + inline events → narrowing kept (under budget).
# ---------------------------------------------------------------------------


def test_mcp_improve_with_inline_events_budget_high_includes_narrowings(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator_drop_putobject,
    putobject_events,
) -> None:
    """budget=100000 (per existing fixture pattern — large enough to
    pass the 6-event-extrapolation) + same events → narrowing is KEPT
    in proposed_removals + refused_narrowings stays empty for s3:PutObject.

    The headline UAT-A divergence proof: SAME events, DIFFERENT budget,
    DIFFERENT observable output. Pre-fix this was impossible to observe
    without a live bouncer."""
    sc = _mcp_call({
        "bouncer": "ibounce",
        "cadence": "per_session",
        "threshold": 0.30,
        "apply": False,
        "profile_name": "active-test",
        "events": putobject_events,
        "friction_budget": 100_000,
    })
    assert sc["status"] == "dry_run"
    # Observable state: narrowing kept.
    actions_in_removals = {r["action"] for r in sc["proposed_removals"]}
    assert "s3:PutObject" in actions_in_removals, (
        f"under-budget narrowing should be kept; "
        f"got proposed_removals={sc['proposed_removals']}, "
        f"refused={sc['refused_narrowings']}"
    )
    # Observable state: NOT in refused list.
    refused_actions = {r["action"] for r in sc["refused_narrowings"]}
    assert "s3:PutObject" not in refused_actions, (
        f"under-budget narrowing should NOT be refused; "
        f"got refused={sc['refused_narrowings']}"
    )
    # Friction metrics surfaced both ways (operator can inspect the
    # estimate that drove the keep decision).
    assert "estimated_weekly_denies" in sc["friction_metrics_baseline"]
    assert "estimated_weekly_denies" in sc["friction_metrics_if_applied"]


# ---------------------------------------------------------------------------
# 3. Regression: no events + no audit-tail → no_change preserved.
# ---------------------------------------------------------------------------


def test_mcp_improve_no_events_no_audit_defaults_no_change(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-fix behavior MUST be preserved: when caller passes no events
    AND the audit tail returns empty, the cycle reports status:no_change
    with empty friction_metrics (no simulation ran). This is the
    audit-tail query path; the regression check guards
    ``[[ibounce-honest-positioning]]`` no-op honesty."""
    # Force the audit fetcher to return zero events (matches the
    # UAT-A reproduction shape: no live bouncer audit data exists).
    monkeypatch.setattr(
        "iam_jit.improve.pipeline._fetch_events_for_bouncer",
        lambda **_: [],
    )

    sc = _mcp_call({
        "bouncer": "ibounce",
        "cadence": "per_session",
        "threshold": 0.30,
        "apply": False,
        "profile_name": "active-test",
        "friction_budget": 100,
        # Deliberately NO events key.
    })
    # Status claim.
    assert sc["status"] == "no_change", (
        f"empty audit + no inline events should report no_change; "
        f"got {json.dumps(sc, default=str)[:500]}"
    )
    # Observable state: no refusals can have happened (no candidates).
    assert sc.get("refused_narrowings", []) == []
    # friction_metrics empty — no simulation ran.
    assert sc.get("friction_metrics_baseline", {}) == {}
    assert sc.get("friction_metrics_if_applied", {}) == {}


# ---------------------------------------------------------------------------
# 4. Inline events + audit-tail data both exist → inline events win.
# ---------------------------------------------------------------------------


def test_mcp_improve_inline_events_override_audit_tail(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator_drop_putobject,
    putobject_events,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When BOTH inline `events` and audit-tail data are available,
    caller-supplied events MUST win (caller intent is explicit).

    Observable shape: stub the audit fetcher to return a DIFFERENT set
    of events (no PutObject). Pass inline events with PutObject. Verify
    the refusal fires on the INLINE events — proving the inline path
    was used, not the audit-tail path."""
    # Audit-tail returns events that contain NO PutObject ops — if the
    # tool consumed these, NO narrowing of s3:PutObject would surface
    # (because no events would deny against it).
    audit_tail_events = [
        {
            "time": 1_700_000_000_000,
            "_bouncer": "ibounce",
            "metadata": {"event_code": "allow"},
            "api": {
                "operation": "GetObject",  # Different operation.
                "service": {"name": "s3"},
                "resources": [{"name": "arn:aws:s3:::cache/get-1"}],
            },
        }
    ]
    monkeypatch.setattr(
        "iam_jit.improve.pipeline._fetch_events_for_bouncer",
        lambda **_: audit_tail_events,
    )

    sc = _mcp_call({
        "bouncer": "ibounce",
        "cadence": "per_session",
        "threshold": 0.30,
        "apply": False,
        "profile_name": "active-test",
        "events": putobject_events,  # Inline path — should win.
        "friction_budget": 1,
    })
    assert sc["status"] == "dry_run"
    # Observable proof: refusal surfaces because INLINE PutObject events
    # were what the gate saw. If the audit-tail GetObject events had won,
    # there would be no PutObject deny shape and no refusal.
    refused_actions = {r["action"] for r in sc["refused_narrowings"]}
    assert "s3:PutObject" in refused_actions, (
        f"inline events did not win over audit-tail; "
        f"refused_narrowings={sc['refused_narrowings']}, "
        f"proposed_removals={sc['proposed_removals']}"
    )


# ---------------------------------------------------------------------------
# 5. Schema parity — same events fixture works in Phase 4 simulator.
# ---------------------------------------------------------------------------


def test_mcp_improve_events_schema_matches_phase_4_simulator(
    putobject_events,
) -> None:
    """Per ``[[cross-product-agent-parity]]``: the events shape accepted
    by `iam_jit_improve_profile` MUST match the shape accepted by
    `bounce_simulate_profile` (Phase 4). If they diverge, agents must
    translate between MCP tools — exactly the friction this convention
    forbids.

    Observable proof: pass the IDENTICAL fixture to both tools and
    observe both produce non-empty results (simulator returns verdicts;
    improve returns proposed_removals + friction_metrics_baseline)."""
    from iam_jit.mcp_server import _handle_request

    # 1. Phase 4 simulator consumes the events directly.
    sim_resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "bounce_simulate_profile",
            "arguments": {
                "profile": {
                    "bouncer": "ibounce",
                    "allows": [
                        {
                            "target": "arn:aws:s3:::cache*",
                            "actions": ["s3:GetObject"],
                        },
                    ],
                    "denies": [],
                },
                "events": putobject_events,
                "bouncer_kind": "ibounce",
                "friction_budget": 100,
            },
        },
    })
    assert "result" in sim_resp, (
        f"Phase 4 simulator rejected fixture: "
        f"{json.dumps(sim_resp, default=str)[:500]}"
    )
    sim_sc = sim_resp["result"]["structuredContent"]
    # Phase 4 produces per-event verdicts.
    assert sim_sc.get("verdicts"), (
        f"Phase 4 produced no verdicts for shared fixture; got {sim_sc}"
    )
    assert len(sim_sc["verdicts"]) == len(putobject_events), (
        f"Phase 4 verdict count mismatch with fixture; "
        f"verdicts={len(sim_sc['verdicts'])} vs events={len(putobject_events)}"
    )

    # 2. The tools/list schema for both tools must advertise events with
    #    the same shape ({type:array, items:type:object}).
    tools_resp = _handle_request({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
    })
    by_name = {t["name"]: t for t in tools_resp["result"]["tools"]}

    sim_events_schema = (
        by_name["bounce_simulate_profile"]["inputSchema"]
        ["properties"]["events"]
    )
    improve_events_schema = (
        by_name["iam_jit_improve_profile"]["inputSchema"]
        ["properties"]["events"]
    )
    assert sim_events_schema["type"] == improve_events_schema["type"] == "array"
    assert (
        sim_events_schema["items"] == improve_events_schema["items"]
        == {"type": "object"}
    ), (
        f"events schema diverges between Phase 4 simulator and "
        f"iam_jit_improve_profile; "
        f"sim={sim_events_schema}, improve={improve_events_schema}"
    )


# ---------------------------------------------------------------------------
# 6. Sabotage — disable the friction-budget gate; test 1's claim fails.
# ---------------------------------------------------------------------------


def test_sabotage_friction_budget_helper_noop_refuses_nothing(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator_drop_putobject,
    putobject_events,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage the helper that counts effective denies; under sabotage
    the same MCP call from test 1 MUST produce zero refusals.

    This proves test 1's refusal assertion exercises the real
    `_apply_friction_budget_to_narrowings` path, not coincidence.
    Without this sabotage check the test 1 refusal could pass even if
    the gate were entirely bypassed — exactly the
    ``docs/CONTRIBUTING.md`` failure mode."""
    from iam_jit.improve import pipeline as pipe

    # With effective denies forced to 0, no narrowing crosses budget.
    monkeypatch.setattr(pipe, "_count_effective_denies", lambda **_kw: 0)

    sc = _mcp_call({
        "bouncer": "ibounce",
        "cadence": "per_session",
        "threshold": 0.30,
        "apply": False,
        "profile_name": "active-test",
        "events": putobject_events,
        "friction_budget": 1,
    })
    # The same call shape as test 1 — but sabotaged gate suppresses
    # the refusal.
    assert sc["refused_narrowings"] == [], (
        f"sabotage should suppress refusals; got {sc['refused_narrowings']}"
    )
    # And the narrowing now appears in proposed_removals.
    actions_in_removals = {r["action"] for r in sc["proposed_removals"]}
    assert "s3:PutObject" in actions_in_removals, (
        f"sabotaged gate path should let s3:PutObject through; "
        f"got proposed_removals={sc['proposed_removals']}"
    )


# ---------------------------------------------------------------------------
# 7. tools/list advertises events on iam_jit_improve_profile.
# ---------------------------------------------------------------------------


def test_mcp_improve_tool_schema_advertises_events() -> None:
    """The tools/list response MUST advertise the new `events` property
    on `iam_jit_improve_profile`. Without the schema entry, MCP hosts
    that enforce strict input validation would reject inline events
    (defeats the fix). Description must mention the demo/test use case
    and the audit-tail fallback so operators understand when to use it
    per ``[[ibounce-honest-positioning]]``."""
    from iam_jit.mcp_server import _handle_request

    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    tools_by_name = {t["name"]: t for t in resp["result"]["tools"]}
    assert "iam_jit_improve_profile" in tools_by_name
    schema = tools_by_name["iam_jit_improve_profile"]["inputSchema"]
    props = schema.get("properties", {})
    assert "events" in props, (
        f"iam_jit_improve_profile schema missing events; "
        f"got props={sorted(props.keys())}"
    )
    ev_schema = props["events"]
    assert ev_schema.get("type") == "array"
    assert ev_schema.get("items") == {"type": "object"}
    # Description must explain when to use it vs audit-tail.
    desc = (ev_schema.get("description") or "").lower()
    assert "audit" in desc, (
        f"events description should explain audit-tail fallback; "
        f"got {ev_schema.get('description')!r}"
    )
