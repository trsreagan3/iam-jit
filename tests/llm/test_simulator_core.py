"""Phase 4 of profile-generation design (docs/PROFILE-GENERATION-DESIGN.md
§3 + §6 Phase 4) — simulator core extraction.

Per [[tests-and-independent-uat-required]] + docs/CONTRIBUTING.md
state-verification convention: every test asserts OBSERVABLE state
(per-event verdict list content, not just summary counts) so a
regression that flips a single verdict can't hide behind matching
totals.

Test taxonomy:
  1.  empty events -> empty verdicts list + zero counts
  2.  single allow_rule + matching event -> verdict allow + matched_rule
      populated
  3.  single deny_rule + matching event -> verdict deny + matched_rule
      populated + reason set
  4.  no rule matches -> abstain
  5.  event matches BOTH allow + deny -> deny (deny-overrides-allow)
  6.  _SAFETY_FLOOR_DENIES patterns deny regardless of profile
  7.  friction_budget supplied -> friction_metrics populated +
      over_budget computed
  8.  friction_budget=None -> friction_metrics empty
  9.  provenance.engine accurately reflects engine reality
  10. cross-bouncer parametrize: each of ibounce/kbouncer/dbounce/
      gbounce returns sensible verdicts with their safety floor
  11. sabotage-check: monkeypatch evaluator to all-allow + verify
      deny-overrides-allow test would catch the regression
  12. MCP dispatch: invoke via real _handle_request + verify JSON-
      serializable + schema-shaped
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit.llm import simulator as sim


# ---------------------------------------------------------------------------
# Event helpers — cross-bouncer.
# ---------------------------------------------------------------------------


def _ibounce_event(
    *, action: str, resource: str, time_ms: int = 1716412800000,
) -> dict[str, Any]:
    svc, _, op = action.partition(":")
    return {
        "_bouncer": "ibounce",
        "time": time_ms,
        "activity_name": "allow",
        "unmapped": {"iam_jit": {"verdict": "allow"}},
        "api": {
            "service": {"name": svc},
            "operation": op,
            "resources": [{"name": resource}],
        },
    }


def _kbounce_event(
    *, verb: str, resource: str, namespace: str = "default",
    time_ms: int = 1716412800000,
) -> dict[str, Any]:
    return {
        "_bouncer": "kbounce",
        "time": time_ms,
        "activity_name": verb,
        "unmapped": {"iam_jit": {"verdict": "allow", "ext": {
            "namespace": namespace,
        }}},
        "api": {
            "service": {"name": "k8s"},
            "operation": verb,
            "resources": [{"name": f"{namespace}/{resource}"}],
        },
    }


def _dbounce_event(
    *, statement: str, table: str, host: str = "db.local",
    time_ms: int = 1716412800000,
) -> dict[str, Any]:
    return {
        "_bouncer": "dbounce",
        "time": time_ms,
        "activity_name": statement.lower(),
        "unmapped": {"iam_jit": {"verdict": "allow", "ext": {}}},
        "api": {
            "service": {"name": "postgres"},
            "operation": statement,
            "resources": [{"name": table}],
        },
        "dst_endpoint": {"hostname": host, "port": 5432},
    }


def _gbounce_event(
    *, method: str, path: str, host: str = "api.local",
    time_ms: int = 1716412800000,
) -> dict[str, Any]:
    return {
        "_bouncer": "gbounce",
        "time": time_ms,
        "activity_name": method.lower(),
        "unmapped": {"iam_jit": {"verdict": "allow", "ext": {}}},
        "api": {
            "service": {"name": host},
            "operation": f"{method} {path}",
            "resources": [{"name": path, "uid": f"https://{host}{path}"}],
        },
        "dst_endpoint": {"hostname": host, "port": 443},
    }


# ---------------------------------------------------------------------------
# Test 1 — empty events.
# ---------------------------------------------------------------------------


def test_evaluate_empty_events():
    profile = {"bouncer": "ibounce", "allows": [], "denies": []}
    result = sim.evaluate_profile_against_events(
        profile=profile, events=[], bouncer_kind="ibounce",
    )

    # State verification: verdicts list is empty AND summary counts
    # match (catches a regression where summary counted phantom events).
    assert result.verdicts == []
    assert result.summary == {
        "total": 0, "allow": 0, "deny": 0, "abstain": 0,
    }
    # Provenance always populated regardless of input.
    assert result.provenance["engine"] == "simulation-python"


# ---------------------------------------------------------------------------
# Test 2 — single allow match.
# ---------------------------------------------------------------------------


def test_evaluate_single_allow_match():
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {
                "target": "arn:aws:s3:::bucket-a/*",
                "actions": ["s3:GetObject"],
                "reason": "test allow",
            }
        ],
        "denies": [],
    }
    events = [_ibounce_event(
        action="s3:GetObject", resource="arn:aws:s3:::bucket-a/key1",
    )]
    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
    )

    # State verification: the exact verdict for THIS event is allow +
    # matched_rule names the rule index + actions.
    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.verdict == "allow"
    assert v.event_idx == 0
    assert v.matched_rule is not None
    assert "allows[0]" in v.matched_rule
    assert "s3:GetObject" in v.matched_rule
    assert v.reason == "test allow"
    assert result.summary["allow"] == 1
    assert result.summary["deny"] == 0


# ---------------------------------------------------------------------------
# Test 3 — single deny match.
# ---------------------------------------------------------------------------


def test_evaluate_single_deny_match():
    profile = {
        "bouncer": "ibounce",
        "allows": [],
        "denies": [
            {
                "target": "*",
                "actions": ["s3:DeleteObject"],
                "reason": "deletes blocked in this env",
            }
        ],
    }
    events = [_ibounce_event(
        action="s3:DeleteObject", resource="arn:aws:s3:::bucket-a/key1",
    )]
    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
    )

    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.verdict == "deny"
    assert v.matched_rule is not None
    assert "denies[0]" in v.matched_rule
    assert v.reason == "deletes blocked in this env"
    assert result.summary["deny"] == 1


# ---------------------------------------------------------------------------
# Test 4 — no match -> abstain.
# ---------------------------------------------------------------------------


def test_evaluate_no_match_abstain():
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {"target": "*", "actions": ["s3:GetObject"], "reason": "reads"}
        ],
        "denies": [
            {"target": "*", "actions": ["iam:CreateUser"], "reason": "no user"}
        ],
    }
    # Action not in any rule.
    events = [_ibounce_event(
        action="dynamodb:Query", resource="arn:aws:dynamodb:::table/orders",
    )]
    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
    )

    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.verdict == "abstain"
    assert v.matched_rule is None
    assert "no allow/deny rule matched" in v.reason
    assert result.summary["abstain"] == 1


# ---------------------------------------------------------------------------
# Test 5 — deny overrides allow.
# ---------------------------------------------------------------------------


def test_evaluate_deny_overrides_allow():
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {
                "target": "*",
                "actions": ["s3:*"],
                "reason": "broad allow",
            }
        ],
        "denies": [
            {
                "target": "arn:aws:s3:::sensitive-*",
                "actions": ["s3:GetObject"],
                "reason": "sensitive bucket protection",
            }
        ],
    }
    events = [_ibounce_event(
        action="s3:GetObject", resource="arn:aws:s3:::sensitive-payroll/data",
    )]
    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
    )

    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    # Even though the allow rule ALSO matches (s3:*), deny precedence
    # must fire. This is the load-bearing invariant.
    assert v.verdict == "deny", (
        f"deny must beat allow when both match; got verdict={v.verdict} "
        f"matched_rule={v.matched_rule}"
    )
    assert v.matched_rule is not None
    assert "denies[" in v.matched_rule
    assert v.reason == "sensitive bucket protection"


# ---------------------------------------------------------------------------
# Test 6 — safety floor always denies.
# ---------------------------------------------------------------------------


def test_evaluate_safety_floor_denies():
    """_SAFETY_FLOOR_DENIES patterns must deny even when the profile
    has an explicit allow for the same action — the floor is universal
    per design §2.3."""
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {
                "target": "*",
                "actions": ["iam:CreateAccessKey"],
                "reason": "intentionally permissive for the test",
            }
        ],
        "denies": [],
    }
    events = [_ibounce_event(
        action="iam:CreateAccessKey",
        resource="arn:aws:iam::123:user/bot",
    )]
    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
    )

    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.verdict == "deny", (
        f"safety floor must fire even when profile allows the action; "
        f"got verdict={v.verdict} matched_rule={v.matched_rule}"
    )
    # The reason must mention the floor source so an operator can
    # trace the denial back to the universal-hard-floor codepath, not
    # a profile rule they could mistakenly relax.
    assert v.matched_rule is not None
    floor_marker_hit = (
        "_SAFETY_FLOOR_DENIES" in (v.matched_rule or "")
        or "KNOWN_ADVERSARIAL_PATTERNS" in (v.matched_rule or "")
    )
    assert floor_marker_hit, (
        f"matched_rule must name the floor source; got {v.matched_rule!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — friction_metrics populated when budget supplied.
# ---------------------------------------------------------------------------


def test_evaluate_friction_metrics_populated():
    """Observed 10 denies across a 7-day span + budget=5 -> over_budget
    with over_budget_factor=2.0."""
    profile = {
        "bouncer": "ibounce", "allows": [],
        "denies": [
            {"target": "*", "actions": ["s3:DeleteObject"], "reason": "no delete"},
        ],
    }
    # 10 denies spread across 7 days (one every ~16.8h).
    start_ms = 1716412800000
    one_day_ms = 24 * 60 * 60 * 1000
    seven_days_ms = 7 * one_day_ms
    events = []
    for i in range(10):
        t = start_ms + int(i * (seven_days_ms / 9))
        events.append(_ibounce_event(
            action="s3:DeleteObject",
            resource="arn:aws:s3:::bucket/key",
            time_ms=t,
        ))

    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
        friction_budget=5,
    )

    fm = result.friction_metrics
    # State verification: every documented field is present + the
    # math checks out at the observable level (over_budget True,
    # factor ~2.0).
    assert fm["actual_denies_in_window"] == 10
    assert fm["budget_max_denies_per_week"] == 5
    assert fm["over_budget"] is True
    assert 1.8 < fm["over_budget_factor"] < 2.2, (
        f"expected over_budget_factor ~2.0; got {fm['over_budget_factor']}"
    )
    # All 10 events must be in the verdicts list as deny.
    assert sum(1 for v in result.verdicts if v.verdict == "deny") == 10


# ---------------------------------------------------------------------------
# Test 8 — friction_metrics empty when budget=None.
# ---------------------------------------------------------------------------


def test_evaluate_friction_metrics_omitted_when_budget_none():
    profile = {"bouncer": "ibounce", "allows": [], "denies": []}
    events = [_ibounce_event(
        action="s3:GetObject", resource="arn:aws:s3:::bucket/key",
    )]
    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
        friction_budget=None,
    )

    assert result.friction_metrics == {}


# ---------------------------------------------------------------------------
# Test 9 — provenance honesty.
# ---------------------------------------------------------------------------


def test_evaluate_provenance_engine_honest():
    """provenance.engine MUST be 'simulation-python' (not 'production-
    parity' or similar) for ALL bouncers per [[ibounce-honest-
    positioning]]. provenance.warnings MUST enumerate per-bouncer
    divergence so operators see the gap."""
    profile = {"bouncer": "ibounce", "allows": [], "denies": []}
    events = [_ibounce_event(
        action="s3:GetObject", resource="arn:aws:s3:::bucket/key",
    )]

    for bk in ("ibounce", "kbounce", "dbounce", "gbounce"):
        result = sim.evaluate_profile_against_events(
            profile=profile, events=events, bouncer_kind=bk,
        )
        assert result.provenance["engine"] == "simulation-python", (
            f"engine field must be honest about non-production-parity; "
            f"got {result.provenance['engine']!r} for bouncer {bk}"
        )
        assert result.provenance["production_parity"] is False, (
            "production_parity flag must remain False until a real "
            "cross-engine harness lands"
        )
        warnings = result.provenance.get("warnings") or []
        # State verification: warnings list is NON-EMPTY + the strings
        # name the divergence dimensions an operator would care about.
        assert warnings, (
            f"warnings must enumerate divergence for {bk}; got empty"
        )
        joined = " ".join(warnings).lower()
        # Every bouncer's catalogue must mention something about the
        # engine being a simulator OR Go-side production.
        assert (
            "simulation" in joined
            or "go-side" in joined
            or "production" in joined
            or "generator-shape" in joined
        ), f"warnings for {bk} too vague: {warnings!r}"


# ---------------------------------------------------------------------------
# Test 10 — cross-bouncer parametrize.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bouncer_kind,event,expected_deny",
    [
        # ibounce: iam:CreateAccessKey is in _SAFETY_FLOOR_DENIES.
        (
            "ibounce",
            _ibounce_event(
                action="iam:CreateAccessKey",
                resource="arn:aws:iam::123:user/bot",
            ),
            True,
        ),
        # kbounce: delete on namespaces hits the cluster floor.
        (
            "kbounce",
            _kbounce_event(verb="delete", resource="namespaces",
                          namespace="kube-system"),
            True,
        ),
        # dbounce: GRANT TO PUBLIC pattern is in floor.
        (
            "dbounce",
            _dbounce_event(
                statement="GRANT ALL PRIVILEGES TO PUBLIC",
                table="users",
            ),
            True,
        ),
        # gbounce: 169.254.169.254 (IMDS) host is in floor.
        (
            "gbounce",
            _gbounce_event(
                method="GET", path="/latest/meta-data/",
                host="169.254.169.254",
            ),
            True,
        ),
    ],
)
def test_evaluate_cross_bouncer_safety_floor(
    bouncer_kind: str, event: dict[str, Any], expected_deny: bool,
):
    """Every bouncer's safety floor must fire on its canonical
    adversarial-pattern event even with an EMPTY profile (no allow
    rules at all). The floor is the structural backstop."""
    profile = {"bouncer": bouncer_kind, "allows": [], "denies": []}
    result = sim.evaluate_profile_against_events(
        profile=profile, events=[event], bouncer_kind=bouncer_kind,
    )

    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    if expected_deny:
        assert v.verdict == "deny", (
            f"{bouncer_kind} canonical adversarial event should deny via "
            f"safety floor; got verdict={v.verdict} reason={v.reason!r}"
        )


# ---------------------------------------------------------------------------
# Test 11 — sabotage check.
# ---------------------------------------------------------------------------


def test_sabotage_check_deny_overrides_allow_failure_detected(
    monkeypatch: pytest.MonkeyPatch,
):
    """Sabotage: monkeypatch the per-event evaluator so it always
    returns allow regardless of profile. The test_evaluate_deny_
    overrides_allow shape (deny+allow simultaneously matching) MUST
    then return allow — which fails the deny-precedence invariant.
    This proves the deny-overrides test is load-bearing, not theater."""
    real_eval = sim._evaluate_one_event

    def sabotage_eval(event_idx, event, allow_rules, deny_rules, bouncer_kind):
        # Always return allow with the first allow rule, ignoring denies.
        if allow_rules:
            return sim.SimulationVerdict(
                event_idx=event_idx,
                event=event,
                verdict="allow",
                reason="sabotaged: forced allow",
                matched_rule="allows[0]: sabotaged",
            )
        return real_eval(
            event_idx, event, allow_rules, deny_rules, bouncer_kind,
        )

    monkeypatch.setattr(sim, "_evaluate_one_event", sabotage_eval)

    profile = {
        "bouncer": "ibounce",
        "allows": [
            {"target": "*", "actions": ["s3:*"], "reason": "broad"},
        ],
        "denies": [
            {
                "target": "arn:aws:s3:::sensitive-*",
                "actions": ["s3:GetObject"],
                "reason": "sensitive bucket",
            },
        ],
    }
    events = [_ibounce_event(
        action="s3:GetObject", resource="arn:aws:s3:::sensitive-payroll/x",
    )]
    result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
    )

    # Under sabotage, the verdict flips to allow — which is exactly
    # the regression the real test 5 (deny-overrides-allow) would
    # catch. This test confirms test 5 is actually testing behaviour.
    assert result.verdicts[0].verdict == "allow", (
        "sabotage path must yield allow; if this assertion fails the "
        "sabotage harness itself broke (regression in monkeypatch path)"
    )
    # Negative assertion: with the real evaluator, the same input
    # returns deny. Verify by calling the unpatched function path.
    monkeypatch.setattr(sim, "_evaluate_one_event", real_eval)
    real_result = sim.evaluate_profile_against_events(
        profile=profile, events=events, bouncer_kind="ibounce",
    )
    assert real_result.verdicts[0].verdict == "deny"


# ---------------------------------------------------------------------------
# Test 12 — MCP dispatch round-trip.
# ---------------------------------------------------------------------------


def test_mcp_dispatch_bounce_simulate_profile_returns_serialized_verdicts():
    """Invoke via real _handle_request + verify the response carries
    the schema-shaped fields + serializes cleanly to JSON (no
    dataclass leakage)."""
    import json

    from iam_jit.mcp_server import _handle_request

    profile = {
        "bouncer": "ibounce",
        "allows": [
            {"target": "*", "actions": ["s3:GetObject"], "reason": "reads"},
        ],
        "denies": [
            {"target": "*", "actions": ["s3:DeleteObject"], "reason": "no delete"},
        ],
    }
    events = [
        _ibounce_event(
            action="s3:GetObject", resource="arn:aws:s3:::bucket/key",
        ),
        _ibounce_event(
            action="s3:DeleteObject", resource="arn:aws:s3:::bucket/key",
            time_ms=1716412900000,
        ),
    ]

    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "bounce_simulate_profile",
            "arguments": {
                "profile": profile,
                "events": events,
                "bouncer_kind": "ibounce",
                "friction_budget": 100,
            },
        },
    })

    sc = resp["result"]["structuredContent"]
    # Must JSON-roundtrip cleanly.
    rendered = json.dumps(sc)
    assert rendered  # no exception
    # Schema-shape verification.
    assert sc["bouncer_kind"] == "ibounce"
    assert sc["summary"]["total"] == 2
    assert sc["summary"]["allow"] == 1
    assert sc["summary"]["deny"] == 1
    assert sc["provenance"]["engine"] == "simulation-python"
    assert "friction_metrics" in sc
    # Per-event verdict structure check.
    assert len(sc["verdicts"]) == 2
    for v in sc["verdicts"]:
        assert v["verdict"] in ("allow", "deny", "abstain")
        assert "event_idx" in v
        assert "matched_rule" in v
        assert "reason" in v


def test_mcp_tool_appears_in_tools_list():
    """bounce_simulate_profile MUST surface in tools/list so agents
    discover it via standard MCP discovery."""
    from iam_jit.mcp_server import _handle_request

    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "bounce_simulate_profile" in names, (
        f"new MCP tool missing from tools/list; got "
        f"{sorted(n for n in names if 'simulate' in n.lower())}"
    )
