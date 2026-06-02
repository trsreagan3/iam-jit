# #723 / BUILD-2 — agent flight recorder timeline assembly tests.
"""Pure-function tests of :func:`iam_jit.flight_recorder.assemble_timeline`.

The assembler is the I/O-free core: given the merged cross-bouncer
event list + the per-bouncer notes (what
``fetch_session_events_via_fanout`` returns), it produces the ordered,
normalized timeline + the honesty / coverage block. These tests pin:

* multi-bouncer ordering by timestamp with a stable cross-bouncer
  tiebreak;
* the honesty block — unreachable bouncers, reachable-but-zero-event
  bouncers, partial flag, timeless-step gap;
* empty-session shape;
* the closed-field JSON shape (no raw event body leaks through).
"""

from __future__ import annotations

from iam_jit.flight_recorder import TIMELINE_SCHEMA_VERSION, assemble_timeline


def _ev(bouncer, time, op, verdict=None, **extra):
    ev = {
        "_bouncer": bouncer,
        "time": time,
        "api": {"operation": op},
        "unmapped": {"iam_jit": {"agent": {"session_id": "S1"}}},
    }
    if verdict is not None:
        ev["unmapped"]["iam_jit"]["verdict"] = verdict
    for k, v in extra.items():
        ev[k] = v
    return ev


def _all_reachable():
    return {b: "" for b in ("ibounce", "kbounce", "dbounce", "gbounce")}


# --------------------------------------------------------------------------
# Ordering
# --------------------------------------------------------------------------


def test_multi_bouncer_ordered_by_timestamp():
    events = [
        _ev("gbounce", "2026-06-03T10:00:03Z", "POST /v1/messages", "allow"),
        _ev("ibounce", "2026-06-03T10:00:01Z", "s3:GetObject", "deny"),
        _ev("dbounce", "2026-06-03T10:00:02Z", "SELECT", "allow"),
    ]
    tl = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    order = [s["bouncer"] for s in tl["steps"]]
    assert order == ["ibounce", "dbounce", "gbounce"]
    # index is the timeline position, monotonic from 0.
    assert [s["index"] for s in tl["steps"]] == [0, 1, 2]


def test_mixed_ms_and_iso_timestamps_order_consistently():
    # ms epoch + ISO string must interleave correctly.
    # dbounce's ISO timestamp (2026-05-28T20:26:41Z = 1_780_000_001_000)
    # is one second BEFORE ibounce's ms-epoch (1_780_000_002_000), so
    # dbounce must order first even though the two use different time
    # encodings — the assembler normalizes both to epoch-ms.
    events = [
        _ev("ibounce", 1_780_000_002_000, "s3:Get", "allow"),
        _ev("dbounce", "2026-05-28T20:26:41Z", "SELECT", "allow"),
    ]
    tl = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    assert [s["bouncer"] for s in tl["steps"]] == ["dbounce", "ibounce"]


def test_stable_tiebreak_on_identical_timestamp():
    # Same timestamp across bouncers -> deterministic order regardless
    # of arrival order. Tiebreak is (bouncer, arrival_index).
    t = "2026-06-03T10:00:00Z"
    events = [
        _ev("gbounce", t, "POST /a", "allow"),
        _ev("ibounce", t, "s3:Get", "allow"),
        _ev("dbounce", t, "SELECT", "allow"),
    ]
    tl1 = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    tl2 = assemble_timeline(
        session_id="S1", events=list(reversed(events)),
        notes_by_bouncer=_all_reachable(),
    )
    o1 = [s["bouncer"] for s in tl1["steps"]]
    o2 = [s["bouncer"] for s in tl2["steps"]]
    assert o1 == o2 == ["dbounce", "gbounce", "ibounce"]  # sorted by bouncer


def test_timeless_step_sorts_last_and_is_flagged():
    events = [
        _ev("ibounce", None, "s3:Get", "allow"),  # no timestamp
        _ev("dbounce", "2026-06-03T10:00:01Z", "SELECT", "allow"),
    ]
    tl = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    assert [s["bouncer"] for s in tl["steps"]] == ["dbounce", "ibounce"]
    assert tl["steps"][-1]["has_timestamp"] is False
    assert any("no parseable timestamp" in g for g in tl["coverage"]["gaps"])


# --------------------------------------------------------------------------
# Honesty / coverage block
# --------------------------------------------------------------------------


def test_unreachable_bouncer_flags_partial_and_gap():
    events = [_ev("ibounce", "2026-06-03T10:00:01Z", "s3:Get", "allow")]
    notes = {"ibounce": "", "kbounce": "connection refused",
             "dbounce": "", "gbounce": ""}
    tl = assemble_timeline(session_id="S1", events=events, notes_by_bouncer=notes)
    cov = tl["coverage"]
    assert cov["partial"] is True
    assert {"bouncer": "kbounce", "reason": "connection refused"} in cov["bouncers_unreachable"]
    assert any("kbounce unreachable" in g for g in cov["gaps"])


def test_reachable_zero_event_bouncer_is_genuine_gap_not_failure():
    # dbounce + gbounce answered but contributed nothing — that is an
    # honest gap (genuine), distinct from an unreachable probe failure.
    events = [_ev("ibounce", "2026-06-03T10:00:01Z", "s3:Get", "allow")]
    tl = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    cov = tl["coverage"]
    # All reachable, so NOT partial (no probe failed)...
    assert cov["partial"] is False
    # ...but the zero-event bouncers are surfaced as genuine gaps.
    assert set(cov["bouncers_reachable_no_events"]) == {"kbounce", "dbounce", "gbounce"}
    assert any("genuine gap" in g for g in cov["gaps"])


def test_contributing_bouncers_listed():
    events = [
        _ev("ibounce", "2026-06-03T10:00:01Z", "s3:Get", "allow"),
        _ev("dbounce", "2026-06-03T10:00:02Z", "SELECT", "allow"),
    ]
    tl = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    assert tl["coverage"]["bouncers_contributing"] == ["dbounce", "ibounce"]


def test_cross_session_event_dropped():
    # A buggy bouncer echoes an event from a DIFFERENT session — it must
    # not pollute the replay.
    leak = _ev("kbounce", "2026-06-03T10:00:05Z", "create pod", "allow")
    leak["unmapped"]["iam_jit"]["agent"]["session_id"] = "OTHER"
    events = [
        _ev("ibounce", "2026-06-03T10:00:01Z", "s3:Get", "allow"),
        leak,
    ]
    tl = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    assert tl["step_count"] == 1
    assert tl["steps"][0]["bouncer"] == "ibounce"


# --------------------------------------------------------------------------
# Empty session
# --------------------------------------------------------------------------


def test_empty_session_shape():
    tl = assemble_timeline(
        session_id="S1", events=[], notes_by_bouncer=_all_reachable()
    )
    assert tl["step_count"] == 0
    assert tl["steps"] == []
    assert tl["coverage"]["partial"] is False
    # Every reachable bouncer with 0 events is a genuine gap.
    assert set(tl["coverage"]["bouncers_reachable_no_events"]) == {
        "ibounce", "kbounce", "dbounce", "gbounce"
    }
    assert tl["meta"]["protocols_represented"] == []


def test_empty_all_unreachable_is_partial():
    notes = {b: "connection refused" for b in
             ("ibounce", "kbounce", "dbounce", "gbounce")}
    tl = assemble_timeline(session_id="S1", events=[], notes_by_bouncer=notes)
    assert tl["coverage"]["partial"] is True
    assert tl["step_count"] == 0
    assert len(tl["coverage"]["bouncers_unreachable"]) == 4


# --------------------------------------------------------------------------
# JSON shape + closed-field discipline
# --------------------------------------------------------------------------


def test_step_field_shape_is_closed():
    events = [
        _ev(
            "ibounce", "2026-06-03T10:00:01Z", "s3:GetObject", "deny",
            resources=[{"uid": "arn:aws:s3:::bucket/key"}],
            status="Failure",
        )
    ]
    events[0]["unmapped"]["iam_jit"]["reason"] = "not in granted policy"
    events[0]["unmapped"]["iam_jit"]["role"] = "jit-readonly-abc"
    # A secret hides in an exotic, non-allow-listed field.
    events[0]["unmapped"]["iam_jit"]["secret_field"] = "AKIA-SUPER-SECRET"
    tl = assemble_timeline(
        session_id="S1", events=events, notes_by_bouncer=_all_reachable()
    )
    step = tl["steps"][0]
    expected_keys = {
        "index", "arrival_index", "bouncer", "protocol", "time_ms", "time",
        "action", "decision", "reason", "resources", "principal",
        "iam_context", "status", "has_timestamp",
    }
    assert set(step.keys()) == expected_keys
    assert step["action"] == "s3:GetObject"
    assert step["decision"] == "deny"
    assert step["reason"] == "not in granted policy"
    assert step["resources"] == ["arn:aws:s3:::bucket/key"]
    assert step["iam_context"] == "jit-readonly-abc"
    assert step["status"] == "Failure"
    assert step["protocol"] == "AWS"
    # Closed-field: the exotic secret must NOT appear anywhere in the
    # serialized timeline (same discipline as ABOM).
    import json
    assert "AKIA-SUPER-SECRET" not in json.dumps(tl)


def test_top_level_shape_and_schema():
    tl = assemble_timeline(
        session_id="S1",
        events=[_ev("gbounce", "2026-06-03T10:00:01Z", "POST /x", "allow")],
        notes_by_bouncer=_all_reachable(),
        since="2h",
        until=None,
    )
    assert tl["schema"] == TIMELINE_SCHEMA_VERSION
    assert tl["session_id"] == "S1"
    assert set(tl.keys()) == {
        "schema", "session_id", "step_count", "steps", "coverage", "meta"
    }
    assert tl["meta"]["since"] == "2h"
    assert tl["meta"]["events_analyzed"] == 1
    assert tl["meta"]["steps_per_protocol"] == {"HTTP": 1}


def test_unknown_action_fallback():
    # No service:Action and no api.operation -> activity_name fallback.
    ev = {
        "_bouncer": "kbounce",
        "time": "2026-06-03T10:00:01Z",
        "activity_name": "Create",
        "unmapped": {"iam_jit": {"verdict": "allow",
                                 "agent": {"session_id": "S1"}}},
    }
    tl = assemble_timeline(
        session_id="S1", events=[ev], notes_by_bouncer=_all_reachable()
    )
    assert tl["steps"][0]["action"] == "Create"
    assert tl["steps"][0]["protocol"] == "K8s"


def test_serve_surface_protocol_label():
    ev = _ev("iam-jit-serve", "2026-06-03T10:00:01Z", "request_cap_exceeded")
    tl = assemble_timeline(
        session_id="S1", events=[ev],
        notes_by_bouncer={"iam-jit-serve": ""},
    )
    assert tl["steps"][0]["protocol"] == "iam-jit"
