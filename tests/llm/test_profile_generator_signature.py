"""Phase 3 prerequisite — signature-compatibility verification for
``_deterministic_fallback_profile``.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §6 Phase 3 the lean-permissive
flag wires into the deterministic-fallback path. This requires the
function accept two new kwargs (``lean_permissive`` + ``friction_budget``)
without breaking the four existing in-tree callers (in
``src/iam_jit/llm/profile_generator.py`` at lines 852 / 864 / 878 / 894 /
970, all using keyword arguments).

State-verification per CONTRIBUTING.md: the test asserts the
OBSERVABLE state (the function returns a valid profile dict + the new
kwargs don't change behaviour when defaulted) — not just "the call
didn't crash."
"""

from __future__ import annotations

import inspect

import pytest

from iam_jit.llm.profile_generator import _deterministic_fallback_profile


def _allow_event(
    bouncer: str = "ibounce",
    action: str = "s3:GetObject",
    resource: str = "arn:aws:s3:::reports",
) -> dict:
    """Build a minimal OCSF-shape event the fallback can parse."""
    service, _, op = action.partition(":")
    return {
        "_bouncer": bouncer,
        "api": {
            "service": {"name": service or "s3"},
            "operation": op or action,
            "resources": [{"name": resource}],
        },
        "unmapped": {"iam_jit": {"verdict": "allow"}},
    }


# ---------------------------------------------------------------------------
# Existing-caller backward-compat — pre-Phase-3 keyword shape
# ---------------------------------------------------------------------------


def test_pre_phase_3_caller_pattern_still_works() -> None:
    """The four existing in-tree callers pass only ``bouncer``,
    ``events``, ``add_safety_denies`` as kwargs. Verify the pre-Phase-3
    shape still produces a valid profile."""
    events = [_allow_event()]
    result = _deterministic_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
    )
    # State-verification: not just "no crash" — the profile must have
    # the expected shape and contain the observed allow.
    assert isinstance(result, dict)
    assert result["bouncer"] == "ibounce"
    assert isinstance(result["allows"], list)
    assert any(
        "arn:aws:s3:::reports" == a["target"]
        for a in result["allows"]
    )
    assert "denies" in result
    assert "flagged_for_review" in result


def test_pre_phase_3_caller_with_safety_denies_off() -> None:
    """The ``add_safety_denies=False`` shape works without the new
    kwargs."""
    result = _deterministic_fallback_profile(
        bouncer="ibounce",
        events=[],
        add_safety_denies=False,
    )
    assert isinstance(result, dict)
    # State-verification: denies must be empty when safety is off.
    assert result["denies"] == []


# ---------------------------------------------------------------------------
# Phase 3 caller pattern — new kwargs accepted
# ---------------------------------------------------------------------------


def test_phase_3_lean_permissive_kwarg_accepted() -> None:
    """Phase 3 passes ``lean_permissive=True``. Verify the kwarg is
    accepted without TypeError (the whole point of this prereq)."""
    events = [_allow_event()]
    result = _deterministic_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
        lean_permissive=True,
    )
    # State-verification: behaviour is unchanged from the pre-Phase-3
    # baseline while Phase 3 itself is still pending — accepting the
    # kwarg means Phase 3 can wire the heuristic into this body
    # without a signature churn.
    assert isinstance(result, dict)
    assert result["bouncer"] == "ibounce"


def test_phase_3_friction_budget_kwarg_accepted() -> None:
    """Phase 3 may pass ``friction_budget={...}``. Verify the kwarg is
    accepted."""
    events = [_allow_event()]
    result = _deterministic_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
        friction_budget={
            "max_legitimate_denies_per_day": 3,
            "max_legitimate_denies_per_week": 10,
        },
    )
    assert isinstance(result, dict)


def test_phase_3_both_new_kwargs_accepted() -> None:
    """Phase 3's typical call: both new kwargs in one call. Verify the
    combined shape works."""
    events = [_allow_event()]
    result = _deterministic_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
        lean_permissive=True,
        friction_budget={
            "max_legitimate_denies_per_day": 3,
            "max_legitimate_denies_per_week": 10,
        },
    )
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Defaults — new kwargs default to safe values
# ---------------------------------------------------------------------------


def test_new_kwargs_have_safe_defaults() -> None:
    """Per spec: defaults are ``lean_permissive=False`` and
    ``friction_budget=None`` so pre-Phase-3 callers see no behaviour
    change."""
    sig = inspect.signature(_deterministic_fallback_profile)
    params = sig.parameters

    assert "lean_permissive" in params
    assert params["lean_permissive"].default is False
    assert params["lean_permissive"].kind is inspect.Parameter.KEYWORD_ONLY

    assert "friction_budget" in params
    assert params["friction_budget"].default is None
    assert params["friction_budget"].kind is inspect.Parameter.KEYWORD_ONLY


def test_existing_kwargs_are_keyword_only() -> None:
    """Per spec: keyword-only signature means no positional-arg breakage
    risk for in-tree callers. Pin the keyword-only convention."""
    sig = inspect.signature(_deterministic_fallback_profile)
    for name in ("bouncer", "events", "add_safety_denies"):
        param = sig.parameters[name]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, (
            f"{name} must be keyword-only to keep backward-compat"
        )


def test_lean_permissive_default_matches_pre_phase_3_behaviour() -> None:
    """Calling with the new kwarg explicitly set to its default value
    produces a profile byte-identical to omitting the kwarg.

    This is the load-bearing state-verification: the Phase 3 hook
    point is in place but DORMANT until Phase 3 wires it. The two
    calls must produce identical profiles."""
    events = [_allow_event()]

    pre_phase_3 = _deterministic_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
    )

    explicit_default = _deterministic_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
        lean_permissive=False,
        friction_budget=None,
    )

    assert pre_phase_3 == explicit_default


# ---------------------------------------------------------------------------
# Defensive — unknown kwarg still raises (we don't accept **kwargs)
# ---------------------------------------------------------------------------


def test_unknown_kwarg_still_raises_type_error() -> None:
    """The function does NOT accept arbitrary **kwargs — typos in
    future caller refactors must still surface as TypeError. Pin the
    strict signature so accidental misuse doesn't silently pass."""
    with pytest.raises(TypeError):
        _deterministic_fallback_profile(
            bouncer="ibounce",
            events=[],
            add_safety_denies=True,
            nonsense_param=True,  # type: ignore[call-arg]
        )
