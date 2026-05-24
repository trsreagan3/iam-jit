"""#560 — missing-profile warning surface tests for setup.py:1179-1200.

Before the #560 fix, declaring a profile name not present in
profiles.yaml produced ZERO warning, because:

  * `load_profiles()` returns `dict[str, Profile]`
  * `{p.name for p in profiles}` iterated the dict KEYS (strings)
    and called `.name` on each string → AttributeError
  * `except Exception: pass` swallowed the AttributeError silently
  * the warning-emitting branch (`profile not in names`) was never
    reached because the AttributeError fired during set comprehension

Net effect: the load-bearing operator hint
("you pinned a profile that doesn't exist; the bouncer will reject
--profile at startup") never reached the operator. Exact MRR-2
Pattern B shape per [[ibounce-honest-positioning]].

Per CONTRIBUTING.md state-verification convention: each test asserts
observable state on the SetupResult shape, not just the function
return / no-exception path.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_declaration_with_pinned_profile(
    *,
    profile: str,
    ibounce_port: int = 21567,
) -> dict[str, Any]:
    """Declaration that pins ibounce to the given profile name."""
    return {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "discovery",
                    "port": ibounce_port,
                    "profile": profile,
                },
            },
        }
    }


@pytest.fixture
def isolated_profiles(tmp_path: pathlib.Path, monkeypatch):
    """Point PROFILES_PATH_ENV at an empty tmp dir so each test
    controls the profiles.yaml surface independently. Without this,
    tests inherit whatever's in ~/.iam-jit/bouncer/profiles.yaml on
    the dev machine + can flake."""
    profiles_path = tmp_path / "profiles.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(profiles_path))
    return profiles_path


def _stopped_posture() -> dict[str, Any]:
    """Posture snapshot indicating NO bouncers are running, so the
    setup code path reaches the profile-presence check (the path
    short-circuits when a bouncer is already running per
    [[creates-never-mutates]] — that's a different branch)."""
    return {
        "bouncers": {
            "ibounce": {"running": False, "port": 8767},
            "kbounce": {"running": False, "port": 8766},
            "dbounce": {"running": False, "port": 5433},
            "gbounce": {"running": False, "port": 8080},
        }
    }


# ---------------------------------------------------------------------------
# Test 1 — nonexistent profile produces a clear, actionable warning
# ---------------------------------------------------------------------------


def test_missing_profile_emits_actionable_warning(isolated_profiles):
    """The whole #560 bug surface: declaring `profile: this-doesnt-exist`
    MUST produce a warning that names the missing profile + lists
    what's available so the operator can fix it."""
    from iam_jit.ambient_config import plan_declaration

    # Write a profiles.yaml that has SOME profiles but NOT the one
    # we're about to declare. (If the file were absent,
    # `load_profiles` falls back to DEFAULT_PROFILES which contains
    # full-user + safe-default — still valid surface for the test.)
    isolated_profiles.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "default"},
            "safe-default": {"description": "readonly-minus"},
        }
    }))

    decl = _make_declaration_with_pinned_profile(
        profile="totally-made-up-profile",
    )
    result = plan_declaration(
        decl, source="<test-missing-profile>", posture=_stopped_posture(),
        env={},
    )
    payload = result.as_dict()

    warnings = payload.get("warnings") or []
    # Find the warning that mentions the pinned profile name.
    matching = [
        w for w in warnings
        if "totally-made-up-profile" in w and "ibounce" in w
    ]
    assert matching, (
        f"declaring a nonexistent profile MUST emit a warning naming "
        f"the missing profile + bouncer. All warnings: {warnings!r}"
    )
    # Operator-actionable: the warning must list the available
    # profiles so the operator can pick a real one.
    joined = matching[0]
    assert "available" in joined.lower() or "profiles.yaml" in joined, (
        f"warning doesn't tell the operator where to look for valid "
        f"profile names; not actionable: {joined!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — valid profile name produces NO warning + records the install
# ---------------------------------------------------------------------------


def test_present_profile_emits_no_warning_and_records_install(isolated_profiles):
    """Declaring a profile that IS in profiles.yaml should NOT warn —
    instead, it should record the install on `profiles_installed`."""
    from iam_jit.ambient_config import plan_declaration

    isolated_profiles.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "default"},
            "safe-default": {"description": "readonly-minus"},
        }
    }))

    decl = _make_declaration_with_pinned_profile(profile="safe-default")
    result = plan_declaration(
        decl, source="<test-present-profile>",
        posture=_stopped_posture(), env={},
    )
    payload = result.as_dict()

    warnings = payload.get("warnings") or []
    # No warning should mention safe-default as missing.
    missing_refs = [
        w for w in warnings
        if "safe-default" in w and (
            "not in profiles.yaml" in w or "missing" in w.lower()
        )
    ]
    assert not missing_refs, (
        f"valid profile 'safe-default' incorrectly flagged as missing: "
        f"{missing_refs!r}"
    )

    # And `profiles_installed` should record the declared source.
    installed = payload.get("profiles_installed") or []
    matching = [
        i for i in installed
        if i.get("profile_name") == "safe-default"
        and i.get("bouncer") == "ibounce"
        and i.get("source") == "declared"
    ]
    assert matching, (
        f"valid profile install not recorded in profiles_installed: "
        f"{installed!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — load_profiles failure surfaces a warning (no silent swallow)
# ---------------------------------------------------------------------------


def test_load_profiles_value_error_surfaces_as_warning(
    isolated_profiles, monkeypatch
):
    """Per #560 fix: ValueError from load_profiles (malformed YAML)
    must surface as a user-visible warning, NOT silently disappear.
    The pre-fix bare `except Exception: pass` would have swallowed
    this entirely."""
    from iam_jit.ambient_config import plan_declaration

    # Malformed profiles.yaml — `profiles:` value is a string instead
    # of a dict, which load_profiles raises ValueError for.
    isolated_profiles.write_text("profiles: not-a-mapping\n")

    decl = _make_declaration_with_pinned_profile(profile="some-profile")
    result = plan_declaration(
        decl, source="<test-malformed-yaml>",
        posture=_stopped_posture(), env={},
    )
    payload = result.as_dict()

    warnings = payload.get("warnings") or []
    matching = [
        w for w in warnings
        if "profile presence check failed" in w
        and "some-profile" in w
    ]
    assert matching, (
        f"malformed profiles.yaml should surface a 'profile presence "
        f"check failed' warning; instead got: {warnings!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — regression: AttributeError no longer hidden by bare except
# ---------------------------------------------------------------------------


def test_load_profiles_returning_unexpected_type_propagates(
    isolated_profiles, monkeypatch
):
    """Regression-pin for the exact #560 shape: if load_profiles
    ever returned something that triggered AttributeError during
    set construction, the OLD code swallowed it (bare except). The
    NEW code uses `set(profiles)` which CANNOT raise AttributeError
    on a dict, AND the except clause is narrowed to
    (FileNotFoundError, ValueError, OSError) — so an unexpected
    error class would propagate instead of hiding.

    This test injects a load_profiles that raises a class NOT in
    our except list and verifies the exception propagates rather
    than being silently swallowed. If a future refactor reverts the
    except clause to bare `except Exception`, this test fires.
    """
    from iam_jit.ambient_config import plan_declaration
    from iam_jit.bouncer import profiles as profiles_mod

    sentinel = RuntimeError("sentinel — must not be swallowed")

    def _boom(*args, **kwargs):
        raise sentinel

    monkeypatch.setattr(profiles_mod, "load_profiles", _boom)

    decl = _make_declaration_with_pinned_profile(profile="x")
    with pytest.raises(RuntimeError, match="sentinel"):
        plan_declaration(
            decl, source="<test-attribute-error-propagation>",
            posture=_stopped_posture(), env={},
        )
