"""State-verification tests for GH #5 + GH #6 — load_profiles() merge
semantics + per-test env isolation.

Per CONTRIBUTING.md: every test asserts observable state (dict keys +
Profile object identity), not just function return shape.

Context: #563 triage identified 26 test failures rooted in
``KeyError: 'safe-default'`` raised by ``load_profiles()`` when the
user's ``~/.iam-jit/bouncer/profiles.yaml`` lacks the default. Two
layers of fix:

- GH #5: bouncer-tests conftest.py forces a per-test profiles-file
  path so tests never read the developer's actual home dir file.
- GH #6: ``load_profiles()`` merges ``DEFAULT_PROFILES`` with the
  user file so a partial user file never crashes
  ``safe-default``-dependent callers in production.
"""

from __future__ import annotations

import os
import pathlib

import pytest
import yaml

from iam_jit.bouncer.profiles import (
    DEFAULT_PROFILES,
    Profile,
    load_profiles,
)


# ---------------------------------------------------------------------------
# GH #6 — merge semantics
# ---------------------------------------------------------------------------


def test_load_profiles_merges_default_profiles_when_user_file_missing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GH #6: with no user file on disk, every DEFAULT_PROFILES entry
    (including ``safe-default``) must be present in the returned map."""
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "absent.yaml"))
    profiles = load_profiles()
    for default_name in DEFAULT_PROFILES:
        assert default_name in profiles, (
            f"DEFAULT_PROFILES entry {default_name!r} missing from load_profiles() result"
        )
    # `safe-default` is the launch-blocker case from #563 triage.
    assert "safe-default" in profiles
    assert isinstance(profiles["safe-default"], Profile)


def test_load_profiles_merges_default_profiles_when_user_file_partial(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GH #6: user file with one custom profile (and nothing else) must
    return: user's custom profile + every DEFAULT_PROFILES entry +
    `full-user`. This is the founder's dogfood-file shape."""
    user_file = tmp_path / "profiles.yaml"
    user_file.write_text(yaml.safe_dump({
        "profiles": {
            "custom-one": {
                "description": "user-authored profile",
                "deny_keywords": ["secret"],
                "keyword_targets": ["arn"],
            },
        },
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(user_file))
    profiles = load_profiles()
    # User's profile present (didn't get dropped by merge)
    assert "custom-one" in profiles
    assert profiles["custom-one"].deny_keywords == ("secret",)
    # DEFAULT_PROFILES still present (didn't get overwritten away)
    assert "safe-default" in profiles
    assert "full-user" in profiles
    for default_name in DEFAULT_PROFILES:
        assert default_name in profiles


def test_load_profiles_user_wins_on_name_collision(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GH #6: when user file defines ``safe-default``, the user's version
    must win — DEFAULT_PROFILES['safe-default'] is the floor, not the
    ceiling. User intent overrides defaults."""
    user_file = tmp_path / "profiles.yaml"
    user_file.write_text(yaml.safe_dump({
        "profiles": {
            "safe-default": {
                "description": "user-overridden safe-default",
                "deny_keywords": ["only-this-one-keyword"],
                "keyword_targets": ["arn"],
            },
        },
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(user_file))
    profiles = load_profiles()
    assert "safe-default" in profiles
    sd = profiles["safe-default"]
    # Observable state: the user's deny_keywords are present, NOT the
    # DEFAULT_PROFILES['safe-default'] shape.
    assert sd.deny_keywords == ("only-this-one-keyword",)
    assert sd.description == "user-overridden safe-default"


def test_load_profiles_empty_user_file_falls_back_to_defaults(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GH #6: empty YAML file (operator created the file but added no
    profiles) → all DEFAULT_PROFILES present. Not an error condition;
    the file just contributes nothing to the merge."""
    user_file = tmp_path / "profiles.yaml"
    user_file.write_text("")
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(user_file))
    profiles = load_profiles()
    assert "safe-default" in profiles
    assert "full-user" in profiles
    for default_name in DEFAULT_PROFILES:
        assert default_name in profiles


def test_load_profiles_malformed_user_file_raises_clearly(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Honest framing per [[ibounce-honest-positioning]]: malformed user
    YAML must raise ValueError, NOT silently fall back to DEFAULT_PROFILES.
    Silent degradation would mask operator misconfiguration."""
    user_file = tmp_path / "bad.yaml"
    user_file.write_text("profiles:\n  bad: [unclosed-list\n")
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(user_file))
    with pytest.raises(ValueError, match="not valid YAML"):
        load_profiles()


# ---------------------------------------------------------------------------
# GH #5 — env isolation
# ---------------------------------------------------------------------------


def test_conftest_isolates_profiles_file_per_test() -> None:
    """GH #5: the autouse fixture in tests/bouncer/conftest.py must set
    ``IAM_JIT_BOUNCER_PROFILES_FILE`` to a per-test tmpdir path, so no
    bouncer test can read the developer's ``~/.iam-jit/bouncer/profiles.yaml``.
    """
    env_value = os.environ.get("IAM_JIT_BOUNCER_PROFILES_FILE")
    assert env_value is not None, (
        "GH #5 autouse fixture failed — IAM_JIT_BOUNCER_PROFILES_FILE not set"
    )
    # The fixture writes to tmp_path which on macOS lives under /private/var.
    # Both forms are accepted (pytest's tmp_path varies by platform).
    assert "isolated_profiles.yaml" in env_value
    home_profiles = str(pathlib.Path.home() / ".iam-jit" / "bouncer" / "profiles.yaml")
    assert env_value != home_profiles, (
        "GH #5 fixture pointed at developer's actual home profiles file"
    )
