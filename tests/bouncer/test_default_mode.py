"""Unit tests for `ProxyConfig.default_mode` — task #343 / §A24.

Purpose: lock in the truth table of the discovery-vs-profile mode
selector that the bouncer surfaces for cross-product symmetry +
agent introspection. The 38.5% / 69.2% / 84.6% role-effectiveness
hit-rate numbers in the launch positioning assume the bouncer
defaults to DISCOVERY mode; a regression flipping the property
silently would invalidate those published claims.

Per `[[discovery-first-default]]` (2026-05-22):

  - `active_profile=None` → "discovery"
  - `active_profile.name in {"", "full-user", "none"}` → "discovery"
    (full-user is the post-pivot default; `none` is the v1.0
    backward-compat alias for it; "" handles the edge case of an
    unnamed profile being stuck on the field)
  - `active_profile.name=<anything else>` → "profile"

These tests exercise the actual property (no mocking the return
value) per `[[scorer-is-ground-truth]]`.
"""

from __future__ import annotations

import pytest

from iam_jit.bouncer.profiles import Profile
from iam_jit.bouncer.proxy import ProxyConfig


# ---------------------------------------------------------------------------
# Per-case unit tests — narrow + readable
# ---------------------------------------------------------------------------


def test_default_mode_returns_discovery_when_no_profile_active():
    """active_profile=None → "discovery". The canonical pre-launch
    default per [[discovery-first-default]]: no profile selected =
    observe + audit + pass-through."""
    config = ProxyConfig(active_profile=None)
    assert config.default_mode == "discovery"


def test_default_mode_returns_discovery_when_default_full_user_profile_active():
    """active_profile.name="full-user" → "discovery". The post-pivot
    default named-profile is `full-user` (a no-deny pass-through
    shape); selecting it should NOT flip the bouncer into "profile"
    mode because it is functionally indistinguishable from no
    profile at all. Load-bearing: the canonical default must round-
    trip through the property as "discovery"."""
    profile = Profile(name="full-user")
    config = ProxyConfig(active_profile=profile)
    assert config.default_mode == "discovery"


def test_default_mode_returns_profile_when_named_profile_active():
    """active_profile.name="readonly-admin-minus" → "profile". Any
    operator-selected named profile (other than the
    discovery-equivalent set) flips the bouncer into profile mode —
    the pre-pivot behavior, now opt-in."""
    profile = Profile(name="readonly-admin-minus")
    config = ProxyConfig(active_profile=profile)
    assert config.default_mode == "profile"


def test_default_mode_returns_profile_when_named_profile_via_CLI():
    """When the operator passes `--profile safe-default` on the CLI,
    the resolved Profile flows into ProxyConfig.active_profile. The
    property must reflect that as "profile" so introspection (e.g.
    the `bouncer_active_mode` MCP tool) reports correctly. This
    mirrors the actual CLI codepath (`bouncer_cli.py` --profile
    flag → resolve_active_profile → ProxyConfig(active_profile=...))
    without spinning up the CLI."""
    profile = Profile(name="safe-default")
    config = ProxyConfig(active_profile=profile)
    assert config.default_mode == "profile"


def test_default_mode_returns_discovery_for_none_alias():
    """active_profile.name="none" → "discovery". `none` is the v1.0
    backward-compat alias for `full-user` (see
    DEPRECATED_PROFILE_ALIASES in profiles.py). The property
    treats it the same as `full-user` so deployments that haven't
    migrated off the alias still report the canonical mode."""
    profile = Profile(name="none")
    config = ProxyConfig(active_profile=profile)
    assert config.default_mode == "discovery"


def test_default_mode_returns_discovery_for_empty_profile_name():
    """active_profile.name="" → "discovery". Defensive: an unnamed
    profile stuck on the field shouldn't be misread as a user-
    selected named profile. Per the docstring at proxy.py L1017."""
    profile = Profile(name="")
    config = ProxyConfig(active_profile=profile)
    assert config.default_mode == "discovery"


# ---------------------------------------------------------------------------
# Truth-table parametrize — lock in the matrix in one place
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile_name,expected_mode",
    [
        # Discovery-equivalent: no profile, default profile, alias
        (None, "discovery"),  # i.e. active_profile=None
        ("", "discovery"),
        ("full-user", "discovery"),
        ("none", "discovery"),
        # Named profiles → "profile" mode
        ("safe-default", "profile"),
        ("readonly-admin-minus", "profile"),
        ("strict-admin", "profile"),
        ("staging-work", "profile"),
        ("data-team", "profile"),
    ],
)
def test_default_mode_truth_table_via_parametrize(profile_name, expected_mode):
    """Table-driven coverage of the discovery-vs-profile selector
    matrix. A row added here is a single line of new coverage; a
    regression breaking any row fails one test rather than masking
    the matrix in a single big assertion. The `profile_name=None`
    row models `active_profile=None` (no Profile object at all);
    every other row constructs a real Profile."""
    if profile_name is None:
        active_profile = None
    else:
        active_profile = Profile(name=profile_name)
    config = ProxyConfig(active_profile=active_profile)
    assert config.default_mode == expected_mode, (
        f"profile_name={profile_name!r} expected {expected_mode!r}; "
        f"got {config.default_mode!r}"
    )
