"""Tests for `ibounce profile doctor` (task #321 / KNOWN-CAVEATS §A19).

Cross-product symmetric with the Go test suites in
dbounce/internal/profile/doctor_test.go and
kbouncer/internal/profile/doctor_test.go.

Verifies the contract:

- Fresh profile → silent (no warning, no startup banner).
- Missing safety-floor field → warning + startup banner with §A19 ref.
- Missing convenience field → silent at startup, visible in `doctor`.
- --apply merges additively (operator-customized values preserved).
- --apply writes a timestamped backup before mutating profiles.yaml.
- --acknowledge silences the warning until a new shipped-defaults
  version bumps the stamp.
"""

from __future__ import annotations

import dataclasses
import datetime
import pathlib

import pytest
import yaml

from iam_jit.bouncer import profile_doctor
from iam_jit.bouncer.profiles import DEFAULT_PROFILES


def _seed_fresh_profile(tmp_path: pathlib.Path) -> pathlib.Path:
    """Write the embedded DEFAULT_PROFILES to a temp file (mirrors what
    `ibounce profile install-defaults` does on first install)."""
    path = tmp_path / "profiles.yaml"
    path.write_text(yaml.safe_dump({"profiles": DEFAULT_PROFILES}, sort_keys=False))
    return path


def _strip_field(path: pathlib.Path, profile_name: str, field: str) -> None:
    data = yaml.safe_load(path.read_text())
    body = data["profiles"][profile_name]
    body.pop(field, None)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    """Each test uses its own profiles.yaml location via
    IAM_JIT_BOUNCER_PROFILES_FILE so the suite never touches
    ~/.iam-jit/."""
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_PROFILES_FILE",
        str(tmp_path / "profiles.yaml"),
    )
    yield


def test_doctor_fresh_profile_no_warnings(tmp_path: pathlib.Path) -> None:
    path = _seed_fresh_profile(tmp_path)
    rep = profile_doctor.check(path)
    assert rep.missing_fields == ()
    assert not rep.has_safety_floor_gap()
    assert profile_doctor.startup_banner_line(path) == ""


def test_doctor_missing_safety_floor_warns_loudly(tmp_path: pathlib.Path) -> None:
    path = _seed_fresh_profile(tmp_path)
    _strip_field(path, "safe-default", "allow_baseline")

    rep = profile_doctor.check(path)
    matching = [g for g in rep.missing_fields
                if g.profile_name == "safe-default" and g.field == "allow_baseline"]
    assert len(matching) == 1, f"expected allow_baseline in missing list; got {rep.missing_fields}"
    gap = matching[0]
    assert gap.category is profile_doctor.FieldCategory.SAFETY_FLOOR
    assert "policy_sentry" in gap.why_matters
    assert rep.has_safety_floor_gap()

    line = profile_doctor.startup_banner_line(path)
    assert line, "expected startup banner to fire on safety-floor gap"
    assert "§A19" in line
    assert "ibounce profile doctor" in line


def test_doctor_missing_convenience_no_startup_warn_but_shows_in_doctor(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    # Inject a temporary CONVENIENCE catalog entry (no real convenience
    # entries ship in v1.0; this enforces the contract for when future
    # ones land).
    extra = profile_doctor.FieldGap(
        profile_name="safe-default",
        field="_test_convenience_field",
        category=profile_doctor.FieldCategory.CONVENIENCE,
        why_matters="test-only convenience field",
        added_in="test fixture",
        default_value="test",
    )
    monkeypatch.setattr(
        profile_doctor,
        "SHIPPED_DEFAULTS_CATALOG",
        (extra,) + profile_doctor.SHIPPED_DEFAULTS_CATALOG,
    )

    path = _seed_fresh_profile(tmp_path)
    rep = profile_doctor.check(path)

    categories = {g.category for g in rep.missing_fields}
    assert profile_doctor.FieldCategory.CONVENIENCE in categories
    assert profile_doctor.FieldCategory.SAFETY_FLOOR not in categories
    assert not rep.has_safety_floor_gap()
    assert profile_doctor.startup_banner_line(path) == ""

    rendered = profile_doctor.format_report(rep)
    assert "_test_convenience_field" in rendered


def test_doctor_apply_merges_additively(tmp_path: pathlib.Path) -> None:
    path = _seed_fresh_profile(tmp_path)
    _strip_field(path, "safe-default", "allow_baseline")

    # Operator-customized field that --apply MUST NOT touch.
    data = yaml.safe_load(path.read_text())
    data["profiles"]["safe-default"]["operator_custom_field"] = "preserved-value"
    path.write_text(yaml.safe_dump(data, sort_keys=False))

    now = datetime.datetime(2026, 5, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)
    result = profile_doctor.apply(path, now=now)
    assert len(result.applied_fields) >= 1

    merged = yaml.safe_load(path.read_text())
    body = merged["profiles"]["safe-default"]
    assert body["allow_baseline"] == "aws_managed_readonly_access"
    assert body["operator_custom_field"] == "preserved-value", \
        "operator-customized field was lost during --apply"

    # Post-apply, doctor should report current.
    rep = profile_doctor.check(path)
    assert not rep.has_safety_floor_gap()


def test_doctor_apply_backs_up(tmp_path: pathlib.Path) -> None:
    path = _seed_fresh_profile(tmp_path)
    _strip_field(path, "safe-default", "allow_baseline")

    prior_bytes = path.read_bytes()
    now = datetime.datetime(2026, 5, 22, 12, 34, 56, tzinfo=datetime.timezone.utc)
    result = profile_doctor.apply(path, now=now)

    assert result.backup_path.endswith(".bak-20260522-123456"), \
        f"backup path missing UTC timestamp suffix; got {result.backup_path!r}"
    backup_bytes = pathlib.Path(result.backup_path).read_bytes()
    assert backup_bytes == prior_bytes, "backup contents differ from prior state"


def test_doctor_acknowledge_silences_until_new_version(
    tmp_path: pathlib.Path,
) -> None:
    path = _seed_fresh_profile(tmp_path)
    _strip_field(path, "safe-default", "allow_baseline")
    assert profile_doctor.startup_banner_line(path) != "", "pre-ack: banner should fire"

    ack_path = profile_doctor.acknowledge(path)
    assert ack_path.exists()
    assert profile_doctor.startup_banner_line(path) == "", \
        "post-ack: banner should be silent"

    # Simulate a version bump.
    ack_path.write_text("OLDER-VERSION-STAMP\n")
    assert profile_doctor.startup_banner_line(path) != "", \
        "after version-bump simulation, banner should re-arm"


def test_doctor_catalog_covers_defaults() -> None:
    """Defensive: every SHIPPED_DEFAULTS_CATALOG entry must reference a
    profile that exists in DEFAULT_PROFILES. A typo here would silently
    make the doctor skip the field (check() returns no gap when the
    profile is absent)."""
    for gap in profile_doctor.SHIPPED_DEFAULTS_CATALOG:
        assert gap.profile_name in DEFAULT_PROFILES, \
            f"catalog references profile {gap.profile_name!r} absent from DEFAULT_PROFILES"
