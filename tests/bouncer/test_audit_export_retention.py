"""Tests for #428 / §A67 — compliance retention tiering (retention.py).

Coverage matrix from the brief:
- test_retention_pci_defaults_correct
- test_retention_hipaa_defaults_correct
- test_retention_sox_defaults_correct
- test_retention_gdpr_pii_purge_after_hot_days
- test_retention_write_time_enforcement_not_query_time
- test_retention_tier_transitions_hot_warm_cold
- test_retention_purge_after_days_actually_deletes
- test_retention_composes_with_disk_pressure_mode
- test_retention_cold_tier_archives_to_s3
"""

from __future__ import annotations

import gzip
import json
import os
import pathlib
import time

import pytest

from iam_jit.bouncer.audit_export import (
    COLD_PREFIX,
    FRAMEWORK_CUSTOM,
    FRAMEWORK_GDPR,
    FRAMEWORK_HIPAA,
    FRAMEWORK_PCI,
    FRAMEWORK_SOX,
    PlannedTransition,
    REDACTION_PLACEHOLDER,
    RetentionPolicy,
    TIER_COLD,
    TIER_HOT,
    TIER_WARM,
    WARM_PREFIX,
    apply_retention,
    default_retention_policy,
    plan_retention,
    redact_event_pii,
    retention_policy_for_framework,
    retention_policy_from_declaration,
    rotation_purge_by_policy,
)


# ---------------------------------------------------------------------------
# Per-framework defaults
# ---------------------------------------------------------------------------


def test_retention_pci_defaults_correct():
    """PCI: cumulative ages — hot to 30d / warm to 120d / cold to
    365d / no purge. 1-year minimum satisfied via cold tier."""
    p = retention_policy_for_framework(FRAMEWORK_PCI)
    assert p.compliance == FRAMEWORK_PCI
    assert p.hot_days == 30
    assert p.warm_days == 120
    assert p.cold_days == 365
    assert p.purge_after_days is None  # no purge — keep indefinitely
    assert p.gdpr_pii_purge is False


def test_retention_hipaa_defaults_correct():
    """HIPAA: 6-year retention. hot to 30d / warm to 210d / cold to
    2190d / purge at 2190d (6 years)."""
    p = retention_policy_for_framework(FRAMEWORK_HIPAA)
    assert p.compliance == FRAMEWORK_HIPAA
    assert p.hot_days == 30
    assert p.warm_days == 210
    assert p.cold_days == 2190
    assert p.purge_after_days == 2190
    assert p.gdpr_pii_purge is False


def test_retention_sox_defaults_correct():
    """SOX: 7-year retention. hot to 30d / warm to 395d / cold to
    2555d / no purge (SOX has no upper bound)."""
    p = retention_policy_for_framework(FRAMEWORK_SOX)
    assert p.compliance == FRAMEWORK_SOX
    assert p.hot_days == 30
    assert p.warm_days == 395
    assert p.cold_days == 2555
    assert p.purge_after_days is None
    assert p.gdpr_pii_purge is False


def test_retention_gdpr_pii_purge_after_hot_days():
    """GDPR: PII purge defaults TRUE so write-time + tier transition
    scrubs PII out after the hot window."""
    p = retention_policy_for_framework(FRAMEWORK_GDPR)
    assert p.compliance == FRAMEWORK_GDPR
    assert p.gdpr_pii_purge is True


# ---------------------------------------------------------------------------
# Write-time enforcement (PII redaction)
# ---------------------------------------------------------------------------


def test_retention_write_time_enforcement_not_query_time():
    """Per the §A67 spec PII redaction MUST run at WRITE time, not
    query time. redact_event_pii mutates in place; we verify the
    credential-shaped strings are replaced before the event leaves
    the writer."""
    policy = retention_policy_for_framework(FRAMEWORK_GDPR)
    event = {
        "metadata": {"version": "1.1.0"},
        "unmapped": {
            "iam_jit": {
                "credentials": {
                    "access_key": "AKIAIOSFODNN7EXAMPLE",
                    "auth": "Bearer abc123.def456-xyz_789",
                    "user_email": "alice@example.com",
                },
            },
        },
    }
    redact_event_pii(event, policy)
    creds = event["unmapped"]["iam_jit"]["credentials"]
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(creds)
    assert "Bearer abc123" not in json.dumps(creds)
    assert "alice@example.com" not in json.dumps(creds)
    # Placeholders explicitly present.
    body = json.dumps(creds)
    assert REDACTION_PLACEHOLDER.format(kind="aws_access_key_id") in body
    assert REDACTION_PLACEHOLDER.format(kind="bearer_token") in body
    assert REDACTION_PLACEHOLDER.format(kind="email") in body


def test_retention_write_time_no_op_when_gdpr_disabled():
    """gdpr_pii_purge=False: redact_event_pii is a no-op."""
    policy = retention_policy_for_framework(FRAMEWORK_PCI)  # gdpr_pii_purge=False
    event = {
        "unmapped": {"iam_jit": {"key": "AKIAIOSFODNN7EXAMPLE"}}
    }
    redact_event_pii(event, policy)
    assert event["unmapped"]["iam_jit"]["key"] == "AKIAIOSFODNN7EXAMPLE"


# ---------------------------------------------------------------------------
# Tier transitions
# ---------------------------------------------------------------------------


def _make_archive(
    path: pathlib.Path,
    *,
    events: list[dict] | None = None,
    mtime_age_days: float = 0.0,
) -> pathlib.Path:
    """Write a rotated archive at ``path`` with the given mtime age."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt") as f:
        for e in events or [{"foo": "bar"}]:
            f.write(json.dumps(e) + "\n")
    if mtime_age_days > 0:
        mtime = time.time() - mtime_age_days * 86400.0
        os.utime(path, (mtime, mtime))
    return path


def test_retention_tier_transitions_hot_warm_cold(tmp_path):
    """Cumulative thresholds: a hot file aged > hot_days transitions
    to warm; a warm file aged > warm_days transitions to cold."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=10,
        warm_days=30,
        cold_days=100,
        purge_after_days=200,
        gdpr_pii_purge=False,
    )
    # Hot archive aged 15d (past hot threshold=10): expect hot→warm.
    hot_arch = _make_archive(
        tmp_path / "audit-2026-05-01-000000.jsonl.gz",
        mtime_age_days=15,
    )
    # Warm archive aged 40d (past warm threshold=30): expect warm→cold.
    warm_arch = _make_archive(
        tmp_path / "warm-2026-04-01-000000.jsonl.gz",
        mtime_age_days=40,
    )
    result = apply_retention(tmp_path, policy)
    # Hot→warm transition.
    hot_to_warm = [t for t in result.transitions if t.from_tier == TIER_HOT]
    assert len(hot_to_warm) == 1
    assert hot_to_warm[0].to_tier == TIER_WARM
    assert pathlib.Path(hot_to_warm[0].path).name.startswith(WARM_PREFIX)
    # Warm→cold transition.
    warm_to_cold = [t for t in result.transitions if t.from_tier == TIER_WARM]
    assert len(warm_to_cold) == 1
    assert warm_to_cold[0].to_tier == TIER_COLD
    assert pathlib.Path(warm_to_cold[0].path).name.startswith(COLD_PREFIX)


def test_retention_purge_after_days_actually_deletes(tmp_path):
    """An archive older than purge_after_days is destroyed."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=10,
        warm_days=20,
        cold_days=30,
        purge_after_days=60,
        gdpr_pii_purge=False,
    )
    # Cold archive aged 90d (past purge_after_days=60).
    cold = _make_archive(
        tmp_path / "cold-2026-01-01-000000.jsonl.gz",
        mtime_age_days=90,
    )
    assert cold.exists()
    result = apply_retention(tmp_path, policy)
    assert str(cold) in result.purged
    assert not cold.exists()


def test_retention_purge_never_destroys_within_window(tmp_path):
    """purge_after_days must be >= cold_days. A misconfigured policy
    that tries to purge while data is still in the cold window is
    rejected at construction time."""
    with pytest.raises(ValueError, match=">= cold_days"):
        retention_policy_for_framework(
            FRAMEWORK_CUSTOM,
            hot_days=10,
            warm_days=20,
            cold_days=30,
            purge_after_days=20,  # < cold_days
        )


def test_retention_composes_with_disk_pressure_mode(tmp_path):
    """The rotation_purge_by_policy helper returns the same lists
    that disk-pressure's archive-and-purge mode would feed off."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=1,
        warm_days=2,
        cold_days=3,
        purge_after_days=4,
        gdpr_pii_purge=False,
    )
    # Two cold archives — one past purge, one fresh.
    _make_archive(
        tmp_path / "cold-2026-05-15-000000.jsonl.gz",
        mtime_age_days=5,  # > purge_after_days=4
    )
    fresh = _make_archive(
        tmp_path / "audit-2026-05-23-000000.jsonl.gz",
        mtime_age_days=0,  # hot + fresh
    )
    transitioned, purged = rotation_purge_by_policy(tmp_path, policy)
    # The stale cold archive aged 5d > purge_after_days=4 → purged.
    assert len(purged) == 1
    assert fresh.exists()


def test_retention_cold_tier_archives_to_s3(tmp_path):
    """Cold-tier archives are returned in the cold_eligible list so
    the #317 S3 sink (or operator-driven `iam-jit logs ship-to`)
    can pick them up. This module never uploads directly."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=10,
        warm_days=20,
        cold_days=100,
        purge_after_days=None,
        gdpr_pii_purge=False,
    )
    # Cold-tier file already in cold; should be eligible for S3.
    cold_arch = _make_archive(
        tmp_path / "cold-2026-04-01-000000.jsonl.gz",
        mtime_age_days=50,
    )
    result = apply_retention(tmp_path, policy)
    assert str(cold_arch) in result.cold_eligible
    # And: a warm archive ready for warm→cold transition shows up
    # in cold_eligible AFTER transition.
    warm_arch = _make_archive(
        tmp_path / "warm-2026-03-01-000000.jsonl.gz",
        mtime_age_days=80,  # past hot+warm=30
    )
    result = apply_retention(tmp_path, policy)
    cold_paths = [pathlib.Path(p).name for p in result.cold_eligible]
    # The just-transitioned file is now cold-prefixed.
    assert any(n.startswith(COLD_PREFIX) for n in cold_paths)


def test_retention_policy_from_declaration_with_framework_default():
    """Declaration parsing reads `compliance: hipaa` + applies HIPAA
    defaults when individual fields are omitted."""
    p = retention_policy_from_declaration({"compliance": "hipaa"})
    assert p.compliance == FRAMEWORK_HIPAA
    assert p.warm_days == 210
    assert p.purge_after_days == 2190


def test_retention_policy_from_declaration_overrides_field():
    """Operator can override individual fields atop framework defaults."""
    p = retention_policy_from_declaration({
        "compliance": "hipaa",
        "hot_days": 60,
    })
    assert p.hot_days == 60
    # Untouched: HIPAA default warm_days.
    assert p.warm_days == 210


def test_retention_policy_from_declaration_empty_returns_default():
    """Empty / missing block returns the conservative PCI default."""
    p = retention_policy_from_declaration(None)
    assert p.compliance == FRAMEWORK_PCI
    p = retention_policy_from_declaration({})
    assert p.compliance == FRAMEWORK_PCI


def test_gdpr_pii_scrub_at_hot_to_warm_transition(tmp_path):
    """When policy.gdpr_pii_purge=True, hot→warm rename ALSO scrubs
    PII from the archive contents."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=5,
        warm_days=10,
        cold_days=15,
        purge_after_days=30,
        gdpr_pii_purge=True,
    )
    event = {"unmapped": {"iam_jit": {"key": "AKIAIOSFODNN7EXAMPLE"}}}
    arch = _make_archive(
        tmp_path / "audit-2026-05-10-000000.jsonl.gz",
        events=[event],
        mtime_age_days=10,  # > hot_days=5
    )
    apply_retention(tmp_path, policy)
    # Original hot file is gone; warm-prefixed file exists.
    assert not arch.exists()
    warm_files = list(tmp_path.glob("warm-*.jsonl.gz"))
    assert len(warm_files) == 1
    with gzip.open(warm_files[0], "rt") as f:
        scrubbed = json.loads(f.read())
    assert scrubbed["unmapped"]["iam_jit"]["key"] != "AKIAIOSFODNN7EXAMPLE"
    assert REDACTION_PLACEHOLDER.format(kind="aws_access_key_id") in scrubbed["unmapped"]["iam_jit"]["key"]


# ---------------------------------------------------------------------------
# #502 — dry-run plan_retention shows planned transitions per file
# ---------------------------------------------------------------------------


def test_plan_retention_dry_run_shows_all_transitions(tmp_path):
    """#502: plan_retention returns a PlannedTransition per file that
    reflects what apply_retention WOULD do without touching the
    filesystem. The 3-file fixture spans all three tier-transition
    scenarios so the table output covers every action label."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=10,
        warm_days=30,
        cold_days=100,
        purge_after_days=None,
        gdpr_pii_purge=False,
    )
    # File 1: fresh hot (age=5d, < hot_days=10) — no-op.
    fresh_hot = _make_archive(
        tmp_path / "audit-2026-05-20-000000.jsonl.gz",
        mtime_age_days=5,
    )
    # File 2: stale hot (age=15d, > hot_days=10) — compress-to-warm.
    stale_hot = _make_archive(
        tmp_path / "audit-2026-05-10-000000.jsonl.gz",
        mtime_age_days=15,
    )
    # File 3: warm archive (age=40d, > warm_days=30) — move-to-cold-storage.
    warm_arch = _make_archive(
        tmp_path / "warm-2026-04-10-000000.jsonl.gz",
        mtime_age_days=40,
    )

    planned = plan_retention(tmp_path, policy)

    # All 3 files should appear.
    assert len(planned) == 3
    by_name = {pathlib.Path(p.path).name: p for p in planned}

    fresh_name = fresh_hot.name
    stale_name = stale_hot.name
    warm_name = warm_arch.name

    assert fresh_name in by_name
    assert by_name[fresh_name].current_tier == TIER_HOT
    assert by_name[fresh_name].planned_tier == TIER_HOT
    assert by_name[fresh_name].action == "no-op"

    assert stale_name in by_name
    assert by_name[stale_name].current_tier == TIER_HOT
    assert by_name[stale_name].planned_tier == TIER_WARM
    assert by_name[stale_name].action == "compress-to-warm"

    assert warm_name in by_name
    assert by_name[warm_name].current_tier == TIER_WARM
    assert by_name[warm_name].planned_tier == TIER_COLD
    assert by_name[warm_name].action == "move-to-cold-storage"

    # Filesystem NOT mutated — originals still exist, no warm/cold files.
    assert fresh_hot.exists()
    assert stale_hot.exists()
    assert warm_arch.exists()
    assert not list(tmp_path.glob("cold-*.jsonl.gz"))


def test_plan_retention_dry_run_no_files_returns_empty(tmp_path):
    """plan_retention against an empty or non-archive dir returns []."""
    policy = retention_policy_for_framework(FRAMEWORK_PCI)
    # Put a non-archive file so dir isn't empty.
    (tmp_path / "audit.jsonl").write_text("active log\n")
    planned = plan_retention(tmp_path, policy)
    assert planned == []


def test_plan_retention_dry_run_purge_labeled(tmp_path):
    """Files past purge_after_days appear with action='purge' in the
    dry-run plan. The filesystem is still not touched."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=10,
        warm_days=20,
        cold_days=30,
        purge_after_days=60,
        gdpr_pii_purge=False,
    )
    cold_old = _make_archive(
        tmp_path / "cold-2026-01-01-000000.jsonl.gz",
        mtime_age_days=90,
    )
    planned = plan_retention(tmp_path, policy)
    assert len(planned) == 1
    assert planned[0].action == "purge"
    assert planned[0].planned_tier == "purge"
    # Filesystem NOT mutated.
    assert cold_old.exists()


# ---------------------------------------------------------------------------
# #503 — multi-pass hot→cold in a single apply_retention call
# ---------------------------------------------------------------------------


def test_apply_retention_single_pass_hot_to_cold(tmp_path):
    """#503: a hot file aged past warm_days (and into cold territory)
    reaches TIER_COLD in a single apply_retention call without an
    intermediate warm-tier rename step. Previously two calls were
    required (first hot→warm, then warm→cold)."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=10,
        warm_days=30,
        cold_days=100,
        purge_after_days=None,
        gdpr_pii_purge=False,
    )
    # Hot file aged 40d — past warm_days (30) so should land in cold
    # after a single apply call.
    hot_arch = _make_archive(
        tmp_path / "audit-2026-04-10-000000.jsonl.gz",
        mtime_age_days=40,
    )
    result = apply_retention(tmp_path, policy)

    # Should have exactly ONE transition: hot → cold (not hot → warm).
    assert len(result.transitions) == 1
    t = result.transitions[0]
    assert t.from_tier == TIER_HOT
    assert t.to_tier == TIER_COLD
    assert pathlib.Path(t.path).name.startswith(COLD_PREFIX)

    # Original hot file gone; cold-prefixed file exists.
    assert not hot_arch.exists()
    cold_files = list(tmp_path.glob("cold-*.jsonl.gz"))
    assert len(cold_files) == 1

    # The resulting cold file is in cold_eligible.
    assert str(cold_files[0]) in result.cold_eligible

    # No intermediate warm file created.
    warm_files = list(tmp_path.glob("warm-*.jsonl.gz"))
    assert len(warm_files) == 0


def test_apply_retention_single_pass_still_transitions_hot_to_warm_when_not_cold(
    tmp_path,
):
    """#503 regression guard: a hot file aged into warm (not past cold)
    still lands at warm (not cold) in a single pass."""
    policy = retention_policy_for_framework(
        FRAMEWORK_CUSTOM,
        hot_days=10,
        warm_days=60,
        cold_days=100,
        purge_after_days=None,
        gdpr_pii_purge=False,
    )
    # Hot file aged 20d — past hot_days (10) but NOT past warm_days (60).
    hot_arch = _make_archive(
        tmp_path / "audit-2026-05-05-000000.jsonl.gz",
        mtime_age_days=20,
    )
    result = apply_retention(tmp_path, policy)

    assert len(result.transitions) == 1
    t = result.transitions[0]
    assert t.from_tier == TIER_HOT
    assert t.to_tier == TIER_WARM
    assert pathlib.Path(t.path).name.startswith(WARM_PREFIX)
    assert not hot_arch.exists()
    assert list(tmp_path.glob("warm-*.jsonl.gz"))
    assert not list(tmp_path.glob("cold-*.jsonl.gz"))
