"""#401 / §A47 — improve-profile pipeline tests.

Covers:
  * diff below threshold → auto-installs
  * diff above threshold → holds pending
  * admin_action audit event emitted
  * managed posture → refuses
  * returns structured summary
  * no change → no-op
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from iam_jit.improve import ImproveProfileResult, improve_profile
from iam_jit.improve.pipeline import _change_size, _compute_diff


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the profiles loader at a temp file with a tiny baseline
    profile so the diff computation has something to chew on."""
    p = tmp_path / "profiles.yaml"
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "test active profile",
                "allow_rules": [
                    {"pattern": "ec2:DescribeInstances", "note": "pre-existing"},
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
    """Point the pending-approval queue at a temp file so we never
    write to the operator's real ~/.iam-jit dir."""
    from iam_jit.profile_allow import operations as ops
    p = tmp_path / "pending.jsonl"
    monkeypatch.setenv(ops.PENDING_APPROVALS_PATH_ENV, str(p))
    return p


@pytest.fixture
def stub_generator(monkeypatch: pytest.MonkeyPatch):
    """Stub generate_from_audit so tests don't make LLM calls.

    Returns a closure the test calls with `(bouncer, allows, scope=None)`
    to wire up the generator output for that test.
    """
    def _install(
        bouncer: str = "ibounce",
        allows: list[dict] | None = None,
        scope: dict[str, list[str]] | None = None,
    ):
        from iam_jit.llm.profile_generator import (
            GeneratedProfile,
            ProfileResult,
        )
        body: dict[str, Any] = {
            "allows": allows or [],
            "denies": [],
        }
        for k, v in (scope or {}).items():
            body[k] = v
        profile_yaml = yaml.safe_dump({
            "profiles": {
                f"improve-{bouncer}-test": body,
            }
        })

        def _fake_generate(*args, **kwargs):
            return ProfileResult(
                bundle=(
                    GeneratedProfile(
                        bouncer=bouncer,
                        profile_yaml=profile_yaml,
                        events_analyzed=10,
                        resources_observed=("arn:aws:s3:::cache",),
                        flagged_for_review=(),
                        skipped_list=(),
                    ),
                ),
                index_yaml="",
                explanation="stub generator",
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

    return _install


@pytest.fixture
def stub_audit_events(monkeypatch: pytest.MonkeyPatch):
    """Stub the audit fetcher to return a fixed set of events."""
    def _install(events: list[dict]) -> None:
        monkeypatch.setattr(
            "iam_jit.improve.pipeline._fetch_events_for_bouncer",
            lambda **_: list(events),
        )
    return _install


@pytest.fixture
def quiet_fanout(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub the profile-reload fan-out so add_profile_allow_rule
    doesn't try to hit real bouncers in tests."""
    from iam_jit.profile_allow.fanout import ProfileReloadResult
    calls: list[str] = []

    def _fake_fanout(affected, *, overrides=None, timeout=5.0):
        out = []
        for b in affected:
            calls.append(b)
            out.append(ProfileReloadResult(
                bouncer=b, url="http://stub",
                reloaded=True, status_code=200, error=None,
            ))
        return out
    monkeypatch.setattr(
        "iam_jit.profile_allow.operations.fanout_profile_reload",
        _fake_fanout,
    )
    return calls


# ---------------------------------------------------------------------------
# Core behaviors
# ---------------------------------------------------------------------------


def test_improve_profile_returns_structured_summary(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """Always returns ImproveProfileResult dataclass with full structure."""
    stub_audit_events([{"_bouncer": "ibounce", "api": {"operation": "GetObject"}}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
        ],
    )
    result = improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        apply=True,
        profile_name="active-test",
    )
    assert isinstance(result, ImproveProfileResult)
    d = result.as_dict()
    assert "status" in d
    assert "rules_added" in d
    assert "rules_removed" in d
    assert "scope_changes" in d
    assert "change_size" in d
    assert "requires_approval" in d
    assert "audit_event_ids" in d


def test_improve_profile_diff_below_threshold_auto_installs(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When change_size < threshold AND auto_install=True, the rule is
    installed via the existing #345 path; status='auto_installed'."""
    # Active profile has 100 pre-existing rules; we add 5. Should be small.
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "many rules",
                "allow_rules": [
                    {"pattern": f"ec2:Action{i}"} for i in range(100)
                ],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
            {"target": "arn:aws:s3:::cache", "actions": ["s3:ListBucket"]},
        ],
    )
    result = improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        auto_install=True,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "auto_installed", result.explanation
    assert result.change_size < 0.30
    assert result.requires_approval is False
    # The profile YAML should now contain the new rules.
    body = yaml.safe_load(p.read_text())
    new_patterns = {
        r["pattern"]
        for r in body["profiles"]["active-test"]["allow_rules"]
    }
    assert "s3:GetObject" in new_patterns
    assert "s3:ListBucket" in new_patterns


def test_improve_profile_diff_above_threshold_holds_pending(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """When change_size >= threshold, entries are queued for operator
    approval; status='pending_approval'."""
    p = tmp_profiles
    # Existing has 0 rules; adding 5 → size=1.0 (>> 0.30).
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "empty",
                "allow_rules": [],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": f"arn:aws:s3:::b-{i}", "actions": ["s3:GetObject"]}
            for i in range(5)
        ],
    )
    result = improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        auto_install=True,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "pending_approval", result.explanation
    assert result.change_size >= 0.30
    assert result.requires_approval is True
    assert len(result.pending_entry_ids) >= 1
    # The pending queue file MUST have entries.
    assert tmp_pending_queue.exists()
    pending_lines = [
        line for line in tmp_pending_queue.read_text().splitlines() if line
    ]
    assert len(pending_lines) >= 1


def test_improve_profile_emits_admin_action_audit(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When auto-installing, an admin_action audit event id is emitted
    (synthesized when out-of-process). The result.audit_event_ids list
    is populated."""
    captured = []

    def _fake_emit(emit, **kwargs):
        captured.append(kwargs)
        return None

    monkeypatch.setattr(
        "iam_jit.bouncer.audit_export.admin_action.emit_admin_action_direct",
        _fake_emit,
    )
    # Pre-populate with many rules so the new ones come in below threshold.
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "many rules",
                "allow_rules": [
                    {"pattern": f"ec2:Action{i}"} for i in range(100)
                ],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[{"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]}],
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.30,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "auto_installed"
    assert len(result.audit_event_ids) >= 1
    assert any(c.get("kind") for c in captured)


def test_improve_profile_respects_managed_posture_refuses_to_run() -> None:
    """posture=managed → status=managed_posture_refused, clear error."""
    result = improve_profile(
        bouncer="ibounce",
        posture="managed",
        apply=True,
    )
    assert result.status == "managed_posture_refused"
    assert "managed" in result.explanation.lower()
    assert result.requires_approval is False
    assert result.rules_added == 0
    assert result.audit_event_ids == []


def test_improve_profile_no_change_returns_no_op(
    tmp_profiles: Path,
    stub_audit_events,
) -> None:
    """Empty audit events → status='no_change' honestly reported."""
    stub_audit_events([])
    result = improve_profile(
        bouncer="ibounce",
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "no_change"
    assert result.rules_added == 0


def test_improve_profile_dry_run_does_not_mutate(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """apply=False returns dry_run with proposed allows; no profile or
    queue mutation."""
    p = tmp_profiles
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[{"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]}],
    )
    snapshot_before = p.read_text()
    result = improve_profile(
        bouncer="ibounce",
        apply=False,
        profile_name="active-test",
    )
    assert result.status == "dry_run"
    assert len(result.proposed_allows) >= 1
    assert p.read_text() == snapshot_before  # no mutation
    # Pending queue should still be empty (dry-run never enqueues).
    if tmp_pending_queue.exists():
        assert tmp_pending_queue.read_text().strip() == ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_compute_diff_correctly_identifies_added_removed() -> None:
    """The diff helper returns (added, removed, scope_changes)."""
    class _FakeRule:
        def __init__(self, pattern, arn_scope=None):
            self.pattern = pattern
            self.arn_scope = arn_scope

    class _FakeProfile:
        allow_rules = (_FakeRule("ec2:Describe*"),)
        only_account_ids = ("111122223333",)
        only_regions = ()
        only_clusters = ()
        only_namespaces = ()
        only_hosts = ()
        only_databases = ()

    proposed = {
        "allows": [
            {"target": "*", "actions": ["s3:GetObject"]},
            {"target": "*", "actions": ["ec2:Describe*"]},  # already exists
        ],
        "only_account_ids": ["111122223333", "999988887777"],
        "only_regions": ["us-east-1"],
    }
    added, removed, scope = _compute_diff(
        current_profile=_FakeProfile(),
        proposed=proposed,
    )
    assert ("s3:GetObject", None) in added or ("s3:GetObject", "*") in added
    # ec2:Describe* exists in current; should NOT be removed (it's in
    # the proposed set too, so neither added nor removed).
    assert all("ec2:Describe*" != a for a, _ in added)
    assert any("only_account_ids: added 999988887777" in s for s in scope)
    assert any("only_regions: added us-east-1" in s for s in scope)


# ---------------------------------------------------------------------------
# #451 (§A47b) — pending-queue + JSONL writing for scope-only diffs
# ---------------------------------------------------------------------------


def test_improve_pending_queue_writes_jsonl_when_threshold_exceeded(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """Above-threshold runs MUST create the JSONL file + append entries.

    Per #451 (§A47b): explanation references the JSONL path, so the
    file must exist when status='pending_approval'."""
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "empty",
                "allow_rules": [],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
        ],
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.10,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "pending_approval"
    assert tmp_pending_queue.exists()
    contents = tmp_pending_queue.read_text().strip().splitlines()
    assert len(contents) >= 1


def test_improve_pending_entry_ids_populated_in_response(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """Each enqueued entry's id MUST surface in pending_entry_ids[]."""
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "empty",
                "allow_rules": [],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
        ],
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.10,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "pending_approval"
    assert len(result.pending_entry_ids) >= 1
    for pid in result.pending_entry_ids:
        assert pid.startswith("pa_")


def test_improve_pending_jsonl_appends_not_overwrites(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """A second pending run MUST append, not truncate — JSONL is a
    forensic record."""
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "empty",
                "allow_rules": [],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[{"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]}],
    )
    improve_profile(
        bouncer="ibounce",
        threshold=0.10,
        apply=True,
        profile_name="active-test",
    )
    lines_after_first = tmp_pending_queue.read_text().splitlines()
    # Drive a second pending cycle (new generator output).
    stub_generator(
        bouncer="ibounce",
        allows=[{"target": "arn:aws:s3:::other", "actions": ["s3:GetObject"]}],
    )
    improve_profile(
        bouncer="ibounce",
        threshold=0.10,
        apply=True,
        profile_name="active-test",
    )
    lines_after_second = tmp_pending_queue.read_text().splitlines()
    assert len(lines_after_second) > len(lines_after_first), (
        "JSONL must append; second cycle truncated the file"
    )


def test_improve_scope_only_diff_routes_through_queue(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """Scope-only diff (no new allows) MUST also create JSONL entries
    + populate pending_entry_ids, NOT silently no-op."""
    p = tmp_profiles
    # Pre-existing has many allow rules so a single scope-change is
    # below threshold (size = 0.5 / (10 + 0) = 0.05).
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "scope-floor candidate",
                "allow_rules": [
                    {"pattern": f"ec2:Action{i}"} for i in range(10)
                ] + [
                    {"pattern": "s3:GetObject", "arn_scope": "arn:aws:s3:::cache"},
                ],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    # Generator: same allow rule already present, but scope-floor narrower.
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
        ] + [
            {"target": "*", "actions": [f"ec2:Action{i}"]} for i in range(10)
        ],
        scope={"only_account_ids": ["111122223333"]},
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.30,
        apply=True,
        profile_name="active-test",
    )
    # Per #452 fix: scope-only diff with no allow adds is its own status.
    assert result.status == "scope_only_change", (
        f"expected scope_only_change got {result.status}: {result.explanation}"
    )
    assert result.rules_added == 0
    assert len(result.scope_changes) >= 1
    # Per #451 fix: pending_entry_ids MUST be populated + JSONL exists.
    assert len(result.pending_entry_ids) >= 1
    assert tmp_pending_queue.exists()
    entries = [
        json.loads(line) for line in tmp_pending_queue.read_text().splitlines()
        if line.strip()
    ]
    assert any(e.get("kind") == "scope_change" for e in entries)


# ---------------------------------------------------------------------------
# #452 (§A47c) — honest status reporting
# ---------------------------------------------------------------------------


def test_improve_status_no_change_when_no_diff(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """Zero adds + zero removals + zero scope changes → status='no_change'."""
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "fully covered",
                "allow_rules": [
                    {"pattern": "s3:GetObject", "arn_scope": "arn:aws:s3:::cache"},
                ],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
        ],
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.30,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "no_change"
    assert result.rules_added == 0
    assert result.scope_changes == []


def test_improve_status_scope_only_change_when_only_scope_diff(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """Scope-only diff (no allow adds) → status='scope_only_change',
    NOT 'auto_installed' (per #452 honesty fix)."""
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "many rules",
                "allow_rules": [
                    {"pattern": f"ec2:Action{i}"} for i in range(20)
                ],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "*", "actions": [f"ec2:Action{i}"]} for i in range(20)
        ],
        scope={"only_regions": ["us-east-1"]},
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.30,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "scope_only_change"
    assert result.rules_added == 0
    assert "auto-installed" not in result.explanation.lower()


def test_improve_status_auto_installed_only_when_rules_added(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """status='auto_installed' MUST require rules_added > 0 (per #452)."""
    # Many existing rules so the change-size is small.
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "many rules",
                "allow_rules": [
                    {"pattern": f"ec2:Action{i}"} for i in range(100)
                ],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
        ],
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.30,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "auto_installed"
    assert result.rules_added >= 1


def test_improve_explanation_matches_status_honestly(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """When rules_added=0 + status='scope_only_change' the explanation
    MUST NOT say 'auto-installed N rules'. Per
    [[ibounce-honest-positioning]]."""
    p = tmp_profiles
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "many rules",
                "allow_rules": [
                    {"pattern": f"ec2:Action{i}"} for i in range(20)
                ],
            },
        },
    }))
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "*", "actions": [f"ec2:Action{i}"]} for i in range(20)
        ],
        scope={"only_account_ids": ["111122223333"]},
    )
    result = improve_profile(
        bouncer="ibounce",
        threshold=0.30,
        apply=True,
        profile_name="active-test",
    )
    assert result.status == "scope_only_change"
    expl = result.explanation.lower()
    assert "auto-installed" not in expl
    assert "scope-only" in expl or "scope" in expl


def test_change_size_normalizes_appropriately() -> None:
    """Empty current + 5 adds → size 1.0 (operator approves first
    baseline); 100 current + 5 adds → small. Removals don't drive size
    because [[creates-never-mutates]] never removes — only flags."""
    assert _change_size(added=5, removed=0, scope_changes=0, current_count=0) == 1.0
    assert _change_size(added=5, removed=0, scope_changes=0, current_count=100) < 0.1
    # 50 removals shouldn't push size above threshold for the same
    # established profile.
    assert _change_size(added=5, removed=50, scope_changes=0, current_count=100) < 0.1
    # All zeros → 0.0
    assert _change_size(added=0, removed=0, scope_changes=0, current_count=10) == 0.0
