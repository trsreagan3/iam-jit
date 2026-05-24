"""MRR-2 F1 — partial-install honesty for improve_profile.

Closes the #448 shape on the ``iam_jit_improve_profile`` surface:
``status="auto_installed"`` may NEVER be returned when one or more
proposed rule adds failed. The pipeline now reports either:

  * ``auto_installed`` — every requested rule landed on disk
  * ``partial_install`` — some landed, some failed
  * ``no_install`` — every requested rule failed

Per ``docs/CONTRIBUTING.md`` state-verification convention:
every test below asserts the **observable** profile-on-disk state
matches the reported ``status``, not just the status string.

Audit context: ``docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md``
(commit 4cc6435). This file is the runtime-side test that the
``[[ibounce-honest-positioning]]`` invariant catches the same
shape ``docs/CONTRIBUTING.md`` calls out on the test side.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from iam_jit.improve import ImproveProfileResult, improve_profile


# ---------------------------------------------------------------------------
# Fixtures (mirror tests/improve/test_pipeline.py so the stubs share shape)
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    p = tmp_path / "profiles.yaml"
    # Pre-seed with 100 rules so the new ones come in below threshold
    # (so the auto-install branch is the one we exercise).
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "many pre-existing rules",
                "allow_rules": [
                    {"pattern": f"ec2:Action{i}"} for i in range(100)
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
def stub_generator(monkeypatch: pytest.MonkeyPatch):
    """Stub generate_from_audit so tests don't make LLM calls."""

    def _install(
        bouncer: str = "ibounce",
        allows: list[dict] | None = None,
        scope: dict[str, list[str]] | None = None,
    ):
        from iam_jit.llm.profile_generator import (
            GeneratedProfile,
            ProfileResult,
        )

        body: dict[str, Any] = {"allows": allows or [], "denies": []}
        for k, v in (scope or {}).items():
            body[k] = v
        profile_yaml = yaml.safe_dump({
            "profiles": {f"improve-{bouncer}-test": body},
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
    def _install(events: list[dict]) -> None:
        monkeypatch.setattr(
            "iam_jit.improve.pipeline._fetch_events_for_bouncer",
            lambda **_: list(events),
        )
    return _install


@pytest.fixture
def quiet_fanout(monkeypatch: pytest.MonkeyPatch) -> list[str]:
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


@pytest.fixture
def fail_n_of_three_adds(monkeypatch: pytest.MonkeyPatch):
    """Make ``add_profile_allow_rule`` raise ProfileAllowError for the
    first N of the proposed rules and succeed for the rest, deferring
    the success-path to the real implementation.

    The bug we're testing for is that ``status="auto_installed"`` was
    returned even when this fixture forced individual rule adds to
    raise — the loop silently ``continue``d.
    """
    from iam_jit.profile_allow import operations as real_ops

    real_add = real_ops.add_profile_allow_rule
    state = {"n_to_fail": 0, "calls": 0}

    def _install(n_to_fail: int) -> None:
        state["n_to_fail"] = n_to_fail
        state["calls"] = 0

        def _maybe_failing(**kwargs):
            state["calls"] += 1
            if state["calls"] <= state["n_to_fail"]:
                raise real_ops.ProfileAllowError(
                    f"synthetic fail #{state['calls']} for "
                    f"{kwargs.get('action')}",
                    code="synthetic_test_failure",
                )
            return real_add(**kwargs)

        monkeypatch.setattr(
            "iam_jit.improve.pipeline.add_profile_allow_rule"
            if False
            else "iam_jit.profile_allow.operations.add_profile_allow_rule",
            _maybe_failing,
        )

    return _install


# ---------------------------------------------------------------------------
# Helpers — observable state
# ---------------------------------------------------------------------------


def _patterns_on_disk(profiles_yaml: Path, profile_name: str) -> set[str]:
    """Read the profile YAML directly and return the on-disk allow-rule
    pattern set (the observable state we're verifying against)."""
    body = yaml.safe_load(profiles_yaml.read_text()) or {}
    profile = body.get("profiles", {}).get(profile_name, {}) or {}
    rules = profile.get("allow_rules") or []
    return {r["pattern"] for r in rules if isinstance(r, dict) and r.get("pattern")}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_all_rules_succeed_returns_auto_installed_with_full_install(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
) -> None:
    """Test 1 — every requested rule lands → status=auto_installed +
    installed_rules count matches requested + failed_rules empty.

    State verification: the profile YAML on disk has every requested
    pattern present after the call."""
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
            {"target": "arn:aws:s3:::cache", "actions": ["s3:ListBucket"]},
            {"target": "arn:aws:s3:::cache", "actions": ["s3:HeadObject"]},
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
    # 1. Reported status claim.
    assert result.status == "auto_installed", result.explanation
    assert result.rules_added == 3
    assert len(result.installed_rules) == 3
    assert result.failed_rules == []
    assert result.recommended_action == ""
    # 2. Observable state matches the claim.
    on_disk = _patterns_on_disk(tmp_profiles, "active-test")
    assert "s3:GetObject" in on_disk
    assert "s3:ListBucket" in on_disk
    assert "s3:HeadObject" in on_disk


def test_partial_failure_returns_partial_install_with_per_rule_breakdown(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
    fail_n_of_three_adds,
) -> None:
    """Test 2 — 1 of 3 adds fails → status=partial_install +
    failed_rules has the 1 failure + installed_rules has the 2 successes.

    State verification: the profile YAML on disk has exactly the
    install_count rules that succeeded (NOT the requested count)."""
    fail_n_of_three_adds(1)
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
            {"target": "arn:aws:s3:::cache", "actions": ["s3:ListBucket"]},
            {"target": "arn:aws:s3:::cache", "actions": ["s3:HeadObject"]},
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
    # 1. Reported status claim.
    assert result.status == "partial_install", result.explanation
    assert result.rules_added == 2  # only what actually landed
    assert len(result.installed_rules) == 2
    assert len(result.failed_rules) == 1
    failure = result.failed_rules[0]
    assert failure["error_code"] == "synthetic_test_failure"
    assert "synthetic fail" in failure["error_message"]
    assert failure["action"]  # at least the action was preserved
    assert "target" in failure
    # recommended_action MUST tell the operator what to do next.
    assert result.recommended_action
    assert (
        "iam_jit_improve_profile" in result.recommended_action
        or "iam-jit profile allow add" in result.recommended_action
    )

    # 2. Observable state matches the claim.
    on_disk = _patterns_on_disk(tmp_profiles, "active-test")
    installed_patterns = {r["action"] for r in result.installed_rules}
    # Every pattern claimed installed is actually on disk.
    assert installed_patterns.issubset(on_disk), (
        f"status='partial_install' but observable disk state diverges: "
        f"claimed installed={installed_patterns!r} vs on_disk={on_disk!r}"
    )
    # The failed pattern is NOT on disk.
    failed_pattern = result.failed_rules[0]["action"]
    assert failed_pattern not in on_disk, (
        f"status='partial_install' said {failed_pattern!r} failed but "
        f"it appears on disk — this is the #448 shape inverted"
    )


def test_all_failures_returns_no_install_with_unchanged_profile(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
    fail_n_of_three_adds,
) -> None:
    """Test 3 — every add fails → status=no_install + failed_rules
    fully populated + installed_rules empty + on-disk profile unchanged.

    State verification: the profile YAML pre-state == post-state."""
    fail_n_of_three_adds(3)
    pre_state = _patterns_on_disk(tmp_profiles, "active-test")
    stub_audit_events([{"_bouncer": "ibounce"}])
    stub_generator(
        bouncer="ibounce",
        allows=[
            {"target": "arn:aws:s3:::cache", "actions": ["s3:GetObject"]},
            {"target": "arn:aws:s3:::cache", "actions": ["s3:ListBucket"]},
            {"target": "arn:aws:s3:::cache", "actions": ["s3:HeadObject"]},
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
    # 1. Reported status claim.
    assert result.status == "no_install", result.explanation
    assert result.rules_added == 0
    assert result.installed_rules == []
    assert len(result.failed_rules) == 3
    assert all(
        f["error_code"] == "synthetic_test_failure"
        for f in result.failed_rules
    )
    assert result.recommended_action
    assert "NOT modified" in result.recommended_action

    # 2. Observable state matches the claim — profile unchanged.
    post_state = _patterns_on_disk(tmp_profiles, "active-test")
    assert post_state == pre_state, (
        f"status='no_install' but observable disk state changed: "
        f"pre={sorted(pre_state)[:5]}... post={sorted(post_state)[:5]}..."
    )
    # And none of the proposed new patterns leaked through.
    proposed_patterns = {"s3:GetObject", "s3:ListBucket", "s3:HeadObject"}
    assert post_state.isdisjoint(proposed_patterns)


def test_regression_response_never_returns_auto_installed_when_any_rule_failed(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
    fail_n_of_three_adds,
) -> None:
    """Test 4 — regression: the #448 shape must not re-ship.

    For every (n_to_fail in [1, 2, 3]) the response MUST NOT carry
    ``status="auto_installed"``. This is the direct mirror of
    docs/CONTRIBUTING.md's status-vs-observable invariant on the
    runtime side."""
    for n_to_fail in (1, 2, 3):
        fail_n_of_three_adds(n_to_fail)
        stub_audit_events([{"_bouncer": "ibounce"}])
        stub_generator(
            bouncer="ibounce",
            allows=[
                {"target": f"arn:aws:s3:::b-{i}", "actions": ["s3:GetObject"]}
                for i in range(3)
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
        assert result.status != "auto_installed", (
            f"#448 shape regression: n_to_fail={n_to_fail} but status "
            f"was 'auto_installed' (full success would silently "
            f"mask {n_to_fail} failures). Got result={result!r}"
        )
        # And the claimed install count matches the count we can prove.
        assert result.rules_added == len(result.installed_rules), (
            f"rules_added={result.rules_added} disagrees with "
            f"len(installed_rules)={len(result.installed_rules)}; this is "
            f"the rules_added=len(proposed) variant of #448"
        )


def test_dataclass_round_trips_new_fields_through_as_dict(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    stub_generator,
    stub_audit_events,
    quiet_fanout,
    fail_n_of_three_adds,
) -> None:
    """The MCP layer renders as_dict() — verify the new fields land in
    the agent-visible payload (not just on the Python dataclass)."""
    fail_n_of_three_adds(1)
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
    assert isinstance(result, ImproveProfileResult)
    d = result.as_dict()
    assert "installed_rules" in d
    assert "failed_rules" in d
    assert "recommended_action" in d
    assert d["status"] == "partial_install"
    assert isinstance(d["installed_rules"], list)
    assert isinstance(d["failed_rules"], list)
    assert isinstance(d["recommended_action"], str)
