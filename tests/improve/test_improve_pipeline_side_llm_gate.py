"""§A93 / #509 Phase 3 — opt-in gate tests for the improve-profile
pipeline (A2 site).

The improve-profile pipeline composes
:func:`iam_jit.llm.profile_generator.generate_from_audit` — when the
side-LLM gate is off, the inner generator skips its LLM ``chat()`` call
AND the outer pipeline emits its own ``improve.pipeline`` report_skip
(Phase 2 wire, preserved). Defense in depth.

Per [[bouncer-zero-llm-when-agent-in-loop]]:

  * Default behavior (``IAM_JIT_ENABLE_SIDE_LLM`` UNSET): the inner
    generator's ``backend.chat(...)`` is NOT called; both the inner
    ``profile_generator.from_audit`` skip + the outer
    ``improve.pipeline`` skip fire. The deterministic event-derived
    fallback still produces a valid profile bundle.
  * Opt-in WITH stub backend: chat() runs normally; only the
    ``improve.pipeline`` skip is silent (the outer counter fires only
    when the generator's backend resolves to NoOp, which doesn't
    happen with a real stub).
  * Caller-supplied result shape stays stable.

State-verification convention per ``docs/CONTRIBUTING.md`` — every
assertion is on OBSERVABLE state: mock chat() call count, skip
counter snapshot, ImproveProfileResult fields.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from iam_jit.improve import improve_profile
from iam_jit.llm import (
    REASON_NO_LLM_BACKEND,
    REASON_NO_SIDE_LLM_ENABLED,
    profile_generator as pg,
    reset_skip_counter,
    skip_counter_snapshot,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_counter() -> None:
    reset_skip_counter()
    yield
    reset_skip_counter()


@pytest.fixture(autouse=True)
def _no_llm_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default to local-dev / agent-in-loop: no opt-in, no creds."""
    for var in (
        "IAM_JIT_LLM",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "IAM_JIT_BEDROCK_MODEL",
        "OLLAMA_HOST",
        "IAM_JIT_ENABLE_SIDE_LLM",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def tmp_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the profiles loader at a temp file with a tiny baseline."""
    p = tmp_path / "profiles.yaml"
    p.write_text(yaml.safe_dump({
        "profiles": {
            "full-user": {"description": "passthrough"},
            "active-test": {
                "description": "test active profile",
                "allow_rules": [
                    {"pattern": "ec2:DescribeInstances", "note": "pre"},
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


class _RecordingBackend:
    """Test-only backend that records every chat() invocation."""

    name = "recording"

    def __init__(self, reply: str = "") -> None:
        self._reply = reply
        self.chat_calls: list[dict] = []

    def chat(
        self,
        *,
        system_prompt: str,
        messages: list[dict[str, str]],
    ) -> str:
        self.chat_calls.append({
            "system_prompt": system_prompt,
            "messages": messages,
        })
        return self._reply


@pytest.fixture
def patch_resolve_backend(monkeypatch: pytest.MonkeyPatch):
    def _make(reply: str = "", name: str = "anthropic") -> _RecordingBackend:
        recorder = _RecordingBackend(reply=reply)

        def _resolve(preferred: str | None):
            return recorder, name

        monkeypatch.setattr(pg, "_resolve_backend", _resolve)
        return recorder

    return _make


@pytest.fixture
def stub_audit_events(monkeypatch: pytest.MonkeyPatch):
    """Stub the audit fetcher so the pipeline sees fixed events."""
    def _install(events: list[dict[str, Any]]) -> None:
        monkeypatch.setattr(
            "iam_jit.improve.pipeline._fetch_events_for_bouncer",
            lambda **_: list(events),
        )
    return _install


@pytest.fixture
def quiet_fanout(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub the profile-reload fan-out so nothing tries to hit real
    bouncers in tests."""
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


def _events_one_bouncer() -> list[dict[str, Any]]:
    return [
        {
            "_bouncer": "ibounce",
            "time": 1716412800000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {
                "verdict": "allow",
                "agent": {"session_id": "abc-123"},
            }},
            "api": {
                "service": {"name": "s3"},
                "operation": "GetObject",
                "resources": [
                    {"name": "arn:aws:s3:::reports-bucket/q2.csv"},
                ],
            },
        },
    ]


# ---------------------------------------------------------------------------
# Default OFF — local-dev / agent-in-loop mode
# ---------------------------------------------------------------------------


def test_improve_default_skips_inner_llm_call(
    tmp_profiles,
    tmp_pending_queue,
    quiet_fanout,
    stub_audit_events,
    patch_resolve_backend,
) -> None:
    """No opt-in: improve_profile runs end-to-end, but the inner
    profile_generator NEVER calls chat() on the backend."""
    stub_audit_events(_events_one_bouncer())
    recorder = patch_resolve_backend(reply="", name="anthropic")
    result = improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        auto_install=True,
        apply=True,
        posture="ambient",
    )
    # Observable 1: LLM was never invoked.
    assert recorder.chat_calls == [], (
        f"backend.chat() must not fire in local-dev mode; "
        f"got {len(recorder.chat_calls)} calls"
    )
    # Observable 2: improve_profile still returned a structured result
    # (deterministic-only event-derived path still works).
    assert result.status in (
        "auto_installed", "pending_approval", "scope_only_change",
        "no_change",
    )


def test_improve_default_emits_both_inner_and_outer_skips(
    tmp_profiles,
    tmp_pending_queue,
    quiet_fanout,
    stub_audit_events,
    patch_resolve_backend,
) -> None:
    """Defense-in-depth: BOTH skip counters fire — inner
    profile_generator.from_audit (gate) + outer improve.pipeline
    (already-shipped Phase 2 wire). Operators see the deferral at
    BOTH layers."""
    stub_audit_events(_events_one_bouncer())
    patch_resolve_backend(reply="", name="anthropic")
    improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        auto_install=True,
        apply=True,
        posture="ambient",
    )
    snap = skip_counter_snapshot()
    # Inner skip (Phase 3 gate) — distinct reason.
    assert snap["counts"].get("profile_generator.from_audit", 0) >= 1
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) >= 1
    # Outer skip (Phase 2 wire — fires when backend name is noop / empty).
    assert snap["counts"].get("improve.pipeline", 0) >= 1


def test_improve_default_result_carries_no_chat_artifact(
    tmp_profiles,
    tmp_pending_queue,
    quiet_fanout,
    stub_audit_events,
    patch_resolve_backend,
) -> None:
    """The returned result reflects deterministic-only path: status is
    structured + observable (per [[ibounce-honest-positioning]])."""
    stub_audit_events(_events_one_bouncer())
    patch_resolve_backend(reply="", name="anthropic")
    result = improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        auto_install=True,
        apply=True,
        posture="ambient",
    )
    # Result must have a status (no silent failures).
    assert result.status
    # Bouncer + window are populated (no degradation to None).
    assert result.bouncer == "ibounce"
    assert result.cadence_window


# ---------------------------------------------------------------------------
# Opt-in WITH stub backend — chat fires
# ---------------------------------------------------------------------------


def test_improve_opt_in_with_stub_backend_invokes_llm(
    tmp_profiles,
    tmp_pending_queue,
    quiet_fanout,
    stub_audit_events,
    patch_resolve_backend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in + stub backend: the inner chat() IS called exactly once."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    stub_audit_events(_events_one_bouncer())
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        "target": "arn:aws:s3:::reports-bucket/*",
                        "actions": ["s3:GetObject"],
                        "reason": "observed",
                    },
                ],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": "stub",
    })
    recorder = patch_resolve_backend(reply=reply, name="anthropic")
    improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        auto_install=True,
        apply=True,
        posture="ambient",
    )
    assert len(recorder.chat_calls) == 1, (
        f"chat() must fire exactly once with opt-in; "
        f"got {len(recorder.chat_calls)}"
    )
    # No NO_SIDE_LLM_ENABLED skip (operator opted in).
    snap = skip_counter_snapshot()
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0


# ---------------------------------------------------------------------------
# Opt-in WITHOUT working creds — distinct misconfig skip fires
# ---------------------------------------------------------------------------


def test_improve_opt_in_without_creds_surfaces_misconfig(
    tmp_profiles,
    tmp_pending_queue,
    quiet_fanout,
    stub_audit_events,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in IS set but the resolved backend is NoOp (creds missing):
    REASON_NO_LLM_BACKEND fires (NOT NO_SIDE_LLM_ENABLED — operator
    opted in; the misconfig is the missing creds)."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    stub_audit_events(_events_one_bouncer())

    class _NoOpShaped:
        name = "noop"

        def chat(self, **_kw):
            return ""

    monkeypatch.setattr(
        pg, "_resolve_backend",
        lambda preferred: (_NoOpShaped(), "noop"),
    )
    improve_profile(
        bouncer="ibounce",
        cadence="per_session",
        threshold=0.30,
        auto_install=True,
        apply=True,
        posture="ambient",
    )
    snap = skip_counter_snapshot()
    assert snap["by_reason"].get(REASON_NO_LLM_BACKEND, 0) >= 1
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0
