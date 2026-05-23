"""§A93 / #509 Phase 3 — opt-in gate tests for
:func:`iam_jit.llm.profile_generator.generate_from_audit` (A2 via
improve/pipeline.py) and
:func:`iam_jit.llm.profile_generator.generate_from_context` (A3).

Per [[bouncer-zero-llm-when-agent-in-loop]]:

  * Default behavior (``IAM_JIT_ENABLE_SIDE_LLM`` UNSET): generator
    skips the bouncer-side LLM ``backend.chat(...)`` call entirely —
    even when a backend is configured via env vars picked up by
    sibling tools. The deterministic fallback still produces a valid
    profile bundle (safety floor + event-derived allows). ``report_skip``
    fires with ``REASON_NO_SIDE_LLM_ENABLED``.
  * Opt-in WITH stub backend: the chat path runs normally; the
    operator's explicit opt-in is honored.
  * Opt-in WITHOUT working creds: the resolved backend is NoOp;
    ``report_skip`` fires with ``REASON_NO_LLM_BACKEND`` (misconfig
    surfacing per [[ibounce-honest-positioning]]).

State-verification convention per ``docs/CONTRIBUTING.md`` — each
test asserts on OBSERVABLE state: backend ``chat()`` mock call count,
skip counter snapshot, returned ProfileResult structure.
"""

from __future__ import annotations

import json

import pytest

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
    """Strip every LLM-related env var so the default path honestly
    reflects no creds + no opt-in."""
    for var in (
        "IAM_JIT_LLM",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "IAM_JIT_BEDROCK_MODEL",
        "OLLAMA_HOST",
        "IAM_JIT_ENABLE_SIDE_LLM",
    ):
        monkeypatch.delenv(var, raising=False)


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
    """Patch _resolve_backend to return a recording backend so we can
    assert chat() was / wasn't called."""
    def _make(reply: str = "", name: str = "anthropic") -> _RecordingBackend:
        recorder = _RecordingBackend(reply=reply)

        def _resolve(preferred: str | None):
            return recorder, name

        monkeypatch.setattr(pg, "_resolve_backend", _resolve)
        return recorder

    return _make


def _events_one_bouncer() -> list[dict]:
    """Minimal audit event payload — one bouncer, one allow event."""
    return [
        {
            "_bouncer": "ibounce",
            "time": 1716412800000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {"verdict": "allow"}},
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
# A2 — generate_from_audit
# ---------------------------------------------------------------------------


def test_audit_gate_default_off_skips_llm_call_and_emits_skip(
    patch_resolve_backend,
) -> None:
    """Default ``IAM_JIT_ENABLE_SIDE_LLM`` UNSET: ``backend.chat`` is
    NOT called + report_skip fires with REASON_NO_SIDE_LLM_ENABLED."""
    recorder = patch_resolve_backend(reply=json.dumps({"profiles": []}))
    result = pg.generate_from_audit(
        events=_events_one_bouncer(),
        time_range="1h",
        bouncers=["ibounce"],
        profile_name="gate-test",
    )

    # Observable 1: the LLM was NEVER called.
    assert recorder.chat_calls == [], (
        "backend.chat() must not be called in local-dev default mode; "
        f"got {len(recorder.chat_calls)} calls"
    )

    # Observable 2: the skip counter fired with REASON_NO_SIDE_LLM_ENABLED.
    snap = skip_counter_snapshot()
    assert snap["counts"].get("profile_generator.from_audit", 0) == 1
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 1

    # Observable 3: response is still well-formed (deterministic fallback
    # produced a bundle; safety floor + event-derived rules survived).
    assert result.backend_name == "noop"
    # The deterministic fallback still emits a profile per requested
    # bouncer (the no-events early-return doesn't fire — we passed an event).
    assert len(result.bundle) >= 1


def test_audit_gate_opt_in_with_stub_backend_runs_llm(
    patch_resolve_backend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``IAM_JIT_ENABLE_SIDE_LLM=1`` + stub backend: chat() IS called."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        "target": "arn:aws:s3:::reports-bucket/*",
                        "actions": ["s3:GetObject"],
                        "reason": "observed legitimate reads",
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
    result = pg.generate_from_audit(
        events=_events_one_bouncer(),
        time_range="1h",
        bouncers=["ibounce"],
        profile_name="optin-test",
    )

    # Observable: chat() WAS called exactly once.
    assert len(recorder.chat_calls) == 1
    # Backend name reflects the resolved one (not noop).
    assert result.backend_name == "anthropic"
    # No NO_SIDE_LLM_ENABLED skip (the operator opted in).
    snap = skip_counter_snapshot()
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0


def test_audit_gate_opt_in_truthy_values(
    patch_resolve_backend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All canonical truthy values enable the opt-in."""
    for truthy in ("1", "true", "TRUE", "yes", "Yes", "on"):
        monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", truthy)
        recorder = patch_resolve_backend(reply="", name="anthropic")
        pg.generate_from_audit(
            events=_events_one_bouncer(),
            time_range="1h",
            bouncers=["ibounce"],
            profile_name=f"truthy-{truthy}",
        )
        assert len(recorder.chat_calls) == 1, (
            f"chat must fire for IAM_JIT_ENABLE_SIDE_LLM={truthy!r}"
        )


def test_audit_gate_opt_in_falsy_values_still_skip(
    patch_resolve_backend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Falsy / weird values do NOT enable the gate."""
    for falsy in ("", "0", "false", "no", "off", "maybe", "  "):
        monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", falsy)
        recorder = patch_resolve_backend(reply="", name="anthropic")
        pg.generate_from_audit(
            events=_events_one_bouncer(),
            time_range="1h",
            bouncers=["ibounce"],
            profile_name=f"falsy-{falsy or 'empty'}",
        )
        assert recorder.chat_calls == [], (
            f"chat must NOT fire for IAM_JIT_ENABLE_SIDE_LLM={falsy!r}"
        )


def test_audit_gate_response_shape_matches_existing_contract(
    patch_resolve_backend,
) -> None:
    """Gated response still matches the documented ProfileResult shape
    so existing consumers don't regress."""
    patch_resolve_backend(reply="")
    result = pg.generate_from_audit(
        events=_events_one_bouncer(),
        time_range="1h",
        bouncers=["ibounce"],
        profile_name="contract-test",
    )
    # ProfileResult contract — every field present + typed.
    assert isinstance(result.bundle, tuple)
    assert isinstance(result.index_yaml, str)
    assert isinstance(result.explanation, str)
    assert isinstance(result.budget_spent_usd, float)
    assert isinstance(result.backend_name, str)
    assert isinstance(result.parser_strict_match, bool)


def test_audit_gate_opt_in_with_noop_backend_reports_misconfig(
    patch_resolve_backend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in IS set but backend resolved to NoOp (creds missing):
    distinct ``REASON_NO_LLM_BACKEND`` skip fires so operators see the
    misconfig per [[ibounce-honest-positioning]]."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")

    # Make _resolve_backend return a NoOp-shaped backend (name == "noop").
    class _NoOpShaped:
        name = "noop"

        def chat(self, **_kw):
            return ""

    monkeypatch.setattr(
        pg, "_resolve_backend",
        lambda preferred: (_NoOpShaped(), "noop"),
    )
    pg.generate_from_audit(
        events=_events_one_bouncer(),
        time_range="1h",
        bouncers=["ibounce"],
        profile_name="misconfig-test",
    )
    snap = skip_counter_snapshot()
    # NO_LLM_BACKEND (not NO_SIDE_LLM_ENABLED — the operator DID opt
    # in; the misconfig is the missing creds).
    assert snap["by_reason"].get(REASON_NO_LLM_BACKEND, 0) >= 1
    # And NOT the side-llm reason.
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0


# ---------------------------------------------------------------------------
# A3 — generate_from_context
# ---------------------------------------------------------------------------


def test_context_gate_default_off_skips_llm_call_and_emits_skip(
    patch_resolve_backend,
) -> None:
    """Default UNSET: chat() NOT called + report_skip fires."""
    recorder = patch_resolve_backend(reply="", name="anthropic")
    result = pg.generate_from_context(
        context="Mid-size SaaS prod/staging split",
        profile_name="ctx-gate",
    )
    assert recorder.chat_calls == [], (
        "backend.chat() must not fire in local-dev default mode"
    )
    snap = skip_counter_snapshot()
    assert snap["counts"].get("profile_generator.from_context", 0) == 1
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 1
    # Result is still well-formed (safety-floor scaffold across all 4 bouncers).
    assert result.backend_name == "noop"
    bouncers = {p.bouncer for p in result.bundle}
    assert bouncers == {"ibounce", "kbounce", "dbounce", "gbounce"}


def test_context_gate_opt_in_with_stub_backend_runs_llm(
    patch_resolve_backend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in IS set: chat() runs normally."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [],
                "denies": [
                    {
                        "target": "arn:aws:iam::*:role/break-glass-*",
                        "actions": ["sts:AssumeRole"],
                        "reason": "break-glass needs approval",
                    },
                ],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": "stub",
    })
    recorder = patch_resolve_backend(reply=reply, name="anthropic")
    result = pg.generate_from_context(
        context="Mid-size SaaS, prod/staging split, 5 engineers",
        profile_name="ctx-optin",
    )
    assert len(recorder.chat_calls) == 1
    assert result.backend_name == "anthropic"
    snap = skip_counter_snapshot()
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0


def test_context_gate_response_includes_scaffold_in_default_mode(
    patch_resolve_backend,
) -> None:
    """When gated, the returned ProfileResult is a scaffold — the
    deterministic safety-floor across all 4 bouncers."""
    patch_resolve_backend(reply="")
    result = pg.generate_from_context(
        context="Anything",
        profile_name="scaffold-test",
    )
    # All four bouncers carry a safety-floor profile.
    bouncers = {p.bouncer for p in result.bundle}
    assert bouncers == {"ibounce", "kbounce", "dbounce", "gbounce"}
    # ibounce safety floor includes the IAM credential lock-down.
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    assert "iam:CreateAccessKey" in ibounce.profile_yaml


# ---------------------------------------------------------------------------
# Cross-cutting — counter parity with /healthz + posture
# ---------------------------------------------------------------------------


def test_counter_snapshot_visible_via_top_level_helper(
    patch_resolve_backend,
) -> None:
    """report_skip surface used by /healthz + iam-jit posture reflects
    both generator gate fires."""
    patch_resolve_backend(reply="")
    pg.generate_from_audit(
        events=_events_one_bouncer(),
        time_range="1h",
        bouncers=["ibounce"],
        profile_name="counter-1",
    )
    pg.generate_from_context(
        context="ctx",
        profile_name="counter-2",
    )
    snap = skip_counter_snapshot()
    assert snap["total"] == 2
    assert snap["counts"]["profile_generator.from_audit"] == 1
    assert snap["counts"]["profile_generator.from_context"] == 1
