"""§A93 / #509 Phase 2 — proxy deny path delegates classification to
agent per [[bouncer-zero-llm-when-agent-in-loop]].

State-verification convention per ``docs/CONTRIBUTING.md``: each test
asserts on OBSERVABLE state (wire body fields, skip counter values,
log records) rather than on construction.

The contract under test:

  1. When NO LLM creds are configured AND the deny is non-destructive
     (structural-heuristic does not flag), the 403 body's
     ``is_likely_injection_classification`` is ``pending_classification``
     + ``deny_event_id`` is present so the agent can call
     ``iam_jit_classify_deny`` (MCP) for agent-mediated enrichment.

  2. The deterministic safety floor (KNOWN_ADVERSARIAL match +
     structural-heuristic destructive-verb backstop) STILL fires
     inline — destructive verbs return ``appears_adversarial`` +
     recommend halt+escalate regardless of LLM availability.

  3. ``report_skip`` is invoked exactly once per pending classification
     (the counter snapshot reflects the call).

  4. ``structured_deny_schema_version`` on the wire body is bumped to
     1.1 to signal the new enum value.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
from iam_jit.bouncer.store import BouncerStore
from iam_jit.llm import reset_skip_counter, skip_counter_snapshot
from iam_jit.structured_deny import (
    INJECTION_AMBIGUOUS,
    INJECTION_APPEARS_ADVERSARIAL,
    INJECTION_APPEARS_LEGITIMATE,
    INJECTION_PENDING_CLASSIFICATION,
    build_structured_deny,
    classify_injection_likelihood,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_skip_counter() -> None:
    """Ensure tests don't bleed counter state into each other."""
    reset_skip_counter()
    yield
    reset_skip_counter()


@pytest.fixture(autouse=True)
def _no_side_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default to local-dev / agent-in-loop mode: no opt-in flag, no
    LLM creds. Tests that want the standalone path can opt back in."""
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)
    monkeypatch.delenv("IAM_JIT_LLM", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def _sigv4_auth(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesignature"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _wait_for_listen(host: str, port: int, *, retries: int = 50) -> None:
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


# ---------------------------------------------------------------------------
# Unit tests — classify_injection_likelihood directly
# ---------------------------------------------------------------------------


def test_local_dev_non_destructive_returns_pending_classification() -> None:
    """Local-dev mode + non-destructive action → pending_classification
    (not ambiguous). Observable state: return value + skip counter."""
    cls, hook = classify_injection_likelihood(
        action="s3:GetObject",
        resource="arn:aws:s3:::cache-bucket/file.json",
        deny_source="static_profile",
        deny_reason="profile 'safe-default' has no matching allow",
    )
    assert cls == INJECTION_PENDING_CLASSIFICATION
    assert hook == ""
    # Skip counter incremented — verifies report_skip fired.
    snap = skip_counter_snapshot()
    assert snap["counts"].get("structured_deny.classify") == 1
    assert snap["last_skips"][-1]["feature"] == "structured_deny.classify"


def test_destructive_verb_always_returns_adversarial_even_in_local_dev() -> None:
    """Deterministic safety floor: destructive verbs flag adversarial
    INLINE regardless of LLM availability. The skip counter MUST NOT
    increment (no deferral needed — the deterministic floor fired)."""
    cls, hook = classify_injection_likelihood(
        action="s3:DeleteObject",
        resource="arn:aws:s3:::cache-bucket/file.json",
        deny_source="static_profile",
        deny_reason="profile 'safe-default' has no matching allow",
    )
    assert cls == INJECTION_APPEARS_ADVERSARIAL
    assert hook == "structural_heuristic"
    # No skip — the deterministic floor fired, no deferral.
    snap = skip_counter_snapshot()
    assert snap["total"] == 0


def test_env_pinned_hook_takes_priority_over_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An IAM_JIT_INJECTION_CLASSIFIER_HOOK is HONORED before the
    pending-classification fallback. Used by tests + custom integrations."""

    monkeypatch.setenv(
        "IAM_JIT_INJECTION_CLASSIFIER_HOOK",
        # Use this module's hook — it returns appears_legitimate.
        "tests.bouncer.test_proxy_deny_path_agent_delegated:_legit_hook",
    )
    cls, hook = classify_injection_likelihood(
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_source="static_profile",
        deny_reason="profile 'safe-default'",
    )
    assert cls == INJECTION_APPEARS_LEGITIMATE
    assert hook  # carries the hook name; exact content varies
    # No skip — hook handled it.
    assert skip_counter_snapshot()["total"] == 0


def test_side_llm_opt_in_without_creds_returns_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When IAM_JIT_ENABLE_SIDE_LLM=1 but no creds configured, the
    classifier degrades to pending_classification + emits a
    report_skip with REASON_BACKEND_UNAVAILABLE so the operator sees
    the misconfig in their counter."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    # No backend creds set by the _no_side_llm autouse fixture.
    cls, _hook = classify_injection_likelihood(
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_source="static_profile",
        deny_reason="profile 'safe-default'",
    )
    # Either pending (when deny_classifier returns no backend) OR
    # ambiguous (when classifier ran + said ambiguous + we surface
    # the degradation). Both shapes increment the skip counter.
    assert cls in (
        INJECTION_PENDING_CLASSIFICATION,
        INJECTION_AMBIGUOUS,
    )
    assert skip_counter_snapshot()["total"] >= 1


def _legit_hook(**_kwargs):
    """Hook helper for the env-pinned hook test above."""
    return INJECTION_APPEARS_LEGITIMATE, "test_hook"


# ---------------------------------------------------------------------------
# build_structured_deny shape — schema_version + classification
# ---------------------------------------------------------------------------


def test_structured_deny_schema_version_bumped_to_1_1() -> None:
    """Schema-version is 1.1 (was 1.0); agents grepping the old version
    see a clean upgrade signal."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
    )
    assert sd.schema_version == "1.1"


def test_structured_deny_local_dev_returns_pending_with_event_id() -> None:
    """Local-dev / agent-in-loop default: pending_classification +
    deny_event_id present so agent can call iam_jit_classify_deny."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
        when="2026-05-23T10:00:00Z",
    )
    assert sd.is_likely_injection_classification == INJECTION_PENDING_CLASSIFICATION
    assert sd.deny_event_id.startswith("evt_ibounce_")
    # human_summary references the pending state operator-friendly.
    summary = sd.human_summary()
    assert "pending" in summary.lower()


# ---------------------------------------------------------------------------
# End-to-end proxy 403 — wire body shape verification
# ---------------------------------------------------------------------------


async def _drive_get_deny(tmp_path) -> tuple[dict, int]:
    """Stand up a default-deny TRANSPARENT proxy + drive ONE GET so we
    hit a non-destructive (and thus pending-classification) deny."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/cache-bucket/data.json",
                headers={
                    "host": "s3.amazonaws.com",
                    "authorization": _sigv4_auth(
                        service="s3", region="us-east-1",
                    ),
                    "X-Agent-Session-Id": "sess-test-pending",
                },
            ) as resp:
                body = await resp.json()
                status = resp.status
        return body, status
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_proxy_403_non_destructive_returns_pending_classification(
    tmp_path,
) -> None:
    """End-to-end: GET on default-deny → 403 with pending_classification
    + deny_event_id + schema_version 1.1."""
    body, status = await _drive_get_deny(tmp_path)
    assert status == 403
    assert (
        body["is_likely_injection_classification"]
        == INJECTION_PENDING_CLASSIFICATION
    )
    assert body["deny_event_id"]
    assert body["deny_event_id"].startswith("evt_")
    assert body["structured_deny_schema_version"] == "1.1"


@pytest.mark.asyncio
async def test_proxy_403_increments_skip_counter(tmp_path) -> None:
    """The end-to-end deny path increments the report_skip counter so
    /healthz can surface the deferral to operators."""
    await _drive_get_deny(tmp_path)
    snap = skip_counter_snapshot()
    # Exactly one structured_deny.classify skip — the deny hot-path
    # ran classify_injection_likelihood once per response.
    assert snap["counts"].get("structured_deny.classify") == 1


@pytest.mark.asyncio
async def test_proxy_healthz_exposes_llm_skips_block(tmp_path) -> None:
    """/healthz on the proxy carries the llm_skips counter snapshot."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/healthz") as resp:
                body = await resp.json()
        assert "llm_skips" in body
        # Schema parity with skip_counter_snapshot().
        assert set(body["llm_skips"]) >= {"total", "counts", "by_reason", "last_skips"}
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# MCP tool — iam_jit_classify_deny
# ---------------------------------------------------------------------------


def test_classify_deny_mcp_missing_event_id_errors() -> None:
    from iam_jit.structured_deny import classify_deny_for_mcp
    result = classify_deny_for_mcp({})
    assert result["status"] == "error"
    assert result["code"] == "missing_deny_event_id"


def test_classify_deny_mcp_not_found() -> None:
    """Unknown deny_event_id returns ``not_found`` rather than crashing."""
    from iam_jit.structured_deny import classify_deny_for_mcp
    result = classify_deny_for_mcp({
        "deny_event_id": "evt_ibounce_doesnotexist",
        "lookback_minutes": 5,
    })
    assert result["status"] == "not_found"
    assert result["deny_event_id"] == "evt_ibounce_doesnotexist"


def test_classify_deny_mcp_invalid_classification_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An agent passing a junk classification gets a clear error rather
    than silent corruption of the audit log."""
    from iam_jit.structured_deny import classify_deny_for_mcp

    # Stub fetch_recent_denies to return a synthesized row that the
    # classifier will match by deny_event_id.
    _stub_fetch_with_one_row(monkeypatch, action="s3:GetObject")
    # Compute the event id the way build_structured_deny would.
    from iam_jit.structured_deny import build_structured_deny
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
        when="2026-05-23T10:00:00Z",
    )
    result = classify_deny_for_mcp({
        "deny_event_id": sd.deny_event_id,
        "classification": "totally_made_up",
    })
    assert result["status"] == "error"
    assert result["code"] == "invalid_classification"


def test_classify_deny_mcp_lookup_only_returns_structured_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the agent omits classification, the tool returns the
    structured deny + guidance so the agent can analyze + call back."""
    from iam_jit.structured_deny import build_structured_deny, classify_deny_for_mcp

    _stub_fetch_with_one_row(monkeypatch, action="s3:GetObject")
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
        when="2026-05-23T10:00:00Z",
    )
    # Sanity: the stub row produces the same deny_event_id as the
    # synthesized one used in the request (otherwise the lookup misses).
    result = classify_deny_for_mcp({"deny_event_id": sd.deny_event_id})
    assert result["status"] == "ok", result
    assert result["mode"] == "lookup_only"
    assert "structured_deny" in result
    assert "guidance" in result


def test_classify_deny_mcp_agent_classified_applies_safety_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent says 'appears_legitimate' for a known-adversarial action
    (``iam:CreateAccessKey`` — listed in KNOWN_ADVERSARIAL_PATTERNS) →
    the deterministic backstop MUST override to 'appears_adversarial'
    + advisory_action='escalate'. The agent's LLM cannot soften the
    safety floor."""
    from iam_jit.structured_deny import build_structured_deny, classify_deny_for_mcp

    _stub_fetch_with_one_row(monkeypatch, action="iam:CreateAccessKey")
    sd = build_structured_deny(
        bouncer="ibounce",
        action="iam:CreateAccessKey",
        resource="*",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
        when="2026-05-23T10:00:00Z",
    )
    result = classify_deny_for_mcp({
        "deny_event_id": sd.deny_event_id,
        "classification": INJECTION_APPEARS_LEGITIMATE,
        "confidence": 0.9,
        "reasoning": "test agent says this is fine",
    })
    assert result["status"] == "ok"
    assert result["classification"] == INJECTION_APPEARS_ADVERSARIAL
    assert result["advisory_action"] == "escalate"
    assert result["deterministic_backstop_fired"] is True
    # Reasoning preserved but prefixed with backstop annotation.
    assert "backstop" in result["reasoning"].lower()


def test_classify_deny_mcp_agent_classified_legitimate_returns_easy_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent says high-confidence legitimate for a non-destructive
    action → advisory_action is easy-allow (no backstop override)."""
    from iam_jit.structured_deny import build_structured_deny, classify_deny_for_mcp

    _stub_fetch_with_one_row(monkeypatch, action="s3:GetObject")
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
        when="2026-05-23T10:00:00Z",
    )
    result = classify_deny_for_mcp({
        "deny_event_id": sd.deny_event_id,
        "classification": INJECTION_APPEARS_LEGITIMATE,
        "confidence": 0.95,
        "reasoning": "operator's normal pattern is s3:GetObject on cache",
    })
    assert result["status"] == "ok"
    assert result["classification"] == INJECTION_APPEARS_LEGITIMATE
    assert result["advisory_action"] == "easy-allow"
    assert result["deterministic_backstop_fired"] is False


def _stub_fetch_with_one_row(
    monkeypatch: pytest.MonkeyPatch, *, action: str
) -> None:
    """Make fetch_recent_denies return a single deny row matching the
    test action so classify_deny_for_mcp finds it."""

    class _Row:
        def __init__(self) -> None:
            self.bouncer = "ibounce"
            self.action = action
            if action == "iam:CreateAccessKey":
                self.resource = "*"
            elif action.startswith("s3:"):
                self.resource = "arn:aws:s3:::cache"
            else:
                self.resource = "*"
            self.deny_reason = "profile 'safe-default'"
            self.deny_source = "static_profile"
            self.rule_id_if_dynamic = None
            self.suggested_allow_command = ""
            self.agent_session_id = ""
            self.when = "2026-05-23T10:00:00Z"

    def _fake_fetch(*, since=None, agent_session_id=None, limit=200):
        return [_Row()], []

    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        _fake_fetch,
    )
