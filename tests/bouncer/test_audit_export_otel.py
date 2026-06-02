"""Tests for the OpenTelemetry GenAI-span exporter — #720 / ADOPT-6.

Coverage:
  * event -> span attribute mapping correctness (gen_ai.* + iam_jit.*),
    asserted against spans captured by the OTel SDK's in-memory exporter.
  * span name + kind + status (enforced deny -> ERROR; allow / advisory
    deny -> UNSET).
  * same-session decisions thread onto one synthetic trace; different
    sessions get different traces.
  * default-OFF: the proxy wiring no-ops when otel_enabled is False.
  * OTel-absent graceful no-op: construction raises OTelDependencyError
    (no crash); otel_available() reports False.
  * fail-soft: a broken span emit is counted on status() + never raises
    out of export().
"""

from __future__ import annotations

import builtins

import pytest

pytest.importorskip("opentelemetry", reason="requires the optional [otel] extra")

from iam_jit.bouncer.audit_export import (
    GENAI_SEMCONV_VERSION,
    OTelDependencyError,
    OTelSpanExporter,
    event_to_span_fields,
    otel_available,
)

# The SDK's in-memory exporter is the canonical test capture surface.
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)


def _decision_event(
    *,
    decision_id: int = 1,
    operation: str = "s3:GetObject",
    service: str = "s3",
    verdict: str = "ALLOW",
    enforced: bool = False,
    mode: str = "cooperative",
    profile: str = "safe-default",
    session_id: str | None = "sess-abc",
    agent_name: str | None = "Claude Code",
    region: str | None = "us-east-1",
    arn: str | None = "arn:aws:s3:::bucket/key",
    status_detail: str = "",
    activity_id: int = 2,
    status_id: int = 1,
    event_type: str | None = None,
) -> dict:
    """Build a minimal OCSF-shaped decision event for the mapper."""
    agent = {}
    if agent_name is not None:
        agent["name"] = agent_name
    if session_id is not None:
        agent["session_id"] = session_id
    ij: dict = {
        "mode": mode,
        "profile": profile,
        "verdict": verdict,
        "decision_id": decision_id,
        "enforced": enforced,
        "ext": {"aws_region": region} if region else {},
    }
    if agent:
        ij["agent"] = agent
    if event_type:
        ij["event_type"] = event_type
    return {
        "metadata": {"product": {"name": "ibounce"}},
        "time": 1_700_000_000_000 + decision_id,
        "activity_id": activity_id,
        "status_id": status_id,
        "status_detail": status_detail,
        "api": {"operation": operation, "service": {"name": service}},
        "resources": [{"uid": arn}] if arn else [],
        "unmapped": {"iam_jit": ij},
    }


def _make_exporter() -> tuple[OTelSpanExporter, InMemorySpanExporter]:
    mem = InMemorySpanExporter()
    exp = OTelSpanExporter(_span_exporter=mem, _synchronous=True)
    exp.start()
    return exp, mem


# ---------------------------------------------------------------------------
# Pure mapping
# ---------------------------------------------------------------------------


def test_mapping_genai_conventional_attrs():
    f = event_to_span_fields(
        _decision_event(operation="ec2:TerminateInstances", service="ec2")
    )
    a = f["attributes"]
    assert f["name"] == "execute_tool ec2:TerminateInstances"
    # GenAI conventional attributes.
    assert a["gen_ai.operation.name"] == "execute_tool"
    assert a["gen_ai.tool.name"] == "ec2:TerminateInstances"
    assert a["gen_ai.tool.type"] == "iam-jit.bouncer.aws_api"
    assert a["gen_ai.tool.call.id"] == "1"
    assert a["gen_ai.agent.name"] == "Claude Code"
    assert a["gen_ai.agent.id"] == "sess-abc"
    # session id is the conversation correlation slot.
    assert a["gen_ai.conversation.id"] == "sess-abc"


def test_mapping_iam_jit_namespaced_extras():
    f = event_to_span_fields(
        _decision_event(
            verdict="DENY",
            enforced=True,
            mode="transparent",
            profile="readonly",
            status_detail="profile denies write",
            operation="s3:DeleteObject",
            service="s3",
            activity_id=4,
            status_id=2,
        )
    )
    a = f["attributes"]
    # Bouncer specifics live under iam_jit.* — NEVER misused conventional
    # attrs.
    assert a["iam_jit.verdict"] == "DENY"
    assert a["iam_jit.mode"] == "transparent"
    assert a["iam_jit.profile"] == "readonly"
    assert a["iam_jit.enforced"] is True
    assert a["iam_jit.reason"] == "profile denies write"
    assert a["iam_jit.product"] == "ibounce"
    assert a["iam_jit.decision_id"] == 1
    assert a["iam_jit.aws.service"] == "s3"
    assert a["iam_jit.aws.action"] == "DeleteObject"
    assert a["iam_jit.aws.region"] == "us-east-1"
    assert a["iam_jit.aws.resource_arn"] == "arn:aws:s3:::bucket/key"
    assert a["iam_jit.ocsf.activity_id"] == 4
    assert a["iam_jit.ocsf.status_id"] == 2
    assert a["iam_jit.semconv.genai_version"] == GENAI_SEMCONV_VERSION


def test_mapping_does_not_set_provider_or_model():
    # Honest: the bouncer is not a GenAI model provider, so we must NOT
    # emit provider/model/token attributes.
    f = event_to_span_fields(_decision_event())
    a = f["attributes"]
    for forbidden in (
        "gen_ai.provider.name",
        "gen_ai.system",
        "gen_ai.request.model",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
    ):
        assert forbidden not in a, f"must not set {forbidden}"


def test_mapping_no_none_attributes():
    # OTel rejects None attribute values; the mapper must drop them.
    f = event_to_span_fields(
        _decision_event(
            session_id=None, agent_name=None, region=None, arn=None
        )
    )
    assert all(v is not None for v in f["attributes"].values())
    # With no session, there's no correlation id.
    assert "gen_ai.conversation.id" not in f["attributes"]
    assert f["trace_id"] is None


def test_enforced_deny_is_error_others_unset():
    deny = event_to_span_fields(
        _decision_event(verdict="DENY", enforced=True)
    )
    assert deny["is_error"] is True
    assert deny["error_type"] == "iam_jit.deny"
    # Advisory deny (cooperative mode, not enforced) is NOT an error —
    # the upstream call succeeded; we only flagged it.
    advisory = event_to_span_fields(
        _decision_event(verdict="DENY", enforced=False)
    )
    assert advisory["is_error"] is False
    # Allow is success (UNSET).
    allow = event_to_span_fields(_decision_event(verdict="ALLOW"))
    assert allow["is_error"] is False


# ---------------------------------------------------------------------------
# End-to-end via in-memory span exporter
# ---------------------------------------------------------------------------


def test_export_emits_span_with_conventional_attrs():
    exp, mem = _make_exporter()
    try:
        exp.export(_decision_event(operation="s3:GetObject"))
    finally:
        spans = mem.get_finished_spans()
        exp.stop()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "execute_tool s3:GetObject"
    # tool-execution span kind is INTERNAL.
    assert span.kind.name == "INTERNAL"
    assert span.attributes["gen_ai.operation.name"] == "execute_tool"
    assert span.attributes["gen_ai.tool.name"] == "s3:GetObject"
    assert span.status.status_code.name == "UNSET"
    assert exp.status()["total_events"] == 1
    assert exp.status()["dropped_events"] == 0


def test_export_enforced_deny_sets_error_status():
    exp, mem = _make_exporter()
    try:
        exp.export(
            _decision_event(verdict="DENY", enforced=True, status_id=2)
        )
    finally:
        spans = mem.get_finished_spans()
        exp.stop()
    assert len(spans) == 1
    span = spans[0]
    assert span.status.status_code.name == "ERROR"
    assert span.attributes["error.type"] == "iam_jit.deny"


def test_same_session_shares_trace_distinct_sessions_differ():
    exp, mem = _make_exporter()
    try:
        exp.export(_decision_event(decision_id=1, session_id="A"))
        exp.export(_decision_event(decision_id=2, session_id="A"))
        exp.export(_decision_event(decision_id=3, session_id="B"))
    finally:
        spans = mem.get_finished_spans()
        exp.stop()
    by_session = {}
    for s in spans:
        by_session.setdefault(
            s.attributes["gen_ai.conversation.id"], set()
        ).add(s.context.trace_id)
    # Session A's two decisions thread onto exactly one trace.
    assert len(by_session["A"]) == 1
    # Session B is a different trace.
    assert by_session["A"] != by_session["B"]


def test_same_session_trace_id_deterministic():
    # A stable session id always derives the same trace id (replayable).
    f1 = event_to_span_fields(_decision_event(session_id="stable"))
    f2 = event_to_span_fields(_decision_event(session_id="stable"))
    assert f1["trace_id"] == f2["trace_id"]
    assert f1["trace_id"] != 0


# ---------------------------------------------------------------------------
# Default-off no-op (proxy wiring)
# ---------------------------------------------------------------------------


def test_default_off_proxy_no_op():
    # When no exporter is registered, the proxy emit path must not touch
    # OTel at all. We assert the module-level slot defaults to None.
    from iam_jit.bouncer import proxy

    # Fresh import state: the global defaults to None (default OFF).
    assert proxy._otel_span_exporter is None
    # And the emit path is a clean no-op (no exception) with it None.
    proxy._emit_audit_event_raw(_decision_event())


def test_register_and_clear_exporter():
    from iam_jit.bouncer import proxy

    exp, mem = _make_exporter()
    try:
        proxy.register_otel_span_exporter(exp)
        assert proxy._otel_span_exporter is exp
        proxy._emit_audit_event_raw(_decision_event(operation="s3:ListBucket"))
        spans = mem.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "execute_tool s3:ListBucket"
    finally:
        proxy.register_otel_span_exporter(None)
        exp.stop()
    assert proxy._otel_span_exporter is None


# ---------------------------------------------------------------------------
# Fail-soft
# ---------------------------------------------------------------------------


def test_export_failsoft_on_emit_error():
    exp, mem = _make_exporter()
    try:
        # Break the tracer so _emit_span raises; export() must swallow +
        # count it, NOT raise.

        class _Boom:
            def start_span(self, *a, **k):
                raise RuntimeError("boom")

        exp._tracer = _Boom()
        # Must not raise.
        exp.export(_decision_event())
        st = exp.status()
        assert st["dropped_events"] == 1
        assert st["total_events"] == 0
        assert "boom" in (st["last_error"] or "")
    finally:
        exp.stop()


def test_export_before_start_is_noop():
    mem = InMemorySpanExporter()
    exp = OTelSpanExporter(_span_exporter=mem, _synchronous=True)
    # Not started — export is a clean no-op.
    exp.export(_decision_event())
    assert mem.get_finished_spans() == ()


def test_stop_is_idempotent():
    exp, mem = _make_exporter()
    exp.stop()
    exp.stop()  # second stop must not raise


# ---------------------------------------------------------------------------
# OTel-absent graceful no-op
# ---------------------------------------------------------------------------


def test_otel_available_true_when_installed():
    # In the test env the SDK IS installed.
    assert otel_available() is True


def test_construction_raises_clean_error_when_otel_absent(monkeypatch):
    # Simulate the optional packages being absent: make any import of an
    # opentelemetry.* module raise ImportError, then assert construction
    # raises OTelDependencyError (a clean, message-bearing error) rather
    # than crashing. No importlib.reload — the import guard in the module
    # is evaluated lazily inside otel_available() / _import_otel(), so
    # patching the importer is sufficient + doesn't poison class identity
    # for other tests.
    import iam_jit.bouncer.audit_export.otel as otel_mod

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name.startswith("opentelemetry"):
            raise ImportError(f"simulated-absent: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    # otel_available() re-probes the import under the patched importer.
    assert otel_mod.otel_available() is False
    with pytest.raises(OTelDependencyError) as ei:
        OTelSpanExporter(endpoint="http://localhost:4318")
    assert "[otel]" in str(ei.value)


def test_unsupported_protocol_rejected():
    with pytest.raises(OTelDependencyError):
        OTelSpanExporter(endpoint="x", protocol="carrier-pigeon")
