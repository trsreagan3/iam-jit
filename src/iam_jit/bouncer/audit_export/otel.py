"""OpenTelemetry GenAI-span exporter — #720 / ADOPT-6.

Channel N of the audit-export transport. Where the other channels ship
the OCSF event verbatim (JSONL log / HTTPS webhook / object storage /
Security Lake), this one MAPS each bouncer decision onto an
OpenTelemetry span that follows the **GenAI semantic conventions**
(`gen_ai.*` attribute namespace) and exports it via OTLP. An operator
who already runs OpenTelemetry sees bouncer decisions as spans/traces
in their existing stack (Datadog / Honeycomb / Grafana / Jaeger / ...)
WITHOUT writing a custom mapping layer — this is the "debug a hung
agent" buyer path: bouncer activity shows up inline next to the
agent's own GenAI traces.

Conventions followed
--------------------
OpenTelemetry GenAI semantic conventions, **Development** status
(tracked at https://opentelemetry.io/docs/specs/semconv/gen-ai/). The
GenAI conventions are not yet Stable; this exporter pins the subset it
emits via ``GENAI_SEMCONV_VERSION`` below so a downstream dashboard can
branch on it, and per the spec's stability-transition guidance the
attribute set here is additive (we never silently change a key's
meaning across a minor bump).

Each bouncer decision is a TOOL-EXECUTION span — the bouncer is gating
an agent's attempt to call a tool (an AWS API). So:

  * span name             ``execute_tool {gen_ai.tool.name}``
                          (the GenAI tool-execution naming template),
                          e.g. ``execute_tool s3:GetObject``.
  * span kind             ``INTERNAL`` (the convention's kind for
                          tool-execution spans).
  * ``gen_ai.operation.name`` = ``"execute_tool"``.
  * ``gen_ai.tool.name``  = the AWS ``service:action`` the agent tried
                          (the "tool" the agent invoked).
  * ``gen_ai.tool.type``  = ``"iam-jit.bouncer.aws_api"`` — honest: the
                          tool the bouncer guards is an AWS API call,
                          not a built-in GenAI function. We do NOT claim
                          ``"function"``.
  * ``gen_ai.tool.call.id`` = the bouncer decision id (the per-request
                          identifier the decision is keyed on).
  * ``gen_ai.agent.name`` = the resolved agent name (Claude Code,
                          codex, ...), when known.
  * ``gen_ai.agent.id``   = the agent session id, when known.
  * ``gen_ai.conversation.id`` = the agent session id (the convention's
                          slot for "session / thread used to correlate
                          messages"). Same value as agent.id by design —
                          the bouncer's unit of correlation IS the
                          session.

Honest namespacing per [[ibounce-honest-positioning]]
-----------------------------------------------------
The bouncer is NOT a GenAI model provider, so we deliberately do NOT
set ``gen_ai.provider.name`` / ``gen_ai.request.model`` / token-usage
attributes — inventing a provider name would mis-signal to a dashboard
that aggregates spend by provider. Everything specific to a bouncer
decision that has no conventional GenAI home lands under the
``iam_jit.*`` attribute namespace:

  * ``iam_jit.verdict``        ALLOW / DENY / PROMPT / ...
  * ``iam_jit.mode``           cooperative / transparent / ...
  * ``iam_jit.profile``        the active bounce profile name
  * ``iam_jit.enforced``       bool — was the upstream call actually
                               blocked (true) vs advisory-flagged (false)
  * ``iam_jit.reason``         the human-readable deny reason
  * ``iam_jit.product``        "ibounce" (cross-product dashboards)
  * ``iam_jit.decision_id``    the integer decision id
  * ``iam_jit.aws.service``    AWS service (s3, ec2, ...)
  * ``iam_jit.aws.action``     AWS action (GetObject, ...)
  * ``iam_jit.aws.region``     AWS region, when known
  * ``iam_jit.aws.resource_arn`` the targeted ARN, when known
  * ``iam_jit.ocsf.activity_id`` the OCSF activity_id (CRUD class)
  * ``iam_jit.ocsf.status_id``   the OCSF status_id

Span status follows the GenAI/OTel error-recording guidance: an
ENFORCED deny (the call was blocked) sets span status ERROR with
``error.type = "iam_jit.deny"``; everything else (allow, advisory
deny, pause-bypass) is left UNSET (the OTel default for success).
This keeps a Honeycomb "error rate" panel honest: it counts the calls
the bouncer actually blocked, not the ones it merely flagged.

Trace correlation
------------------
All spans for one agent session share a deterministic trace id derived
from the session id (a stable 128-bit hash) so every decision in a
session threads onto ONE trace — exactly what an operator wants when
debugging a hung agent. Events without a resolvable session id get
their own one-off trace (no correlation possible, but the span still
lands). This is best-effort correlation: we do not have the agent's
real upstream trace context (the bouncer sits out-of-band), so we
synthesise a stable trace id rather than claim a parent we can't see.

Optional / default-OFF / fail-soft
-----------------------------------
* The ``opentelemetry-sdk`` + OTLP exporter are an OPTIONAL extra
  (``pip install 'iam-jit[otel]'``). The base install stays lean. Every
  OTel import is guarded; when the libs are absent, ``OTelSpanExporter``
  construction raises ``OTelDependencyError`` with a clear pip hint —
  the CLI/serve layer turns that into a friendly message, never a crash.
* DEFAULT OFF per [[v1-scope-bar]] — the proxy only builds an exporter
  when the operator opts in (``--otel-endpoint`` / ``IAM_JIT_OTEL_*`` /
  ambient config). The standard OTel env vars
  (``OTEL_EXPORTER_OTLP_ENDPOINT`` etc.) are honoured by the underlying
  SDK exporter.
* FAIL-SOFT: ``export(event)`` NEVER blocks the proxy hot path and
  NEVER raises. Conversion + the OTel SDK live behind a try/except that
  records the error on the status counter and logs once. The OTel SDK's
  own ``BatchSpanProcessor`` does the off-thread, batched network I/O,
  so a slow/down collector can never stall a decision.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from typing import Any

logger = logging.getLogger(__name__)


# The slice of the GenAI semantic conventions this exporter targets.
# The GenAI conventions are in OTel "Development" status (not yet
# Stable); pin the version here so a downstream dashboard can branch on
# `iam_jit.semconv.genai_version` and so a future convention bump is a
# deliberate edit, not a silent drift. Tracks the conventions as of the
# 1.30.x semconv line (gen_ai tool/agent spans).
GENAI_SEMCONV_VERSION = "1.30.0"

# Default OTLP protocol when the operator doesn't pick one. http/protobuf
# is the most broadly-reachable (no extra grpc transport setup, works
# through proxies + most managed collectors).
DEFAULT_OTLP_PROTOCOL = "http/protobuf"
_VALID_PROTOCOLS = ("http/protobuf", "grpc")

# OTel resource service.name for the spans this exporter emits. An
# operator filtering their trace store by `service.name = "ibounce"`
# catches every bouncer span. Cross-product alignment per
# [[cross-product-agent-parity]]: kbounce/dbounce would use their own
# product name here; everything else about the span shape is identical.
DEFAULT_SERVICE_NAME = "ibounce"

# --- GenAI semantic-convention attribute keys (string literals so this
# module imports with zero OTel dep present; the SDK doesn't define a
# stable Python constant for the experimental gen_ai keys anyway). ---
_ATTR_GENAI_OPERATION_NAME = "gen_ai.operation.name"
_ATTR_GENAI_TOOL_NAME = "gen_ai.tool.name"
_ATTR_GENAI_TOOL_TYPE = "gen_ai.tool.type"
_ATTR_GENAI_TOOL_CALL_ID = "gen_ai.tool.call.id"
_ATTR_GENAI_AGENT_NAME = "gen_ai.agent.name"
_ATTR_GENAI_AGENT_ID = "gen_ai.agent.id"
_ATTR_GENAI_CONVERSATION_ID = "gen_ai.conversation.id"

# The GenAI tool-execution operation name + span-name prefix.
_OP_EXECUTE_TOOL = "execute_tool"

# iam-jit-namespaced extras (everything the bouncer knows that has no
# conventional GenAI home).
_ATTR_IJ_PRODUCT = "iam_jit.product"
_ATTR_IJ_VERDICT = "iam_jit.verdict"
_ATTR_IJ_MODE = "iam_jit.mode"
_ATTR_IJ_PROFILE = "iam_jit.profile"
_ATTR_IJ_ENFORCED = "iam_jit.enforced"
_ATTR_IJ_REASON = "iam_jit.reason"
_ATTR_IJ_DECISION_ID = "iam_jit.decision_id"
_ATTR_IJ_AWS_SERVICE = "iam_jit.aws.service"
_ATTR_IJ_AWS_ACTION = "iam_jit.aws.action"
_ATTR_IJ_AWS_REGION = "iam_jit.aws.region"
_ATTR_IJ_AWS_RESOURCE_ARN = "iam_jit.aws.resource_arn"
_ATTR_IJ_OCSF_ACTIVITY_ID = "iam_jit.ocsf.activity_id"
_ATTR_IJ_OCSF_STATUS_ID = "iam_jit.ocsf.status_id"
_ATTR_IJ_SEMCONV_VERSION = "iam_jit.semconv.genai_version"
_ATTR_IJ_EVENT_TYPE = "iam_jit.event_type"

# error.type value for an enforced deny (a blocked upstream call). Uses
# the iam_jit namespace so it's clearly OUR semantic, distinguishable
# from a transport/exception error.type a downstream might also see.
_ERROR_TYPE_DENY = "iam_jit.deny"


class OTelDependencyError(RuntimeError):
    """Raised at exporter-construction time when the optional
    ``opentelemetry-sdk`` / OTLP-exporter packages are not installed.

    Surfaced to the operator (at CLI parse / serve start) as a clear
    "this feature needs the [otel] extra" message + pip hint — never a
    silent no-op (the operator explicitly asked for OTel export) and
    never a crash deep in the hot path. Mirrors the WebhookLicenseError
    posture: fail LOUD at config time, fail SOFT at run time.
    """


def otel_available() -> bool:
    """Return True if the OTel SDK + at least one OTLP exporter import.

    Cheap probe used by the CLI to decide whether to even attempt
    construction (so the operator gets the friendly message before any
    span machinery spins up). Does not import the heavy bits eagerly
    beyond what's needed to answer the question.
    """
    try:  # noqa: SD-3 probe-only: ImportError here is the answer (deps absent), not an error to surface; the caller acts on the bool
        import opentelemetry.sdk.trace  # noqa: F401
        import opentelemetry.trace  # noqa: F401
    except Exception:
        return False
    return True


def _normalize_protocol(protocol: str | None) -> str:
    p = (protocol or DEFAULT_OTLP_PROTOCOL).strip().lower()
    if p in ("http", "http/json"):
        # We only ship the protobuf HTTP exporter; normalise the common
        # shorthand to it rather than silently failing later.
        p = "http/protobuf"
    if p not in _VALID_PROTOCOLS:
        raise OTelDependencyError(
            f"unsupported OTLP protocol {protocol!r}; expected one of "
            f"{_VALID_PROTOCOLS}"
        )
    return p


def _trace_id_from_session(session_id: str | None) -> int | None:
    """Derive a stable 128-bit trace id from an agent session id.

    Every decision in one session threads onto ONE trace so an operator
    debugging a hung agent sees the whole session as a single trace.
    Returns None when there's no session id (raw boto3 / pre-agent-
    identity events) — the caller then lets the SDK mint a fresh trace
    per span (no correlation possible, but the span still lands).

    SHA-256 over the session id, low 128 bits, forced non-zero (a
    zero trace id is invalid per the W3C trace-context spec). This is a
    SYNTHETIC trace id: the bouncer sits out-of-band and does not see
    the agent's real upstream trace context, so we never claim a parent
    span we can't observe.
    """
    if not session_id:
        return None
    digest = hashlib.sha256(session_id.encode("utf-8")).digest()
    tid = int.from_bytes(digest[:16], "big")
    if tid == 0:
        tid = 1
    return tid


def _span_id_from_decision(session_id: str | None, decision_id: Any) -> int | None:
    """Derive a stable 64-bit span id from (session, decision).

    Deterministic so a replay of the same event produces the same span
    id (idempotent-ish for dashboards). Returns None to let the SDK mint
    one when we don't have enough to derive a stable value. Forced
    non-zero (a zero span id is invalid)."""
    if decision_id is None:
        return None
    seed = f"{session_id or ''}:{decision_id}".encode("utf-8")
    sid = int.from_bytes(hashlib.sha256(seed).digest()[:8], "big")
    if sid == 0:
        sid = 1
    return sid


def event_to_span_fields(event: dict[str, Any]) -> dict[str, Any]:
    """Pure mapping: OCSF audit event -> the fields a GenAI span needs.

    Returns a dict with:
      * ``name``        the span name (``execute_tool {tool}``)
      * ``attributes``  the ``{gen_ai.*, iam_jit.*}`` attribute dict
                        (None values dropped — OTel rejects None attrs)
      * ``is_error``    bool — True iff this is an ENFORCED deny
      * ``error_type``  the error.type string when is_error, else None
      * ``trace_id``    synthetic trace id (or None)
      * ``span_id``     synthetic span id (or None)
      * ``time_unix_ns`` the event time in ns (or None -> "now")

    Separated from the exporter so it's trivially unit-testable without
    any OTel machinery, and so the mapping is the single source of truth
    the tests assert against.
    """
    ij = (
        event.get("unmapped", {}).get("iam_jit", {})
        if isinstance(event.get("unmapped"), dict)
        else {}
    )
    if not isinstance(ij, dict):
        ij = {}
    agent = ij.get("agent") if isinstance(ij.get("agent"), dict) else {}
    ext = ij.get("ext") if isinstance(ij.get("ext"), dict) else {}

    api = event.get("api", {}) if isinstance(event.get("api"), dict) else {}
    service_block = api.get("service", {}) if isinstance(api.get("service"), dict) else {}
    service = service_block.get("name") or ""
    operation = api.get("operation") or ""
    # `operation` is "service:Action"; split out the action half for the
    # AWS-namespaced extras. The tool name is the full operation.
    action = ""
    if ":" in operation:
        _svc_part, _, action = operation.partition(":")
        if not service:
            service = _svc_part
    else:
        action = operation

    tool_name = operation or service or "aws_api"
    session_id = agent.get("session_id") if isinstance(agent, dict) else None
    agent_name = agent.get("name") if isinstance(agent, dict) else None
    decision_id = ij.get("decision_id")
    verdict = ij.get("verdict")
    enforced = bool(ij.get("enforced"))

    # An ENFORCED deny is the only "error" — the upstream call was
    # blocked. Advisory denies, allows, pause-bypass are success (UNSET).
    v_norm = (verdict or "").strip().lower()
    is_error = v_norm == "deny" and enforced

    resource_arn = None
    resources = event.get("resources")
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            resource_arn = first.get("uid")

    reason = event.get("status_detail") or ""

    attributes: dict[str, Any] = {
        _ATTR_GENAI_OPERATION_NAME: _OP_EXECUTE_TOOL,
        _ATTR_GENAI_TOOL_NAME: tool_name,
        _ATTR_GENAI_TOOL_TYPE: "iam-jit.bouncer.aws_api",
        _ATTR_IJ_PRODUCT: (
            event.get("metadata", {}).get("product", {}).get("name")
            if isinstance(event.get("metadata"), dict)
            else None
        )
        or "ibounce",
        _ATTR_IJ_SEMCONV_VERSION: GENAI_SEMCONV_VERSION,
        _ATTR_IJ_ENFORCED: enforced,
    }
    # gen_ai.tool.call.id — the decision id is the per-call identifier.
    if decision_id is not None:
        attributes[_ATTR_GENAI_TOOL_CALL_ID] = str(decision_id)
        attributes[_ATTR_IJ_DECISION_ID] = decision_id
    # Agent identity -> gen_ai.agent.* + conversation.id.
    if agent_name:
        attributes[_ATTR_GENAI_AGENT_NAME] = agent_name
    if session_id:
        attributes[_ATTR_GENAI_AGENT_ID] = session_id
        attributes[_ATTR_GENAI_CONVERSATION_ID] = session_id
    # iam_jit.* extras.
    if verdict:
        attributes[_ATTR_IJ_VERDICT] = verdict
    if ij.get("mode"):
        attributes[_ATTR_IJ_MODE] = ij.get("mode")
    if ij.get("profile"):
        attributes[_ATTR_IJ_PROFILE] = ij.get("profile")
    if reason:
        attributes[_ATTR_IJ_REASON] = reason
    if service:
        attributes[_ATTR_IJ_AWS_SERVICE] = service
    if action:
        attributes[_ATTR_IJ_AWS_ACTION] = action
    region = ext.get("aws_region") if isinstance(ext, dict) else None
    if region:
        attributes[_ATTR_IJ_AWS_REGION] = region
    if resource_arn:
        attributes[_ATTR_IJ_AWS_RESOURCE_ARN] = resource_arn
    if event.get("activity_id") is not None:
        attributes[_ATTR_IJ_OCSF_ACTIVITY_ID] = event.get("activity_id")
    if event.get("status_id") is not None:
        attributes[_ATTR_IJ_OCSF_STATUS_ID] = event.get("status_id")
    # Synthetic / meta events (AUDIT_DROPPED, heartbeats, alerts) carry
    # an event_type marker — surface it so a dashboard can filter them
    # out of "real decision" panels.
    if ij.get("event_type"):
        attributes[_ATTR_IJ_EVENT_TYPE] = ij.get("event_type")

    # Drop any None-valued attributes (OTel rejects None; belt-and-braces
    # — the conditionals above already avoid most).
    attributes = {k: v for k, v in attributes.items() if v is not None}

    t = event.get("time")
    time_unix_ns = int(t) * 1_000_000 if isinstance(t, (int, float)) else None

    return {
        "name": f"{_OP_EXECUTE_TOOL} {tool_name}",
        "attributes": attributes,
        "is_error": is_error,
        "error_type": _ERROR_TYPE_DENY if is_error else None,
        "trace_id": _trace_id_from_session(session_id),
        "span_id": _span_id_from_decision(session_id, decision_id),
        "time_unix_ns": time_unix_ns,
    }


class OTelSpanExporter:
    """Convert each audit event to a GenAI span + export it via OTLP.

    Lifecycle::

        exporter = OTelSpanExporter(
            endpoint="https://otlp.honeycomb.io",
            protocol="http/protobuf",
            headers={"x-honeycomb-team": "..."},
        )
        exporter.start()
        exporter.export(event)   # never blocks, never raises
        exporter.stop()          # flushes the batch processor

    Construction raises ``OTelDependencyError`` when the optional OTel
    packages are absent — the caller turns that into a friendly message.
    Once started, ``export`` is fail-soft: a conversion bug or a span-
    emit failure is counted + logged, never raised into the hot path.
    The OTel ``BatchSpanProcessor`` owns the off-thread, batched network
    send so a slow collector can't stall a decision.
    """

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        protocol: str | None = None,
        headers: dict[str, str] | None = None,
        service_name: str = DEFAULT_SERVICE_NAME,
        # For tests: inject an in-memory span exporter so attribute
        # mapping can be captured + asserted without a real collector.
        # Production callers leave this None + the OTLP exporter is built.
        _span_exporter: Any | None = None,
        # For tests: use SimpleSpanProcessor (synchronous flush) instead
        # of BatchSpanProcessor so a captured span is visible immediately
        # without waiting for the batch timer.
        _synchronous: bool = False,
    ) -> None:
        self.endpoint = endpoint
        self.protocol = _normalize_protocol(protocol)
        self.headers = dict(headers) if headers else None
        self.service_name = service_name
        self._injected_span_exporter = _span_exporter
        self._synchronous = _synchronous

        self._provider: Any | None = None
        self._tracer: Any | None = None
        self._processor: Any | None = None
        self._started = False

        # Stats — mirrors the other sinks' status() shape so the MCP
        # status tool surfaces OTel health uniformly.
        self._lock = threading.Lock()
        self._total_events = 0
        self._dropped_events = 0
        self._last_error: str | None = None
        self._last_error_at_unix: float | None = None

        # Cache the OTel symbols we need; raises OTelDependencyError when
        # the optional packages aren't installed. Done in __init__ (not
        # lazily on first export) so the operator gets the dependency
        # error at config time, not mid-incident.
        self._otel = self._import_otel()

    @staticmethod
    def _import_otel() -> dict[str, Any]:
        """Import the OTel symbols. Raises OTelDependencyError (with a
        pip hint) when the optional packages are absent."""
        try:
            from opentelemetry.sdk.resources import SERVICE_NAME, Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import (
                BatchSpanProcessor,
                SimpleSpanProcessor,
            )
            from opentelemetry.trace import SpanKind, Status, StatusCode
        except Exception as e:  # ImportError + any transitive failure
            raise OTelDependencyError(
                "OpenTelemetry export requires the optional [otel] extra. "
                "Install it: pip install 'iam-jit[otel]' "
                "(opentelemetry-sdk + opentelemetry-exporter-otlp). "
                f"Import failed with: {e}"
            ) from e
        return {
            "Resource": Resource,
            "SERVICE_NAME": SERVICE_NAME,
            "TracerProvider": TracerProvider,
            "BatchSpanProcessor": BatchSpanProcessor,
            "SimpleSpanProcessor": SimpleSpanProcessor,
            "SpanKind": SpanKind,
            "Status": Status,
            "StatusCode": StatusCode,
        }

    def _build_otlp_exporter(self) -> Any:
        """Build the real OTLP span exporter for the configured protocol.

        Honours the standard OTel env vars (``OTEL_EXPORTER_OTLP_ENDPOINT``,
        ``OTEL_EXPORTER_OTLP_HEADERS``, ...) — when ``endpoint`` is None we
        pass nothing + let the SDK read the env. An explicit ``endpoint``
        wins over the env var.
        """
        kwargs: dict[str, Any] = {}
        if self.endpoint:
            kwargs["endpoint"] = self.endpoint
        if self.headers:
            kwargs["headers"] = self.headers
        if self.protocol == "grpc":
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
        else:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        return OTLPSpanExporter(**kwargs)

    def start(self) -> None:
        """Build the tracer provider + span processor + exporter.

        Idempotent. A failure here (e.g. a bad gRPC endpoint URL the SDK
        rejects at construction) records the error + raises — start
        failure is up front, mirroring the webhook SSRF-gate posture.
        Mid-flight failures (a down collector) are fail-soft inside the
        SDK's BatchSpanProcessor and never reach ``export``.
        """
        if self._started:
            return
        otel = self._otel
        resource = otel["Resource"].create(
            {otel["SERVICE_NAME"]: self.service_name}
        )
        provider = otel["TracerProvider"](resource=resource)
        if self._injected_span_exporter is not None:
            span_exporter = self._injected_span_exporter
        else:
            span_exporter = self._build_otlp_exporter()
        if self._synchronous:
            processor = otel["SimpleSpanProcessor"](span_exporter)
        else:
            processor = otel["BatchSpanProcessor"](span_exporter)
        provider.add_span_processor(processor)
        self._provider = provider
        self._processor = processor
        # Use a private tracer off OUR provider — we deliberately do NOT
        # call trace.set_tracer_provider() (the global), so wiring the
        # bouncer's OTel export never hijacks an operator's own global
        # tracer provider if they run one in-process.
        self._tracer = provider.get_tracer("iam_jit.bouncer.audit_export.otel")
        self._started = True

    def export(self, event: dict[str, Any]) -> None:
        """Convert one audit event to a span + hand it to the processor.

        NEVER blocks (the BatchSpanProcessor queues + sends off-thread).
        NEVER raises — a conversion bug or emit failure is counted +
        logged so the operator can spot misconfiguration, but the proxy
        hot path is unaffected. Mirrors WebhookPusher.push / the
        SessionRecorder.record fail-soft posture.
        """
        if not self._started or self._tracer is None:
            return
        try:
            self._emit_span(event)
            with self._lock:
                self._total_events += 1
        except Exception as e:  # noqa: SD-1 fail-soft per design: an OTel conversion/emit failure must never break the audit hot path; it's counted on status() + logged below so the operator can spot it
            with self._lock:
                self._dropped_events += 1
                self._last_error = f"otel export failed: {e}"
                import time as _time

                self._last_error_at_unix = _time.time()
            logger.warning("otel span export failed: %s", e)

    def _emit_span(self, event: dict[str, Any]) -> None:
        """Build + finish one span. Called only from ``export`` (inside
        its fail-soft guard)."""
        otel = self._otel
        fields = event_to_span_fields(event)

        ctx = self._span_context(fields["trace_id"], fields["span_id"])
        start_time = fields["time_unix_ns"]
        span = self._tracer.start_span(
            fields["name"],
            kind=otel["SpanKind"].INTERNAL,
            attributes=fields["attributes"],
            start_time=start_time,
            context=ctx,
        )
        if fields["is_error"]:
            # GenAI/OTel error-recording: set status ERROR + the
            # conventional error.type attribute so dashboards count
            # blocked calls in their error panels.
            span.set_attribute("error.type", fields["error_type"])
            span.set_status(otel["Status"](otel["StatusCode"].ERROR))
        # The decision is a point-in-time verdict; we don't model a
        # duration (the bouncer's evaluate is sub-ms). End immediately at
        # the same instant so the span is a near-zero-width marker on the
        # session's trace.
        span.end(end_time=start_time)

    def _span_context(self, trace_id: int | None, span_id: int | None) -> Any:
        """Build an explicit trace context so all spans for one session
        thread onto one synthetic trace. Returns None when we have no
        trace id (the SDK then mints a fresh trace per span)."""
        if trace_id is None:
            return None
        try:
            from opentelemetry import trace as _trace
            from opentelemetry.trace import (
                NonRecordingSpan,
                SpanContext,
                TraceFlags,
            )
        except Exception as e:
            logger.warning("otel trace-context build import failed: %s", e)
            return None  # noqa: SD-4 fail-soft + logged (not silent): these symbols already imported cleanly in _import_otel() at construction (SDK present) so this is unreachable-defensive; None is the function's documented "no correlation context -> SDK mints a fresh trace" signal — the span STILL lands, so it's a graceful degrade, not a swallowed failure
        # The parent span context carries the session-derived trace id.
        # We DON'T set a parent span id (the decision spans are siblings
        # under one trace, not nested) — but SpanContext needs a span id,
        # so reuse the trace-derived value as a stable synthetic parent.
        parent_span_id = span_id or (trace_id & 0xFFFFFFFFFFFFFFFF) or 1
        parent_ctx = SpanContext(
            trace_id=trace_id,
            span_id=parent_span_id,
            is_remote=True,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
        )
        return _trace.set_span_in_context(NonRecordingSpan(parent_ctx))

    def stop(self) -> None:
        """Flush + shut down the span processor + provider. Idempotent.

        Fail-soft: a flush failure (collector down at shutdown) is logged,
        never raised — mirrors the other sinks' teardown posture.
        """
        if not self._started:
            return
        try:
            if self._processor is not None:
                # force_flush drains the batch queue; shutdown closes the
                # exporter's transport.
                self._processor.force_flush()
        except Exception as e:
            logger.warning("otel processor force_flush failed: %s", e)
        try:
            if self._provider is not None:
                self._provider.shutdown()
        except Exception as e:
            logger.warning("otel provider shutdown failed: %s", e)
        self._started = False

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP status tool. Mirrors the other sinks."""
        with self._lock:
            return {
                "configured": True,
                "endpoint": self.endpoint or "(from OTEL_* env)",
                "protocol": self.protocol,
                "service_name": self.service_name,
                "genai_semconv_version": GENAI_SEMCONV_VERSION,
                "total_events": self._total_events,
                "dropped_events": self._dropped_events,
                "last_error": self._last_error,
                "last_error_at_unix": self._last_error_at_unix,
            }


__all__ = [
    "DEFAULT_OTLP_PROTOCOL",
    "DEFAULT_SERVICE_NAME",
    "GENAI_SEMCONV_VERSION",
    "OTelDependencyError",
    "OTelSpanExporter",
    "event_to_span_fields",
    "otel_available",
]
