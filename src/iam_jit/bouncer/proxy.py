"""Bouncer Stage 2 — transparent HTTP proxy that intercepts AWS SDK
calls via ``AWS_ENDPOINT_URL=http://127.0.0.1:<port>``.

Slice 1 of the proxy work (per http-proxy-pre-launch). This slice
ships:
  - the aiohttp-based HTTP server
  - request parsing via the existing bouncer.request_parser
  - per-request audit logging (no forwarding yet — Slice 2)
  - mode enum + advisory-vs-enforce decision shaping

Per bouncer-both-modes-first-class: the server supports both
cooperative (advisory) and transparent (enforce) modes as first-
class user choices. Slice 1 wires the mode plumbing; later slices
add the forwarding layer + HTTPS + edge cases.

What this module does NOT do yet (later slices):
  - Forward allowed requests to real AWS (Slice 2)
  - HTTPS / MITM cert handling (Slice 4)
  - Connection pooling + streaming + per-region routing (Slice 5)
  - bouncer_active_mode / bouncer_recommend_mode_for_task MCP
    tools (Slices 3 + 6)

The Slice 1 server is useful on its own as an OBSERVABILITY tool:
point an SDK client at it and you get a parsed log of every call
the client would make, complete with the bouncer's verdict for
each, without actually forwarding. Useful for "what does my
boto3 script ACTUALLY call?" inspection.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as _dt
import enum
import logging
from typing import TYPE_CHECKING, Any

from .decisions import DecisionRecord, DefaultPolicy, Mode, decide
from .request_parser import parse_request
from .rules import RuleSet

if TYPE_CHECKING:
    from .store import BouncerStore

logger = logging.getLogger(__name__)


class ProxyMode(str, enum.Enum):
    """Which kind of guardrail the proxy runs.

    Per bouncer-both-modes-first-class these are first-class user
    choices, not v1.0/v1.1 phases. The user picks at deployment
    time; per-task scope can override.
    """

    COOPERATIVE = "cooperative"
    """Advisory mode. Every call is parsed + logged + a verdict is
    computed, but every call is ALSO forwarded to AWS (Slice 2)
    regardless of the verdict. Useful for: solo dev iterating fast,
    debugging the bouncer itself, observability without enforcement,
    pre-flip preview of what TRANSPARENT mode would block."""

    TRANSPARENT = "transparent"
    """Enforcement mode. DENY verdicts return 403 to the SDK client
    without forwarding. ALLOW verdicts forward verbatim. PROMPT
    verdicts block + interactive prompt (later slices). Useful for:
    locked-down-IAM-dev environments, compliance-sensitive deploys,
    agent-safety-critical sessions."""


@dataclasses.dataclass(frozen=True)
class ProxyConfig:
    """Runtime config for the proxy server. Built from CLI flags +
    env + ProxyMode."""

    host: str = "127.0.0.1"
    port: int = 8767
    mode: ProxyMode = ProxyMode.COOPERATIVE
    default_policy: DefaultPolicy = DefaultPolicy.DENY
    # Don't bind to 0.0.0.0 by default — proxy is a LOCAL-ONLY
    # thing per the local-only-safety-mode + no-hosted-saas memos.
    # Binding externally would silently expose a credential-handling
    # surface to the network.


@dataclasses.dataclass
class RequestObservation:
    """What the proxy observed + decided about one inbound HTTP
    request. Slice 1 surfaces this so callers (tests + future
    forwarding layer) can inspect verdicts without parsing logs."""

    at: str
    method: str
    host: str
    path: str
    parsed_service: str | None
    parsed_action: str | None
    parsed_region: str | None
    parsed_arn: str | None
    decision_verdict: str
    decision_reason: str
    mode_at_decision: str
    enforced: bool
    """In COOPERATIVE mode, even a DENY verdict has enforced=False
    (advisory only). In TRANSPARENT mode, DENY verdicts have
    enforced=True (would 403 the SDK client). Useful for the
    audit-log + the eventual recommender."""


def _build_observation(
    *,
    method: str,
    host: str,
    path: str,
    parsed,  # ParsedRequest | None
    record: DecisionRecord,
    mode: ProxyMode,
) -> RequestObservation:
    """Compose the observation surfaced to callers + audit log."""
    enforced = (
        mode == ProxyMode.TRANSPARENT
        and record.decision.value in ("deny", "prompt")
    )
    return RequestObservation(
        at=_dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z"),
        method=method,
        host=host,
        path=path,
        parsed_service=parsed.service if parsed else None,
        parsed_action=parsed.action if parsed else None,
        parsed_region=parsed.region if parsed else None,
        parsed_arn=getattr(parsed, "arn", None) if parsed else None,
        decision_verdict=record.decision.value,
        decision_reason=record.reason,
        mode_at_decision=mode.value,
        enforced=enforced,
    )


def evaluate_request(
    *,
    method: str,
    host: str,
    path: str,
    headers: dict[str, str],
    body: bytes | str | None,
    query: dict[str, str] | None,
    store: BouncerStore,
    mode: ProxyMode,
    default_policy: DefaultPolicy = DefaultPolicy.DENY,
) -> RequestObservation:
    """Pure-function evaluation of one inbound proxy request.

    Slice 1's core unit: given the HTTP request parts, parse it,
    run it through the bouncer's rule engine, and return a
    RequestObservation that captures verdict + whether it would be
    ENFORCED in the current mode.

    The forwarding layer (Slice 2) consumes this observation:
    - mode=COOPERATIVE + any verdict → always forward
    - mode=TRANSPARENT + ALLOW → forward
    - mode=TRANSPARENT + DENY → return 403 to client
    - mode=TRANSPARENT + PROMPT → block, surface to user (later)

    Side effect: writes the decision to the store's audit log just
    like `iam-jit-bouncer decide --record` does, so post-hoc review
    of "what was the proxy doing 10 minutes ago?" works the same
    way `tasks review` does.
    """
    parsed = parse_request(
        method=method, host=host, path=path,
        headers=headers, body=body, query=query,
    )
    if parsed is None:
        # Bouncer can't classify (no SigV4 auth header) — this is
        # not a normal AWS SDK request. Surface a synthetic deny
        # observation so the forwarding layer can refuse.
        from .decisions import Decision  # local import: small enum, avoid module-load cycle risk
        # Always Mode.ENFORCE in the decision record so the verdict
        # surfaced matches the unified "compute as if enforcing"
        # semantics in evaluate_request below. `enforced` (set in
        # _build_observation) is what tells callers whether the
        # transparent-mode 403 actually fires.
        synthetic = DecisionRecord(
            decision=Decision.DENY,
            mode=Mode.ENFORCE,
            service="",
            action="",
            arn=None,
            region=None,
            matched_rule=None,
            reason="unclassifiable request — no SigV4 auth header",
        )
        return _build_observation(
            method=method, host=host, path=path,
            parsed=None, record=synthetic, mode=mode,
        )

    # Compose the active ruleset (global rules + active task scope)
    id_tagged = store.list_rules()
    ruleset = RuleSet(rules=[r for _, r in id_tagged])
    active_task = store.get_active_task()

    # ALWAYS compute the verdict with ENFORCE semantics. The
    # COOPERATIVE-vs-TRANSPARENT distinction lives entirely in the
    # `enforced` flag (set by _build_observation) + the forwarding
    # layer (Slice 2) consults that flag to decide whether to 403
    # the client or just log + forward.
    #
    # Why not use LEARN mode internally? LEARN auto-allows
    # everything by design — useful for the original "watch what
    # happens" workflow, but DEFEATS the cooperative-mode use
    # case where the user wants to PREVIEW what transparent mode
    # would deny without flipping the switch. With ENFORCE
    # semantics here, cooperative-mode logs show real deny verdicts
    # the user can act on; the actual forwarding still happens
    # because `enforced` is False.
    record = decide(
        ruleset,
        mode=Mode.ENFORCE,
        default_policy=default_policy,
        service=parsed.service,
        action=parsed.action,
        arn=getattr(parsed, "arn", None),
        region=parsed.region,
        active_task=active_task,
    )

    # Audit log every proxy decision (always; both modes).
    matched_rule_id: int | None = None
    if record.matched_rule is not None:
        for rid, r in id_tagged:
            if r == record.matched_rule:
                matched_rule_id = rid
                break
    try:
        store.record_decision(
            record,
            matched_rule_id=matched_rule_id,
            task_id=active_task.task_id if active_task is not None else None,
        )
    except Exception as e:
        # Audit-write failure is a high-priority signal; log it but
        # don't crash the proxy. (The opt-in-feedback pipeline can
        # report this category when enabled per opt-in-feedback-pipeline.)
        logger.warning("bouncer-proxy audit-write failed: %s", e)

    return _build_observation(
        method=method, host=host, path=path,
        parsed=parsed, record=record, mode=mode,
    )


# ---------------------------------------------------------------------------
# aiohttp server (Slice 1: observability-only; Slice 2 adds forwarding)
# ---------------------------------------------------------------------------


async def _handle_request(request, *, store, config: ProxyConfig):
    """aiohttp handler for any inbound request. Slice 1 returns the
    observation as JSON so the client (and tests) can verify what
    the proxy saw + decided. Slice 2 will replace the JSON body
    with the actual forwarded AWS response on ALLOW + advisory."""
    from aiohttp import web

    body = await request.read()
    obs = evaluate_request(
        method=request.method,
        host=request.headers.get("host", ""),
        path=request.path_qs,
        headers=dict(request.headers),
        body=body,
        query=dict(request.query),
        store=store,
        mode=config.mode,
        default_policy=config.default_policy,
    )

    # Slice 1 behavior: always return the observation as JSON. This
    # is "advisory" for the SDK client — it will NOT understand the
    # response and the call will fail at the client. Slice 2 will:
    #   - On ALLOW (cooperative or transparent): forward + return
    #     the real AWS response
    #   - On DENY in transparent: return a 403 with iam-jit reason
    #   - On DENY in cooperative: forward anyway (advisory verdict
    #     logged, no enforcement at the wire)
    status = 403 if obs.enforced else 200
    return web.json_response(
        {
            "proxy_observation": dataclasses.asdict(obs),
            "_slice1_note": (
                "Slice 1 returns observations only. Forwarding ships "
                "in Slice 2; until then the SDK client will see this "
                "JSON body and fail to parse it as an AWS response."
            ),
        },
        status=status,
    )


async def serve(config: ProxyConfig, *, store: BouncerStore) -> None:
    """Run the proxy server until cancelled.

    Slice 1: aiohttp app with one catch-all handler. Slice 2 will
    add request forwarding + per-region endpoint resolution.
    """
    try:
        from aiohttp import web
    except ImportError as e:
        raise RuntimeError(
            "aiohttp is required for the bouncer HTTP proxy. "
            "Install it: pip install 'aiohttp>=3.9'"
        ) from e

    app = web.Application()

    async def handler(request):
        return await _handle_request(request, store=store, config=config)

    app.router.add_route("*", "/{tail:.*}", handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.host, config.port)
    await site.start()
    logger.info(
        "iam-jit-bouncer proxy listening on http://%s:%s (mode=%s)",
        config.host, config.port, config.mode.value,
    )
    logger.info(
        "Point your SDK at it: AWS_ENDPOINT_URL=http://%s:%s "
        "(Slice 1: returns observations only; forwarding in Slice 2)",
        config.host, config.port,
    )

    # Block forever (until task cancellation)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
