"""Bouncer Stage 2 — transparent HTTP proxy that intercepts AWS SDK
calls via ``AWS_ENDPOINT_URL=http://127.0.0.1:<port>``.

Slices 1 + 2 of the proxy work (per http-proxy-pre-launch):
  - Slice 1: aiohttp-based HTTP server, SigV4 request parsing,
    per-request audit logging, mode enum + advisory-vs-enforce
    decision shaping
  - Slice 2: SigV4-preserving forwarding to real AWS endpoints,
    streaming responses, connection pooling

Per bouncer-both-modes-first-class: the server supports both
cooperative (advisory) and transparent (enforce) modes as first-
class user choices. Per `bouncer-mode-selection-for-agents`:
  - Cooperative + ALLOW: forward; log
  - Cooperative + DENY:  forward (advisory); log the would-be-deny
  - Transparent + ALLOW: forward; log
  - Transparent + DENY:  return 403 with iam-jit reason; don't forward

SigV4 forwarding rules (LOAD-BEARING):
  - The proxy NEVER re-signs requests. The client already signed
    with their secret key; we don't have (and don't want) access to
    that key. We forward the request verbatim, preserving headers,
    body, and the Authorization header that contains the SigV4
    signature.
  - The client signs against the ORIGINAL AWS Host header (e.g.
    s3.us-east-1.amazonaws.com), even though it connects to the
    proxy at 127.0.0.1:8767. We forward to the host the client
    signed against — the SigV4 signature validates correctly at
    AWS because Host matches.
  - The proxy listens on plain HTTP (no MITM TLS in Slice 2; that's
    Slice 4). The OUTBOUND forward is always HTTPS to real AWS.

What this module does NOT do yet (later slices):
  - MITM TLS for HTTPS-only SDK clients (Slice 4)
  - Connection-pool tuning + advanced streaming (Slice 5)
  - bouncer_active_mode / bouncer_recommend_mode_for_task MCP
    tools (Slices 3 + 6)
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import threading

# HIGH-32-05 mitigation counter: pause-lookup failures are caught
# + logged but the proxy continues to enforce. Without surfacing
# this, an operator who typed `pause start` thinks they have a
# bypass window, but the proxy keeps 403ing because the lookup
# silently fails. Counter is exposed on /healthz so monitors can
# alert on a non-zero value.
_pause_lookup_errors_lock = threading.Lock()
_pause_lookup_errors_total = 0


def _bump_pause_lookup_error_counter() -> None:
    global _pause_lookup_errors_total
    with _pause_lookup_errors_lock:
        _pause_lookup_errors_total += 1


def _pause_lookup_error_count() -> int:
    with _pause_lookup_errors_lock:
        return _pause_lookup_errors_total


def _reset_pause_lookup_error_counter_for_tests() -> None:
    """Reset hook for tests. Not part of the public surface."""
    global _pause_lookup_errors_total
    with _pause_lookup_errors_lock:
        _pause_lookup_errors_total = 0
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
    forward_scheme: str = "https"
    """Outbound scheme for forwarding allowed requests. Defaults to
    HTTPS (real AWS endpoints). Tests pass "http" to forward to a
    local mock-AWS server."""
    active_profile: Any = None
    """Slice 7: the resolved Profile object whose denies act as a
    hard floor above task/global rules. None or `Profile(name='full-user')`
    means no profile-level rules fire (existing behavior; `none` also
    resolves here for v1.0 backward-compat — see DEPRECATED_PROFILE_ALIASES
    in profiles.py)."""
    account_id: str | None = None
    account_alias: str | None = None
    """Account-id / alias used by profile.only_account_ids checks
    and keyword_targets that include 'account_alias'. Optional;
    profile rules that target these fields simply don't match when
    the values are None."""
    prompt_on_deny: bool = False
    """#5 v1.0 (async): when True, transparent-mode DENYs also
    write a pending_prompts row so the operator can later answer
    (always-allow / add-to-profile / ignore) via the `bouncer
    prompts` CLI. Async — the agent gets DENIED immediately; the
    operator's answer takes effect on the NEXT call of the same
    shape. v1.1 will add a synchronous mode where the proxy
    briefly waits for an answer before returning."""
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
    active_profile=None,  # type: profiles.Profile | None
    account_id: str | None = None,
    account_alias: str | None = None,
    prompt_on_deny: bool = False,
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
    like `ibounce decide --record` does, so post-hoc review
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
        # HIGH-32-01 closure: persist the unclassifiable-deny to the
        # audit log too. Otherwise an operator running `bouncer logs
        # tail` sees nothing for traffic that the proxy refused —
        # making it harder to spot scanners / probe traffic / mis-
        # configured clients.
        try:
            store.record_decision(
                synthetic, matched_rule_id=None, task_id=None,
            )
        except Exception as e:
            logger.warning(
                "bouncer-proxy unclassifiable audit-write failed: %s", e,
            )
        return _build_observation(
            method=method, host=host, path=path,
            parsed=None, record=synthetic, mode=mode,
        )

    # AWS Slice 7: profile is the HARD FLOOR. Evaluate BEFORE the
    # rule engine so a permissive task scope or global allow rule
    # CANNOT override a profile deny. Per the env-profiles spec:
    # profile keyword denies + only_account_ids + deny_verbs all
    # fire here; if a profile denies, short-circuit with
    # decision_source=profile so post-hoc audit can distinguish
    # profile-fired denies from task/global-fired denies.
    if active_profile is not None:
        from .decisions import Decision  # local import to avoid cycle
        from .profiles import evaluate_profile
        # The request_parser puts the synthesized AWS ARN on
        # `resource_hint` (not `arn`) — that's the field we feed
        # to the profile keyword check. Fall back to .arn if
        # present for forward-compat with parsers that set both.
        arn_for_profile = (
            getattr(parsed, "resource_hint", None)
            or getattr(parsed, "arn", None)
        )
        prof_verdict = evaluate_profile(
            active_profile,
            arn=arn_for_profile,
            resource_name=arn_for_profile,
            account_id=account_id,
            account_alias=account_alias,
            service=parsed.service,
            action=parsed.action,
        )
        if prof_verdict.denied:
            short_circuit = DecisionRecord(
                decision=Decision.DENY,
                mode=Mode.ENFORCE,
                service=parsed.service,
                action=parsed.action,
                arn=getattr(parsed, "arn", None),
                region=parsed.region,
                matched_rule=None,
                reason=prof_verdict.reason,
            )
            try:
                store.record_decision(short_circuit, matched_rule_id=None, task_id=None)
            except Exception as e:
                logger.warning("bouncer-proxy audit-write failed: %s", e)
            return _build_observation(
                method=method, host=host, path=path,
                parsed=parsed, record=short_circuit, mode=mode,
            )

    # Compose the active ruleset (global rules + active profile's
    # allow_rules + active task scope). Profile allow_rules sit at
    # the SAME precedence as global rules — they're "global rules
    # that are gated on this profile being active." They do NOT
    # bypass profile DENY layers above (already short-circuited by
    # this point if any fired). The profile-allow rules are appended
    # AFTER the global ruleset so a global DENY beats a profile
    # ALLOW (mirrors AWS IAM explicit-deny semantics).
    id_tagged = store.list_rules()
    composed_rules = [r for _, r in id_tagged]
    if active_profile is not None and active_profile.allow_rules:
        from .rules import Effect, ProxyRule
        for par in active_profile.allow_rules:
            composed_rules.append(ProxyRule(
                pattern=par.pattern,
                effect=Effect.ALLOW,
                arn_scope=par.arn_scope,
                region_scope=par.region_scope,
                note=par.note or f"from profile {active_profile.name}",
                origin="profile",
            ))
    ruleset = RuleSet(rules=composed_rules)
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
    # Resolve the ARN to feed into rule-matching. The request parser
    # places synthesized AWS ARNs on `resource_hint`; only the
    # explicit-IAM API parsers set `arn`. Prefer arn when present,
    # fall back to resource_hint so global rules + profile allow_rules
    # with arn_scope can actually match against S3/EC2/DynamoDB paths.
    resolved_arn = (
        getattr(parsed, "arn", None)
        or getattr(parsed, "resource_hint", None)
    )
    record = decide(
        ruleset,
        mode=Mode.ENFORCE,
        default_policy=default_policy,
        service=parsed.service,
        action=parsed.action,
        arn=resolved_arn,
        region=parsed.region,
        active_task=active_task,
    )

    # #6a — timed bypass / "pause." If an operator-initiated pause is
    # active, the proxy demotes effective behavior to COOPERATIVE for
    # this decision: the verdict text is preserved (so audit reviewers
    # see what WOULD have been denied) but enforcement is suspended.
    # The pause_id is recorded on the audit row so reviewers can ask
    # "what calls happened inside the pause window the operator
    # opened?" with a single SQL filter.
    #
    # Safety-mode-lean-permissive: the audit trail does the work; the
    # bypass is acceptable precisely because every decision during it
    # is recorded with pause_id linkage + the pause itself is its own
    # audit row. There is intentionally no "stealth pause" — every
    # pause has start/end audit rows.
    active_pause: dict | None = None
    try:
        active_pause = store.get_active_pause()
    except Exception as e:
        # HIGH-32-05 closure: bump a counter that /healthz exposes
        # so the operator's monitor can alert on "pause is supposedly
        # active but my proxy can't see it." Without this, the proxy
        # silently enforces through a window the operator thought
        # they had opened.
        _bump_pause_lookup_error_counter()
        logger.warning("bouncer-proxy pause-lookup failed: %s", e)
    effective_mode = mode
    if active_pause is not None and mode == ProxyMode.TRANSPARENT:
        effective_mode = ProxyMode.COOPERATIVE

    # Audit log every proxy decision (always; both modes).
    matched_rule_id: int | None = None
    if record.matched_rule is not None:
        for rid, r in id_tagged:
            if r == record.matched_rule:
                matched_rule_id = rid
                break
    decision_id: int = 0
    try:
        decision_id = store.record_decision(
            record,
            matched_rule_id=matched_rule_id,
            task_id=active_task.task_id if active_task is not None else None,
            pause_id=active_pause["id"] if active_pause is not None else None,
        )
    except Exception as e:
        # Audit-write failure is a high-priority signal; log it but
        # don't crash the proxy. (The opt-in-feedback pipeline can
        # report this category when enabled per opt-in-feedback-pipeline.)
        logger.warning("bouncer-proxy audit-write failed: %s", e)

    # #5 v1.0 (async): if operator opted into prompt-on-deny AND
    # this was a transparent-mode DENY (the only mode where DENY
    # actually blocks the agent), enqueue a pending prompt so the
    # operator can later answer (always-allow / add-to-profile /
    # ignore) via `bouncer prompts`. The agent has already been
    # denied; the answer takes effect on the NEXT call of the same
    # shape. v1.1 will add a synchronous flow.
    if (
        prompt_on_deny
        and decision_id > 0
        and mode == ProxyMode.TRANSPARENT
        and record.decision.value == "deny"
        and active_pause is None  # pauses already bypass enforcement
    ):
        try:
            store.add_pending_prompt(
                decision_id=decision_id,
                service=parsed.service,
                action=parsed.action,
                arn=resolved_arn,
                region=parsed.region,
                deny_reason=record.reason,
            )
        except Exception as e:
            logger.warning("bouncer-proxy prompt-enqueue failed: %s", e)

    return _build_observation(
        method=method, host=host, path=path,
        parsed=parsed, record=record, mode=effective_mode,
    )


# ---------------------------------------------------------------------------
# aiohttp server (Slice 1: observability-only; Slice 2 adds forwarding)
# ---------------------------------------------------------------------------


def _forward_url(host: str, path_qs: str, scheme: str = "https") -> str:
    """Build the outbound URL for forwarding.

    The client's SigV4 signature is over the ORIGINAL AWS Host header
    (e.g. `s3.us-east-1.amazonaws.com`). The client connects to the
    proxy at 127.0.0.1:PORT but signed with the AWS host. We forward
    to the AWS host so the signature validates downstream.

    `scheme` defaults to https because real AWS endpoints are HTTPS.
    Tests can pass scheme="http" to forward to a local mock-AWS.
    """
    # `host` may already include `:port`; preserve as-is.
    return f"{scheme}://{host}{path_qs}"


# CRIT-32-01 closure: outbound Host allowlist. The proxy receives
# its destination from the inbound Host header, which is attacker-
# controllable. Without this check, a compromised agent can set
# Host: attacker.example.com on its proxy connection and the proxy
# faithfully forwards the SigV4-signed body + AccessKeyId there.
# That makes the bouncer an exfil channel — the inverse of its
# promise.
#
# Allowlist strategy: accept the canonical AWS endpoint TLDs (cover
# commercial + GovCloud + China + .dev). Extra hosts can be added
# via IAM_JIT_BOUNCER_EXTRA_HOSTS (comma-separated suffix list) for
# LocalStack, tests, or special-purpose deployments. Test code
# passes `localhost` / `127.0.0.1:PORT` for the mock-AWS server;
# those match via the loopback exception below.
_AWS_HOST_SUFFIXES = (
    ".amazonaws.com",        # commercial AWS
    ".amazonaws.com.cn",     # AWS China
    ".amazonaws.us",         # AWS GovCloud
    ".api.aws",              # newer service domains
    ".aws.dev",              # AWS developer / preview domains
)


def _is_allowed_forward_host(host: str) -> bool:
    """True iff `host` is an AWS endpoint (or test loopback, or in
    the operator's IAM_JIT_BOUNCER_EXTRA_HOSTS allowlist).

    Strips an optional `:port` suffix; the comparison is on the
    bare DNS host. Case-insensitive (AWS endpoints are lowercase
    canonically but the SigV4 signature is normalized; some
    legitimate clients send mixed-case hosts).
    """
    if not host:
        return False
    bare = host.split(":", 1)[0].lower().rstrip(".")
    if not bare:
        return False
    # Loopback exception — tests + LocalStack default deploy use this
    if bare in ("127.0.0.1", "localhost", "::1"):
        return True
    if bare.startswith("127.") and bare.replace(".", "").isdigit():
        return True
    # AWS canonical TLDs
    for suffix in _AWS_HOST_SUFFIXES:
        if bare.endswith(suffix):
            return True
    # Operator-supplied extras (comma-separated suffix list)
    extras_env = os.environ.get("IAM_JIT_BOUNCER_EXTRA_HOSTS", "")
    for raw_suffix in extras_env.split(","):
        suffix = raw_suffix.strip().lower().lstrip(".")
        if not suffix:
            continue
        # Compare with leading dot so "evil.example.com" doesn't slip
        # past a "vil.example.com" allowlist entry by mistake.
        suffix_with_dot = "." + suffix
        if bare == suffix or bare.endswith(suffix_with_dot):
            return True
    return False


_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
})


def _strip_hop_headers(headers):
    """Remove RFC 7230 hop-by-hop headers + headers the upstream
    library will recompute. Returns a NEW container of the same
    shape (dict-in → dict-out, list-of-tuples-in → list-of-tuples-out).
    Doesn't mutate input.

    HIGH-32-04 (multi-value headers): callers should prefer the
    list-of-tuples form so duplicate header keys round-trip. The
    dict form is kept for backward compatibility with existing
    Slice 2 tests + tools.

    Hop-by-hop headers (RFC 7230 §6.1) must not be forwarded. The
    Host header is preserved because the client signed against it.
    Content-Length is dropped because aiohttp recomputes it from
    the body bytes.
    """
    if isinstance(headers, dict):
        return {
            k: v for k, v in headers.items()
            if k.lower() not in _HOP_HEADERS
        }
    # list-of-tuples / CIMultiDict.items() / other iterable
    return [
        (k, v) for (k, v) in headers
        if k.lower() not in _HOP_HEADERS
    ]


async def _forward_to_aws(
    *,
    method: str,
    host: str,
    path_qs: str,
    headers: dict[str, str],
    body: bytes,
    forward_scheme: str = "https",
    session,  # aiohttp.ClientSession
    timeout_s: float = 30.0,
):
    """Forward a SigV4-signed request to the real AWS endpoint and
    return (status, response_headers, response_body_bytes).

    LOAD-BEARING invariants:
    - Authorization header (SigV4 signature) is forwarded verbatim.
    - Host header is preserved.
    - Body bytes are forwarded as-is.
    - Hop-by-hop headers are stripped per RFC 7230.
    - Outbound scheme is HTTPS by default; tests override with HTTP.
    - The proxy NEVER re-signs the request. We don't have the
      client's secret key + don't want it.

    Returns response data tuple. Slice 2 reads the full response
    into memory; Slice 5 will add streaming for large objects.
    """
    import aiohttp

    forward_headers = _strip_hop_headers(headers)
    url = _forward_url(host, path_qs, scheme=forward_scheme)

    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with session.request(
        method=method,
        url=url,
        headers=forward_headers,
        data=body,
        timeout=timeout,
        allow_redirects=False,
        # Don't auto-decompress; client expects raw bytes.
        auto_decompress=False,
    ) as resp:
        resp_body = await resp.read()
        resp_headers = dict(resp.headers)
    return resp.status, resp_headers, resp_body


async def _handle_request(request, *, store, config: ProxyConfig, session):
    """aiohttp handler for inbound proxy requests.

    Slice 2 behavior:
      ALLOW (cooperative or transparent) → forward to AWS, return
        the AWS response verbatim
      DENY + TRANSPARENT → return 403 with iam-jit reason, no forward
      DENY + COOPERATIVE → forward anyway (advisory verdict logged,
        no enforcement at the wire)
      PROMPT (any mode) → Slice 2 treats as DENY for now; Slice 3
        will add interactive prompt UX
    """
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
        active_profile=config.active_profile,
        account_id=config.account_id,
        account_alias=config.account_alias,
        prompt_on_deny=config.prompt_on_deny,
    )

    if obs.enforced:
        # Transparent + (deny or prompt) → 403 without forwarding.
        # Body is ibounce-shaped JSON the SDK client won't parse as
        # an AWS error — that's intentional; the SDK will surface
        # the unparseable response as a client error. Slice 3 will
        # add an AWS-error-shaped body so SDK clients see a clean
        # AccessDenied with the iam-jit reason.
        return web.json_response(
            {
                "error": "ibounce DENY",
                "decision_verdict": obs.decision_verdict,
                "decision_reason": obs.decision_reason,
                "service": obs.parsed_service,
                "action": obs.parsed_action,
                "arn": obs.parsed_arn,
                "mode": obs.mode_at_decision,
            },
            status=403,
            # Wire-protocol response headers retain the
            # `x-iam-jit-bouncer-*` prefix for v1.0 to keep agents +
            # tooling that grep on them working unchanged. Renamed in
            # v1.1 alongside the env-var alignment pass.
            headers={"x-iam-jit-bouncer-verdict": obs.decision_verdict},
        )

    # Unclassifiable + cooperative mode is a tricky case — we can't
    # forward because we don't know where to forward to (no SigV4
    # host header to trust). Return 400.
    host_header = request.headers.get("host", "")
    if not obs.parsed_service or not host_header:
        return web.json_response(
            {
                "error": "ibounce cannot forward unclassifiable request",
                "decision_reason": obs.decision_reason,
                "hint": (
                    "request has no SigV4 Authorization header or no Host header; "
                    "the proxy can't determine the AWS endpoint to forward to."
                ),
            },
            status=400,
            headers={"x-iam-jit-bouncer-verdict": obs.decision_verdict},
        )

    # CRIT-32-01 closure: outbound Host allowlist. The Host header is
    # attacker-controllable; without this check, a compromised agent
    # can point the proxy at attacker.example.com and exfil the
    # SigV4-signed body + AccessKeyId.
    if not _is_allowed_forward_host(host_header):
        logger.warning(
            "ibounce refused forward to non-AWS host %r "
            "(service=%s action=%s)",
            host_header, obs.parsed_service, obs.parsed_action,
        )
        return web.json_response(
            {
                "error": "ibounce DENY (forward-host-mismatch)",
                "decision_reason": (
                    f"refused to forward to {host_header!r}: not an AWS "
                    f"endpoint. CRIT-32-01 protection. Set "
                    f"IAM_JIT_BOUNCER_EXTRA_HOSTS for legitimate non-AWS "
                    f"targets (LocalStack etc)."
                ),
                "service": obs.parsed_service,
                "action": obs.parsed_action,
                "attempted_host": host_header,
            },
            status=403,
            headers={
                "x-iam-jit-bouncer-verdict": "deny",
                "x-iam-jit-bouncer-refusal": "forward-host-mismatch",
            },
        )

    # ALLOW (either mode) OR cooperative+DENY → forward to AWS
    # HIGH-32-04 closure: aiohttp's request.headers is a CIMultiDict;
    # converting via dict() collapses duplicate keys to the last
    # value, which can break legitimate clients sending multi-value
    # headers (e.g. multiple `Forwarded:` headers via a proxy chain).
    # Pass as list-of-tuples instead so multi-values round-trip.
    try:
        status, resp_headers, resp_body = await _forward_to_aws(
            method=request.method,
            host=host_header,
            path_qs=request.path_qs,
            headers=list(request.headers.items()),
            body=body,
            forward_scheme=config.forward_scheme,
            session=session,
        )
    except Exception as e:
        # Forward failed (timeout, DNS, TLS, etc). Return 502 with
        # ibounce-shaped explanation.
        logger.warning("ibounce forward failed: %s", e)
        return web.json_response(
            {
                "error": "ibounce forward to AWS failed",
                "upstream_error": str(e),
                "service": obs.parsed_service,
                "action": obs.parsed_action,
            },
            status=502,
            headers={
                "x-iam-jit-bouncer-verdict": obs.decision_verdict,
                "x-iam-jit-bouncer-forward-error": "true",
            },
        )

    # Strip hop-by-hop from the AWS response too (RFC 7230) +
    # surface the bouncer's verdict in a debug header so users
    # debugging can see what the bouncer decided.
    out_headers = _strip_hop_headers(resp_headers)
    out_headers["x-iam-jit-bouncer-verdict"] = obs.decision_verdict
    out_headers["x-iam-jit-bouncer-mode"] = obs.mode_at_decision
    if obs.decision_verdict == "deny" and not obs.enforced:
        # Cooperative-mode advisory: surface that the bouncer WOULD
        # have denied this call in transparent mode.
        out_headers["x-iam-jit-bouncer-advisory"] = "would-deny-in-transparent"

    return web.Response(body=resp_body, status=status, headers=out_headers)


async def serve(config: ProxyConfig, *, store: BouncerStore) -> None:
    """Run the proxy server until cancelled.

    Slices 1 + 2: aiohttp app with one catch-all handler. The
    handler now FORWARDS allowed requests to real AWS (or to the
    forward_scheme'd endpoint for tests). A pooled aiohttp
    ClientSession is created at startup + reused for all forwards.
    """
    try:
        import aiohttp
        from aiohttp import web
    except ImportError as e:
        raise RuntimeError(
            "aiohttp is required for the bouncer HTTP proxy. "
            "Install it: pip install 'aiohttp>=3.9'"
        ) from e

    # Pooled session reused for all outbound forwards. Slice 5 will
    # tune the connector + add streaming response handling for
    # large objects (S3 GetObject of multi-GB files).
    connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=300)
    session = aiohttp.ClientSession(connector=connector)
    app = web.Application()

    async def handler(request):
        return await _handle_request(
            request, store=store, config=config, session=session,
        )

    async def healthz_handler(request):
        # Liveness probe. Bypasses proxy evaluation entirely (never
        # parses as a request, never writes to the audit log) so
        # monitor traffic doesn't pollute the operator's "what just
        # happened" view in `ibounce logs tail`. Mirrors
        # kbouncer's /healthz shape for cross-product symmetry.
        active_profile = getattr(config, "active_profile", None)
        try:
            decision_count = store.count_decisions()
            status_str = "ok"
        except Exception:
            decision_count = 0
            status_str = "degraded"
        # #6a — surface pause state so monitoring can flag a window
        # that's still open (e.g. ops left it on overnight by mistake)
        # without us having to invent a separate probe endpoint.
        # HIGH-33-02 closure: truncate operator-supplied free text +
        # strip control chars so a maliciously-crafted reason can't
        # break monitor parsers (newlines splitting the JSON line,
        # NULL bytes confusing C parsers, etc).
        pause_payload = None
        try:
            active_pause = store.get_active_pause()
            if active_pause is not None:
                reason = active_pause["reason"] or ""
                # Strip control chars + cap length
                reason = "".join(
                    ch for ch in reason if ch == " " or (32 <= ord(ch) < 127)
                )[:200]
                pause_payload = {
                    "id": active_pause["id"],
                    "started_at": active_pause["started_at"],
                    "ends_at": active_pause["ends_at"],
                    "reason": reason,
                }
        except Exception:
            pass
        pause_errs = _pause_lookup_error_count()
        if pause_errs > 0 and status_str == "ok":
            # HIGH-32-05 mitigation: a non-zero count means the proxy
            # has been silently enforcing through a window the operator
            # thought they had opened. Flip status so monitor probes
            # alert before the operator wonders why their pause "isn't
            # working."
            status_str = "degraded"
        return web.json_response({
            "status": status_str,
            "mode": config.mode.value,
            "default_policy": config.default_policy.value,
            "active_profile": active_profile.name if active_profile else "",
            "decisions_count": decision_count,
            "pause": pause_payload,
            "pause_lookup_errors_total": pause_errs,
        })

    # /healthz registered BEFORE the catch-all so it wins route
    # precedence; aiohttp dispatches in registration order.
    app.router.add_route("GET", "/healthz", healthz_handler)
    app.router.add_route("*", "/{tail:.*}", handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.host, config.port)
    await site.start()
    logger.info(
        "ibounce proxy listening on http://%s:%s (mode=%s)",
        config.host, config.port, config.mode.value,
    )
    logger.info(
        "Point your SDK at it: AWS_ENDPOINT_URL=http://%s:%s "
        "(Slice 2: forwards allowed requests to AWS verbatim; "
        "SigV4 signatures preserved)",
        config.host, config.port,
    )

    # Block forever (until task cancellation)
    try:
        await asyncio.Event().wait()
    finally:
        await session.close()
        await runner.cleanup()
