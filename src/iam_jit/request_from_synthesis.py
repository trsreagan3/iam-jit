# #421 / §A60 — `iam_jit_request_role_from_synthesis` MCP tool backend.
"""Synthesis-aware role-request flow.

Phase E of [[bouncer-informs-agent-informs-iam-jit]]. The agent
synthesises a permission set from bouncer observation + codebase
context + operator intent (channels iam-jit deliberately does NOT
read; see [[recommender-context-boundary]]). It calls this entry
point with the synthesised permissions + an explicit ``evidence``
block tracing back to those upstream inputs.

iam-jit's job at this seam is narrow:

  * Validate the evidence block is present + structurally honest
    (per [[ibounce-honest-positioning]] no anonymous synthesised
    requests).
  * Translate the agent's ``[{action, resources, count}, ...]`` shape
    into a standard request policy.
  * Route it through the existing scorer + auto-approve gates
    (per [[scorer-is-ground-truth]] the scorer is unchanged; this
    surface reuses the same safety floor every request goes through).
  * Return the verdict + (when auto-approved) STS credentials.

iam-jit deliberately does NOT:

  * Auto-generate the permission set (the agent does that with
    context iam-jit doesn't have).
  * Mutate any existing customer IAM resource — per
    [[creates-never-mutates]] the credentials returned belong to a
    NEW short-lived role iam-jit just created.
  * Score the evidence block contents. The block exists for
    OPERATOR audit, not for iam-jit to second-guess agent context.

The schema for ``evidence`` is documented inline below; tests
enforce it.

Tests for this module MUST follow the state-verification pattern per
``docs/CONTRIBUTING.md`` — assert observable state matches reported
status, not just the status string. This module was the surface that
shipped bugs #475 (``audit_event_ids`` returned but events were
write-only; query path returned empty), #476 (``status="auto_approved"``
with ``credentials: null`` silently) and #477 (empty
``codebase_references: []`` passing evidence-block discipline). The
convention exists to prevent the same shape from re-shipping.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json as _json
import logging as _logging
import os as _os
import pathlib as _pathlib
import secrets
import time
import typing

_logger = _logging.getLogger(__name__)


# Default upper bound on how far back the agent's evidence audit-window
# is allowed to point. 365 days is permissive enough for re-discovery
# loops + long-running migrations and tight enough that a "from=1970-
# 01-01" fabrication doesn't sail through. Operators can raise / lower
# this via the ``IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS`` env var without
# touching code; the per-request override is intentionally NOT
# exposed (the floor is operator-set, not request-set).
DEFAULT_MAX_LOOKBACK_DAYS = 365


def _max_lookback_days() -> int:
    """Return the operator-configured max lookback window in days.

    Sourced from ``IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS`` env var, with
    ``DEFAULT_MAX_LOOKBACK_DAYS`` as the fallback. A bad value (non-
    integer, <=0) falls back to the default + logs a warning rather
    than erroring — the synthesis surface should never refuse to run
    just because an operator typo'd a config value.
    """
    raw = _os.environ.get("IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS")
    if not raw:
        return DEFAULT_MAX_LOOKBACK_DAYS
    try:
        v = int(raw)
        if v <= 0:
            raise ValueError("must be positive")
        return v
    except ValueError as e:
        # MRR-2 F6 (HIGH from
        # docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md): the previous
        # ``_logger.warning`` was invisible to default log config —
        # the operator's intended 90-day audit window silently
        # truncated to the 7-day default and downstream synthesis
        # requests started getting ``invalid_audit_window_too_old``
        # rejections for events they thought were in scope. Emit a
        # structured degraded_capability event so /healthz +
        # posture surface the typo loudly.
        from .degraded_capability import (
            REASON_BAD_ENV_VAR_VALUE,
            emit as _deg_emit,
        )
        _deg_emit(
            feature="synthesis.max_lookback_env",
            reason=REASON_BAD_ENV_VAR_VALUE,
            hint=(
                f"IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS={raw!r} is "
                f"invalid; falling back to default "
                f"{DEFAULT_MAX_LOOKBACK_DAYS} days. Set a positive "
                f"integer to override."
            ),
            extra={"degraded_env_var_value": raw[:64]},
        )
        _logger.warning(
            "IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS=%r is invalid (%s); "
            "falling back to default %d days",
            raw, e, DEFAULT_MAX_LOOKBACK_DAYS,
        )
        return DEFAULT_MAX_LOOKBACK_DAYS


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SynthesisRequestError(ValueError):
    """Raised when an incoming synthesis request is structurally bad.

    Carries an OCSF-friendly ``code`` so the MCP wrapper can re-emit
    a stable error payload (the operator can grep their audit log for
    ``code=missing_evidence_block`` etc.).
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: dict[str, typing.Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = dict(details or {})


# ---------------------------------------------------------------------------
# Evidence validation
# ---------------------------------------------------------------------------


# Required keys on the evidence block. Per [[ibounce-honest-positioning]]
# every synthesised request MUST trace to:
#   * the bouncer audit window it came from
#   * the codebase / config the agent consulted
#   * the operator's stated intent
# Absent any of these the request is REJECTED (not just down-graded to
# pending) because the auditability discipline is the whole point of
# this surface.
_REQUIRED_EVIDENCE_KEYS: tuple[str, ...] = (
    "bouncer_audit_window",
    "codebase_references",
    "operator_intent",
)
_REQUIRED_AUDIT_WINDOW_KEYS: tuple[str, ...] = ("from", "to", "bouncer")


def _validate_evidence(evidence: typing.Any) -> dict[str, typing.Any]:
    """Verify the evidence block is present + well-formed.

    Returns the normalised dict. Raises :class:`SynthesisRequestError`
    on any structural problem so the MCP wrapper can return a
    rejection payload AND emit an audit row capturing the attempt
    (per [[ibounce-honest-positioning]] we'd rather record the
    refusal than silently accept).
    """
    if evidence is None:
        raise SynthesisRequestError(
            "synthesis requests MUST include an `evidence` block per "
            "[[ibounce-honest-positioning]] — no anonymous synthesised "
            "requests. Provide bouncer_audit_window + codebase_references "
            "+ operator_intent fields.",
            code="missing_evidence_block",
        )
    if not isinstance(evidence, dict):
        raise SynthesisRequestError(
            "`evidence` must be a mapping; got "
            f"{type(evidence).__name__}",
            code="invalid_evidence_block",
            details={"actual_type": type(evidence).__name__},
        )
    missing = [k for k in _REQUIRED_EVIDENCE_KEYS if k not in evidence]
    if missing:
        raise SynthesisRequestError(
            f"`evidence` is missing required fields: {missing}. "
            "Required: bouncer_audit_window (with from/to/bouncer), "
            "codebase_references (list[str]), operator_intent (str).",
            code="missing_evidence_field",
            details={"missing_fields": missing},
        )
    window = evidence.get("bouncer_audit_window")
    if not isinstance(window, dict):
        raise SynthesisRequestError(
            "`evidence.bouncer_audit_window` must be a mapping with "
            "`from`, `to`, `bouncer` keys.",
            code="invalid_audit_window",
        )
    missing_w = [k for k in _REQUIRED_AUDIT_WINDOW_KEYS if not window.get(k)]
    if missing_w:
        raise SynthesisRequestError(
            f"`evidence.bouncer_audit_window` missing required fields: "
            f"{missing_w}. Each of from/to/bouncer must be a non-empty "
            "string.",
            code="missing_audit_window_field",
            details={"missing_fields": missing_w},
        )
    # #477 / §A60f — validate the from/to are actual ISO-8601 / RFC-3339
    # timestamps, not opaque "x"/"y" strings. The recipe page promises
    # the audit chain traces back to a SPECIFIC bouncer window; "x"/"y"
    # makes that promise vacuous. Per [[ibounce-honest-positioning]]
    # the discipline is enforced at the seam, not left as a future TODO.
    from_str = str(window["from"])
    to_str = str(window["to"])
    try:
        from_dt = _parse_iso8601(from_str)
    except ValueError as e:
        raise SynthesisRequestError(
            f"`evidence.bouncer_audit_window.from` must be ISO-8601 / "
            f"RFC-3339 (e.g. `2026-05-23T13:00:00Z`); got {from_str!r} "
            f"({e}).",
            code="invalid_audit_window_iso_format",
            details={"field": "from", "value": from_str},
        ) from None
    try:
        to_dt = _parse_iso8601(to_str)
    except ValueError as e:
        raise SynthesisRequestError(
            f"`evidence.bouncer_audit_window.to` must be ISO-8601 / "
            f"RFC-3339 (e.g. `2026-05-23T14:00:00Z`); got {to_str!r} "
            f"({e}).",
            code="invalid_audit_window_iso_format",
            details={"field": "to", "value": to_str},
        ) from None
    if from_dt > to_dt:
        raise SynthesisRequestError(
            f"`evidence.bouncer_audit_window.from` ({from_str}) must "
            f"not be after `to` ({to_str}). The window is read as "
            "[from, to]; a reversed window suggests fabrication.",
            code="invalid_audit_window_reversed",
            details={"from": from_str, "to": to_str},
        )
    now = _dt.datetime.now(_dt.timezone.utc)
    # Allow up to 60s of clock skew so a freshly-bouncer-stamped window
    # whose `to` is "right now" doesn't trip the future-window guard.
    if from_dt > now + _dt.timedelta(seconds=60):
        raise SynthesisRequestError(
            f"`evidence.bouncer_audit_window.from` ({from_str}) is in "
            "the future. The window must point to OBSERVED bouncer "
            "activity, not a planned one.",
            code="invalid_audit_window_future",
            details={"from": from_str, "now": now.isoformat()},
        )
    max_days = _max_lookback_days()
    oldest_allowed = now - _dt.timedelta(days=max_days)
    if to_dt < oldest_allowed:
        raise SynthesisRequestError(
            f"`evidence.bouncer_audit_window.to` ({to_str}) is older "
            f"than the operator-configured max lookback "
            f"({max_days} days). Set "
            "IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS to raise the ceiling "
            "if a longer window is genuinely intended.",
            code="invalid_audit_window_too_old",
            details={
                "to": to_str,
                "max_lookback_days": max_days,
                "oldest_allowed": oldest_allowed.isoformat(),
            },
        )

    refs = evidence.get("codebase_references")
    if not isinstance(refs, list):
        raise SynthesisRequestError(
            "`evidence.codebase_references` must be a list of strings.",
            code="invalid_codebase_references",
        )
    # #477 / §A60f — empty codebase_references defeats the whole purpose
    # of the evidence chain (no traceback to what the agent actually
    # read). Reject explicitly + tell the operator how to satisfy it.
    cleaned_refs = [str(r).strip() for r in refs if str(r).strip()]
    if not cleaned_refs:
        raise SynthesisRequestError(
            "`evidence.codebase_references` must contain at least one "
            "non-empty entry — the path(s) / symbol(s) the agent read "
            "to synthesise this request (e.g. `CLAUDE.md`, "
            "`terraform/prod/main.tf`, `src/handlers/upload.py:42`). "
            "An empty list defeats the audit-chain purpose of the "
            "evidence block.",
            code="invalid_codebase_references_empty",
        )
    intent = evidence.get("operator_intent")
    if not isinstance(intent, str) or not intent.strip():
        raise SynthesisRequestError(
            "`evidence.operator_intent` must be a non-empty string "
            "capturing what the operator asked for.",
            code="invalid_operator_intent",
        )
    return {
        "bouncer_audit_window": {
            "from": from_str,
            "to": to_str,
            "bouncer": str(window["bouncer"]),
        },
        "codebase_references": cleaned_refs,
        "operator_intent": intent.strip(),
    }


def _parse_iso8601(value: str) -> _dt.datetime:
    """Parse an ISO-8601 / RFC-3339 timestamp into a tz-aware datetime.

    Handles the `Z` suffix (UTC) Python's stdlib fromisoformat()
    historically choked on — pre-3.11 it didn't recognise `Z`; we
    normalise + accept it across versions for parity with the
    audit-export wire shape which always emits `Z`.

    Raises :class:`ValueError` on any parse failure so the caller can
    map the failure to a stable rejection code.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("must be a non-empty string")
    s = value.strip()
    # Normalise `Z` to `+00:00` for fromisoformat across Python versions.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"not parseable as ISO-8601: {e}") from None
    # Force tz-awareness — naive datetimes from the agent would compare
    # incorrectly against `now()`. Per RFC-3339 a timestamp without
    # offset is ambiguous; we treat it as UTC + log no warning (the
    # agent's responsibility is to send the right shape).
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Permission set normalisation
# ---------------------------------------------------------------------------


def _validate_permissions(
    permissions: typing.Any,
) -> list[dict[str, typing.Any]]:
    """Verify the permissions list is well-formed + non-empty. Returns
    a normalised list."""
    if not isinstance(permissions, list) or not permissions:
        raise SynthesisRequestError(
            "`permissions` must be a non-empty list of "
            "{action, resources, count} entries. The agent extracts "
            "this via `bounce_extract_permissions_from_audit`.",
            code="empty_permissions",
        )
    out: list[dict[str, typing.Any]] = []
    for i, p in enumerate(permissions):
        if not isinstance(p, dict):
            raise SynthesisRequestError(
                f"`permissions[{i}]` must be a mapping; got "
                f"{type(p).__name__}",
                code="invalid_permission_entry",
            )
        action = p.get("action")
        if not isinstance(action, str) or ":" not in action:
            raise SynthesisRequestError(
                f"`permissions[{i}].action` must be `service:Action` "
                f"form; got {action!r}",
                code="invalid_permission_action",
            )
        resources = p.get("resources") or []
        if not isinstance(resources, list):
            raise SynthesisRequestError(
                f"`permissions[{i}].resources` must be a list",
                code="invalid_permission_resources",
            )
        out.append({
            "action": action,
            "resources": [str(r) for r in resources] or ["*"],
            "count": int(p.get("count") or 0),
        })
    return out


def _build_policy_from_permissions(
    permissions: list[dict[str, typing.Any]],
) -> dict[str, typing.Any]:
    """Turn the agent-shaped ``[{action, resources, count}, ...]`` into
    a standard IAM policy document.

    One Allow statement per action so the scorer can attribute
    risk-factor messages back to specific actions (the scorer already
    handles multi-statement policies). ``count`` is dropped here —
    it's metadata for the operator, not policy.
    """
    statements: list[dict[str, typing.Any]] = []
    for p in permissions:
        statements.append({
            "Effect": "Allow",
            "Action": [p["action"]],
            "Resource": list(p["resources"]),
        })
    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


# ---------------------------------------------------------------------------
# Request ID
# ---------------------------------------------------------------------------


def _new_request_id() -> str:
    """Generate a short ULID-ish id prefixed with ``rfs_`` (Request From
    Synthesis). Mirrors the ``dd_`` shape used in
    :mod:`iam_jit.dynamic_denies.store`."""
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = secrets.token_bytes(10)
    rand_int = int.from_bytes(rand, "big") & ((1 << 80) - 1)

    def _enc(v: int, n: int) -> str:
        chars: list[str] = []
        for _ in range(n):
            chars.append(alphabet[v & 0x1F])
            v >>= 5
        return "".join(reversed(chars))

    return "rfs_" + _enc(ts_ms, 10) + _enc(rand_int, 16)


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SynthesisVerdict:
    """Outcome of a synthesis-request evaluation. The MCP / CLI wrapper
    serialises this to JSON for the agent.

    The ``notes`` field (#476 / §A60e) is an operator-language list of
    strings explaining partial-state conditions the agent needs to know
    about — most commonly "approved but credentials not minted in this
    release; here's how to mint them". Always present (possibly empty)
    so the wire shape is stable. Per
    [[ambient-value-prop-and-friction-framing]] the notes are framed
    as actionable next-steps, not as errors.
    """

    request_id: str
    status: str  # auto_approved | pending_operator_approval | rejected
    score: int | None
    risk_factors: tuple[str, ...]
    audit_event_id: str
    rejection_code: str | None
    rejection_message: str | None
    evidence: dict[str, typing.Any]
    resource_mapping_applied: str | None
    requested_duration: str
    credentials: dict[str, typing.Any] | None
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "score": self.score,
            "risk_factors": list(self.risk_factors),
            "audit_event_id": self.audit_event_id,
            "rejection_code": self.rejection_code,
            "rejection_message": self.rejection_message,
            "evidence": dict(self.evidence),
            "resource_mapping_applied": self.resource_mapping_applied,
            "requested_duration": self.requested_duration,
            "credentials": dict(self.credentials) if self.credentials else None,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def _new_audit_event_id() -> str:
    """Stable id form for the synthesis-request admin-action row.
    Prefixed ``evt_rfs_`` so audit-log greps disambiguate from other
    audit-row sources."""
    rand = secrets.token_hex(8)
    return f"evt_rfs_{rand}"


def _emit_synthesis_audit(
    *,
    request_id: str,
    status: str,
    score: int | None,
    evidence: dict[str, typing.Any],
    resource_mapping_applied: str | None,
    requested_duration: str,
    permissions_count: int,
    justification: str,
    rejection_code: str | None,
    audit_sink: typing.Callable[[dict[str, typing.Any]], None] | None,
) -> str:
    """Emit one structured audit row for this synthesis attempt.

    Per [[ibounce-honest-positioning]] EVEN REJECTIONS get an audit
    row — the auditor reading "why did this synth request happen at
    19:03" should always find the answer, not a silent gap.

    ``audit_sink`` lets tests collect rows in-memory; the default
    (None) is a no-op so the function works in environments without an
    audit-export channel configured. The returned ``audit_event_id``
    is the id the agent sees in the verdict + can grep for in the
    OCSF stream.
    """
    audit_event_id = _new_audit_event_id()
    now_iso = _dt.datetime.now(_dt.timezone.utc).replace(
        microsecond=0,
    ).isoformat().replace("+00:00", "Z")
    row = {
        "audit_event_id": audit_event_id,
        "kind": "iam_jit_request_role_from_synthesis",
        "request_id": request_id,
        "status": status,
        "score": score,
        "when": now_iso,
        "rejection_code": rejection_code,
        "resource_mapping_applied": resource_mapping_applied,
        "requested_duration": requested_duration,
        "permissions_count": permissions_count,
        "justification": justification,
        # The evidence chain is reproduced ON the audit row so the
        # operator can trace WHY this request happened back through
        # the bouncer-audit-window without joining tables. This is
        # the load-bearing field for the auditability discipline.
        "evidence": dict(evidence),
    }
    if audit_sink is not None:
        try:
            audit_sink(row)
        except Exception:
            # Audit-sink failure must not prevent us from returning
            # the verdict — the agent's loop relies on a response.
            pass
    return audit_event_id


# ---------------------------------------------------------------------------
# Scoring + decision
# ---------------------------------------------------------------------------


# Default auto-approve threshold used when no settings object is
# supplied (e.g. CLI smoke + tests). Mirrors the conservative default
# in the route-side flow (`auto_approve_risk_below=4`). Reusing the
# numerical floor keeps the synthesis surface honest about being a
# THIN wrapper around the existing safety mechanism.
DEFAULT_AUTO_APPROVE_THRESHOLD = 4


def _score_policy_safely(
    policy: dict[str, typing.Any],
) -> tuple[int, tuple[str, ...]]:
    """Run the deterministic scorer over the synthesised policy.

    Returns (score, risk_factors). We pull the scorer at call time so
    test-time monkey-patches of :mod:`iam_jit.review` work.

    Falls back to a conservative score=10 when the scorer raises (the
    synthesis surface should NEVER swallow a scoring error silently —
    the safe response is "treat as max risk + route to pending").
    """
    try:
        from .review import analyze_policy
    except Exception:
        return 10, ("scorer_import_failed",)
    try:
        analysis = analyze_policy(policy, request={})
    except Exception:
        return 10, ("scorer_raised",)
    return int(analysis.risk_score), tuple(analysis.risk_factors)


def _route_decision(
    score: int,
    threshold: int,
) -> str:
    """Translate score + threshold into the public status string.

    Mirrors the auto-approve gate in :mod:`iam_jit.auto_approve` (the
    `above_threshold` reason becomes `pending_operator_approval`).
    """
    if score < threshold:
        return "auto_approved"
    return "pending_operator_approval"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def request_role_from_synthesis(
    *,
    permissions: list[dict[str, typing.Any]],
    observed_scope: dict[str, typing.Any] | None,
    justification: str,
    evidence: typing.Any,
    requested_duration: str = "PT1H",
    resource_mapping_applied: str | None = None,
    auto_approve_threshold: int = DEFAULT_AUTO_APPROVE_THRESHOLD,
    audit_sink: typing.Callable[[dict[str, typing.Any]], None] | None = None,
    credential_factory: typing.Callable[
        [dict[str, typing.Any]], dict[str, typing.Any] | None,
    ] | None = None,
) -> SynthesisVerdict:
    """Validate the synthesis request + route through the scorer.

    ``credential_factory`` lets the caller plug in real STS issuance
    (in production: a thin wrapper around :mod:`iam_jit.provision`);
    in tests it's a stub that returns a fake credential bundle. When
    omitted, ``credentials`` is None even for auto_approved verdicts —
    the caller is expected to wire issuance at the route layer.

    The function NEVER raises for "validation failed" — it returns a
    SynthesisVerdict with status='rejected' + a populated
    ``rejection_code`` so the MCP wrapper can JSON-encode the
    rejection (raising would crash the agent's loop). Internal bugs
    still propagate.
    """
    request_id = _new_request_id()
    # 1) Evidence-block gate (REQUIRED — per [[ibounce-honest-positioning]]).
    try:
        normalised_evidence = _validate_evidence(evidence)
    except SynthesisRequestError as err:
        audit_event_id = _emit_synthesis_audit(
            request_id=request_id,
            status="rejected",
            score=None,
            evidence={"_invalid": True, "_reason": err.code},
            resource_mapping_applied=resource_mapping_applied,
            requested_duration=requested_duration,
            permissions_count=len(permissions) if isinstance(permissions, list) else 0,
            justification=str(justification or ""),
            rejection_code=err.code,
            audit_sink=audit_sink,
        )
        return SynthesisVerdict(
            request_id=request_id,
            status="rejected",
            score=None,
            risk_factors=(),
            audit_event_id=audit_event_id,
            rejection_code=err.code,
            rejection_message=err.message,
            evidence={},
            resource_mapping_applied=resource_mapping_applied,
            requested_duration=requested_duration,
            credentials=None,
        )

    # 2) Permission-set validation.
    try:
        normalised_permissions = _validate_permissions(permissions)
    except SynthesisRequestError as err:
        audit_event_id = _emit_synthesis_audit(
            request_id=request_id,
            status="rejected",
            score=None,
            evidence=normalised_evidence,
            resource_mapping_applied=resource_mapping_applied,
            requested_duration=requested_duration,
            permissions_count=0,
            justification=str(justification or ""),
            rejection_code=err.code,
            audit_sink=audit_sink,
        )
        return SynthesisVerdict(
            request_id=request_id,
            status="rejected",
            score=None,
            risk_factors=(),
            audit_event_id=audit_event_id,
            rejection_code=err.code,
            rejection_message=err.message,
            evidence=normalised_evidence,
            resource_mapping_applied=resource_mapping_applied,
            requested_duration=requested_duration,
            credentials=None,
        )

    # Justification must be a non-empty string (separate from evidence —
    # the operator might supply BOTH the WHY (justification) and the
    # full evidence chain).
    if not isinstance(justification, str) or not justification.strip():
        audit_event_id = _emit_synthesis_audit(
            request_id=request_id,
            status="rejected",
            score=None,
            evidence=normalised_evidence,
            resource_mapping_applied=resource_mapping_applied,
            requested_duration=requested_duration,
            permissions_count=len(normalised_permissions),
            justification="",
            rejection_code="missing_justification",
            audit_sink=audit_sink,
        )
        return SynthesisVerdict(
            request_id=request_id,
            status="rejected",
            score=None,
            risk_factors=(),
            audit_event_id=audit_event_id,
            rejection_code="missing_justification",
            rejection_message=(
                "`justification` is required — a short string explaining "
                "the business reason for this role. The `evidence` block "
                "is the AUDIT chain; justification is the human-readable "
                "WHY."
            ),
            evidence=normalised_evidence,
            resource_mapping_applied=resource_mapping_applied,
            requested_duration=requested_duration,
            credentials=None,
        )

    # 3) Score the synthesised policy.
    policy = _build_policy_from_permissions(normalised_permissions)
    score, risk_factors = _score_policy_safely(policy)
    status = _route_decision(score, auto_approve_threshold)

    # 4) Credentials only minted on auto-approve. Pending requests come
    #    back without credentials — the operator approves separately
    #    through the existing pending-review surface.
    credentials: dict[str, typing.Any] | None = None
    if status == "auto_approved" and credential_factory is not None:
        try:
            credentials = credential_factory({
                "request_id": request_id,
                "policy": policy,
                "observed_scope": dict(observed_scope or {}),
                "requested_duration": requested_duration,
                "evidence": normalised_evidence,
            })
        except Exception:
            # Issuance failure flips us to pending; the operator can
            # retry from the pending queue once the underlying cause
            # (AWS rate limit, missing role-create permission, etc.)
            # is fixed.
            status = "pending_operator_approval"
            credentials = None

    # 5) Audit row (always — per [[ibounce-honest-positioning]]).
    audit_event_id = _emit_synthesis_audit(
        request_id=request_id,
        status=status,
        score=score,
        evidence=normalised_evidence,
        resource_mapping_applied=resource_mapping_applied,
        requested_duration=requested_duration,
        permissions_count=len(normalised_permissions),
        justification=justification.strip(),
        rejection_code=None,
        audit_sink=audit_sink,
    )

    # 6) Operator-facing notes. #476 / §A60e: when the verdict says
    #    auto_approved but no credentials came back (because the caller
    #    didn't wire a credential_factory yet — the v1.0 default for the
    #    MCP path), surface an HONEST signal to the agent so it doesn't
    #    pretend STS creds are coming. Per
    #    [[ambient-value-prop-and-friction-framing]] the framing is
    #    "here's what's done + here's what's next", not an error.
    notes_list: list[str] = []
    if status == "auto_approved" and credentials is None:
        # #473 / §A60b — credential_factory not wired at call site.
        # Surface an actionable note so the agent knows how to proceed
        # rather than silently receiving null. Per
        # [[ambient-value-prop-and-friction-framing]] this is framed as
        # "here's what's done + here's what's next", not an error.
        notes_list.append(
            "Synthesis approved; credential issuance not available in "
            "this invocation. To mint actual STS credentials, run "
            f"`iam-jit request --from-synthesis {request_id}` OR use "
            "the MCP server (which wires credential_factory via #473)."
        )
        notes_list.append(
            "Your audit chain is preserved: query via "
            f"`iam-jit audit query --filter audit_event_id={audit_event_id}`."
        )

    return SynthesisVerdict(
        request_id=request_id,
        status=status,
        score=score,
        risk_factors=risk_factors,
        audit_event_id=audit_event_id,
        rejection_code=None,
        rejection_message=None,
        evidence=normalised_evidence,
        resource_mapping_applied=resource_mapping_applied,
        requested_duration=requested_duration,
        credentials=credentials,
        notes=tuple(notes_list),
    )


# ---------------------------------------------------------------------------
# OCSF audit-sink wiring (#475 / §A60d)
# ---------------------------------------------------------------------------
#
# The synthesis-request audit row needs to land in the SAME OCSF stream
# the ibounce proxy writes to so that `iam-jit audit query --filter
# audit_event_id=<id>` can retrieve it. Without this wiring the recipe
# page's promise ("the auditor reading 'why did this synth request fail
# at 14:02' should always find the answer") is vacuous — the row is
# emitted as a Python dict + immediately discarded.
#
# Architecture choice: write to the SAME JSONL path the ibounce proxy
# uses (default ``~/.iam-jit/audit.jsonl``, overridable via the same
# ``IAM_JIT_BOUNCER_AUDIT_LOG`` env var). The synthesis surface runs
# inside the iam-jit MCP server process, not inside ibounce, but the
# default audit-log path is shared by convention so cross-product
# ``iam-jit audit query`` finds synthesis rows alongside proxy
# decisions without operators wiring two log paths.
#
# A separate env var ``IAM_JIT_SYNTHESIS_AUDIT_LOG`` overrides JUST the
# synthesis path for operators who deliberately want it segregated.
#
# Per [[ibounce-honest-positioning]] failures here MUST be observable
# (logged) but never crash the agent's loop. The audit sink is a
# feature, not a hard dependency of correctness.


# OCSF constants — mirror ``bouncer/audit_export/event.py`` so the
# synthesis row shares the same product/class/category identity. Kept
# local (rather than imported) so the synthesis surface stays
# decoupled from the bouncer's lifecycle imports.
_OCSF_SCHEMA_VERSION = "1.1.0"
_PRODUCT_NAME = "iam-jit"
_PRODUCT_VENDOR_NAME = "iam-jit"
_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"
# Synthesis is a CREATE-shaped activity (we're creating a role-request
# record, possibly issuing creds). Pick activity_id=1 (Create) per the
# OCSF v1.1.0 class 6003 spec.
_ACTIVITY_CREATE = 1
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_CREATE
_STATUS_SUCCESS_ID = 1
_STATUS_SUCCESS_NAME = "Success"
_STATUS_FAILURE_ID = 2
_STATUS_FAILURE_NAME = "Failure"
_SEVERITY_INFORMATIONAL_ID = 1
_SEVERITY_INFORMATIONAL_NAME = "Informational"

# Custom event_type discriminator under unmapped.iam_jit.event_type
# so a filter on that key isolates synthesis rows from proxy decisions
# / admin actions / pause events / etc.
SYNTHESIS_EVENT_TYPE = "iam_jit_request_role_from_synthesis"


def _default_synthesis_audit_log_path() -> _pathlib.Path:
    """Return the JSONL path the synthesis sink writes to.

    Resolution order:

      1. ``IAM_JIT_SYNTHESIS_AUDIT_LOG`` env var (synthesis-only
         override; lets operators segregate synthesis rows if they
         really want).
      2. ``IAM_JIT_BOUNCER_AUDIT_LOG`` env var (the same override
         ibounce honours — keeps synthesis + proxy rows in one stream
         by default).
      3. ``~/.iam-jit/audit.jsonl`` (the conventional bouncer path).

    The path is advisory; the writer creates parent dirs as needed.
    """
    override = _os.environ.get("IAM_JIT_SYNTHESIS_AUDIT_LOG")
    if override:
        return _pathlib.Path(override)
    bouncer_override = _os.environ.get("IAM_JIT_BOUNCER_AUDIT_LOG")
    if bouncer_override:
        return _pathlib.Path(bouncer_override)
    return _pathlib.Path.home() / ".iam-jit" / "audit.jsonl"


def synthesis_row_to_ocsf(row: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Convert a synthesis audit row (the dict shape emitted by
    ``_emit_synthesis_audit``) into an OCSF v1.1.0 class 6003 event.

    Same wire shape every ibounce/kbounce/dbounce/gbounce decision
    event uses, so the existing cross-bouncer query CLI + the per-
    bouncer `/audit/events` endpoint pick it up without per-product
    parsing.

    The synthesis audit chain (bouncer_audit_window, codebase_references,
    operator_intent) is reproduced under ``unmapped.iam_jit.synthesis``
    so the operator's audit query can fan out from the synthesis row
    to the underlying bouncer window without joining tables.
    """
    status = str(row.get("status") or "")
    status_id = _STATUS_SUCCESS_ID
    status_name = _STATUS_SUCCESS_NAME
    if status == "rejected":
        status_id = _STATUS_FAILURE_ID
        status_name = _STATUS_FAILURE_NAME

    evidence = dict(row.get("evidence") or {})
    audit_event_id = str(row.get("audit_event_id") or "")
    request_id = str(row.get("request_id") or "")

    # OCSF `time` is unix milliseconds. The synthesis row carries
    # `when` as ISO-8601; parse + convert here. Fall back to now() if
    # absent / malformed.
    when_ms = int(time.time() * 1000)
    when_iso = row.get("when")
    if isinstance(when_iso, str) and when_iso:
        try:
            dt = _parse_iso8601(when_iso)
            when_ms = int(dt.timestamp() * 1000)
        except ValueError:
            pass

    status_detail = (
        f"synthesis request {request_id} status={status} "
        f"score={row.get('score')} "
        f"rejection_code={row.get('rejection_code')}"
    )

    return {
        "metadata": {
            "version": _OCSF_SCHEMA_VERSION,
            "product": {
                "name": _PRODUCT_NAME,
                "vendor_name": _PRODUCT_VENDOR_NAME,
            },
        },
        "time": when_ms,
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "category_uid": _CATEGORY_UID,
        "category_name": _CATEGORY_NAME,
        "activity_id": _ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": _TYPE_UID,
        "type_name": f"{_CLASS_NAME}: Create",
        "severity_id": _SEVERITY_INFORMATIONAL_ID,
        "severity": _SEVERITY_INFORMATIONAL_NAME,
        "status_id": status_id,
        "status": status_name,
        "status_detail": status_detail,
        # Top-level convenience for grep + the events_endpoint filter
        # parser — `iam-jit audit query --filter audit_event_id=evt_rfs_…`
        # walks dotted paths, so a top-level key resolves cleanly. The
        # nested copy under unmapped.iam_jit also keeps the OCSF-pure
        # consumers happy (everything iam-jit-specific lives under
        # `unmapped`).
        "audit_event_id": audit_event_id,
        "actor": {"user": {"name": "agent-synthesis", "uid": request_id}},
        "api": {
            "operation": SYNTHESIS_EVENT_TYPE,
            "service": {"name": "iam-jit.synthesis"},
            "request": {"uid": request_id},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": SYNTHESIS_EVENT_TYPE,
                "audit_event_id": audit_event_id,
                "request_id": request_id,
                "verdict": status,
                "score": row.get("score"),
                "rejection_code": row.get("rejection_code"),
                "resource_mapping_applied": row.get("resource_mapping_applied"),
                "requested_duration": row.get("requested_duration"),
                "permissions_count": row.get("permissions_count"),
                "justification": row.get("justification"),
                # Full evidence chain reproduced for the auditor — per
                # the recipe page's "trace WHY this role was issued"
                # promise.
                "synthesis": {
                    "evidence": evidence,
                },
                "ext": {},
            },
        },
    }


def default_synthesis_audit_sink(
    row: dict[str, typing.Any],
    *,
    path: _pathlib.Path | None = None,
) -> None:
    """Append one synthesis row to the JSONL audit log as an OCSF event.

    This is the DEFAULT sink wired into :func:`request_role_from_synthesis_for_mcp`
    so synthesis rows are findable via `iam-jit audit query` out of the
    box — no operator config required.

    Per [[ibounce-honest-positioning]] failures are LOGGED but never
    raised. A broken disk should not make the agent's MCP call fail.
    """
    target = path or _default_synthesis_audit_log_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        ocsf_event = synthesis_row_to_ocsf(row)
        # Append-only JSONL — matches the on-disk shape ibounce's
        # AuditLogWriter produces so the events_endpoint reader picks
        # it up with no changes. One JSON object per line, no trailing
        # comma, no array wrapping (NDJSON).
        with target.open("a", encoding="utf-8") as f:
            f.write(_json.dumps(ocsf_event, ensure_ascii=False))
            f.write("\n")
    except OSError as e:
        _logger.warning(
            "synthesis audit sink failed to write to %s: %s. The "
            "synthesis verdict was still returned to the caller; the "
            "audit chain is broken for this row.",
            target, e,
        )
    except Exception as e:  # defensive — never raise into the MCP path
        _logger.warning(
            "synthesis audit sink unexpected error: %s. Row dropped.",
            e,
        )


# ---------------------------------------------------------------------------
# MCP adapter
# ---------------------------------------------------------------------------


def request_role_from_synthesis_for_mcp(
    args: dict[str, typing.Any],
    *,
    audit_sink: typing.Callable[[dict[str, typing.Any]], None] | None = None,
    credential_factory: typing.Callable[
        [dict[str, typing.Any]], dict[str, typing.Any] | None,
    ] | None = None,
) -> dict[str, typing.Any]:
    """MCP-tool entry point. Wraps :func:`request_role_from_synthesis`
    with arg unpacking + a stable JSON-friendly response.

    ``audit_sink`` defaults to :func:`default_synthesis_audit_sink`
    (#475 / §A60d) which appends OCSF v1.1.0 class 6003 events to the
    shared JSONL audit log — making synthesis rows findable via
    `iam-jit audit query --filter audit_event_id=...` out of the box.

    ``credential_factory`` is left None by default in v1.0 (#473
    follow-up). The verdict's ``notes`` field surfaces an honest
    "credentials not yet wired" signal in that state per #476 / §A60e
    + [[ambient-value-prop-and-friction-framing]].
    """
    sink = audit_sink if audit_sink is not None else default_synthesis_audit_sink
    verdict = request_role_from_synthesis(
        permissions=args.get("permissions") or [],
        observed_scope=args.get("observed_scope") or {},
        justification=args.get("justification") or "",
        evidence=args.get("evidence"),
        requested_duration=str(args.get("requested_duration") or "PT1H"),
        resource_mapping_applied=args.get("resource_mapping_applied"),
        auto_approve_threshold=int(
            args.get("auto_approve_threshold")
            or DEFAULT_AUTO_APPROVE_THRESHOLD,
        ),
        audit_sink=sink,
        credential_factory=credential_factory,
    )
    return verdict.as_dict()


# ---------------------------------------------------------------------------
# #473 / §A60b — local credential factory
# ---------------------------------------------------------------------------
#
# The MCP server is a stateless stdio process with no AccountStore or
# ProvisionerRole mechanism. This factory uses the CALLER'S own ambient
# AWS credentials (from the environment / ~/.aws / instance-metadata) to:
#
#   1. Create a short-lived IAM role in the caller's account with the
#      synthesised policy (per [[creates-never-mutates]] — a NEW role,
#      not a mutation of an existing one).
#   2. Call sts:AssumeRole to issue STS credentials for that role.
#   3. Return the credentials dict to the synthesis surface.
#
# This is the "local safety mode" shape (per [[local-only-safety-mode]])
# appropriate for the MCP path. Cross-account provisioning is handled by
# the server-side `provision()` module (separate trust boundary per
# [[create-not-assume-pattern]]).
#
# The factory MUST raise on any failure — the synthesis surface catches
# the exception + flips the verdict to pending_operator_approval, so
# the agent always gets an honest response (never silently null).
#
# Env vars that influence the factory:
#   IAM_JIT_SYNTHESIS_ROLE_PATH  — IAM path prefix (default /iam-jit/synthesis/)
#   IAM_JIT_SYNTHESIS_SESSION_DURATION — STS session seconds (default 3600)


_SYNTHESIS_ROLE_PATH_ENV = "IAM_JIT_SYNTHESIS_ROLE_PATH"
_SYNTHESIS_SESSION_DURATION_ENV = "IAM_JIT_SYNTHESIS_SESSION_DURATION"
_DEFAULT_SYNTHESIS_ROLE_PATH = "/iam-jit/synthesis/"
_DEFAULT_SYNTHESIS_SESSION_DURATION = 3600  # 1 hour


def build_local_credential_factory(
    *,
    iam_client: typing.Any | None = None,
    sts_client: typing.Any | None = None,
) -> typing.Callable[[dict[str, typing.Any]], dict[str, typing.Any]]:
    """Return a credential_factory that creates a role + issues STS creds.

    The factory is a closure over the boto3 clients (or None, in which
    case boto3 is imported at call time using ambient credentials).
    Injecting ``iam_client`` / ``sts_client`` lets tests pass moto-backed
    clients without touching env vars.

    Raises :class:`RuntimeError` if boto3 is not installed — the caller
    (the MCP server) should catch this and return a graceful response
    rather than crashing the stdio loop.

    Per [[creates-never-mutates]]: this factory CREATES a new IAM role for
    every synthesis request. It never modifies existing roles.
    """
    try:
        import boto3 as _boto3  # type: ignore[import]
    except ImportError as e:
        raise RuntimeError(
            "boto3 is required for credential issuance but is not "
            "installed. Install it with `pip install boto3` or run "
            "`iam-jit` in the standard virtualenv."
        ) from e

    _iam = iam_client
    _sts = sts_client

    def _factory(spec: dict[str, typing.Any]) -> dict[str, typing.Any]:
        """Create an IAM role + return STS creds for the synthesis request.

        ``spec`` is the payload provided by :func:`request_role_from_synthesis`:
        ``{request_id, policy, observed_scope, requested_duration, evidence}``.

        Returns a dict with ``AccessKeyId``, ``SecretAccessKey``,
        ``SessionToken``, ``Expiration``, ``RoleArn`` — the stable
        contract the synthesis surface serialises into the agent's verdict.

        Raises on any AWS API error so the synthesis surface can flip
        the verdict to pending_operator_approval (per
        [[scorer-is-ground-truth]] + [[ibounce-honest-positioning]]:
        fail-CLOSED on issuance failure).
        """
        import json as _json_local
        import datetime as _dt_local

        iam = _iam if _iam is not None else _boto3.client("iam")
        sts = _sts if _sts is not None else _boto3.client("sts")

        request_id = str(spec.get("request_id") or "")
        policy = spec.get("policy") or {"Version": "2012-10-17", "Statement": []}

        # Derive role name from request_id: IAM role names are ≤64 chars,
        # must match [\w+=,.@-]. Use "ijsynth-" prefix + last 52 chars of
        # the rfs_ id (strips "rfs_" prefix + truncates).
        safe_id = request_id.replace("_", "").replace("-", "")[-52:]
        role_name = f"ijsynth-{safe_id}"[:64]

        role_path = _os.environ.get(
            _SYNTHESIS_ROLE_PATH_ENV, _DEFAULT_SYNTHESIS_ROLE_PATH
        )
        session_duration = int(
            _os.environ.get(
                _SYNTHESIS_SESSION_DURATION_ENV,
                str(_DEFAULT_SYNTHESIS_SESSION_DURATION),
            )
        )

        # Determine the current principal ARN for the trust policy.
        # The role trusts the caller's own identity so sts:AssumeRole
        # works immediately without additional IAM plumbing.
        try:
            caller = sts.get_caller_identity()
            caller_arn = caller["Arn"]
        except Exception as e:
            raise RuntimeError(
                f"sts:GetCallerIdentity failed — check that AWS "
                f"credentials are configured: {e}"
            ) from e

        trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": "sts:AssumeRole",
            }],
        }

        # Resolve expiry from requested_duration (ISO-8601 duration like
        # PT1H). Fall back to the env-var session duration.
        requested_duration = str(spec.get("requested_duration") or "PT1H")
        expires_at_iso = _resolve_expiry_from_duration(requested_duration)

        # Create the role. If a role with the same name already exists
        # (e.g. concurrent retry), re-use it — idempotency keeps the
        # synthesis surface safe under concurrent calls.
        try:
            iam.create_role(
                RoleName=role_name,
                Path=role_path,
                AssumeRolePolicyDocument=_json_local.dumps(trust),
                Description=f"iam-jit synthesis grant {request_id}"[:1000],
                MaxSessionDuration=session_duration,
                Tags=[
                    {"Key": "managed-by", "Value": "iam-jit"},
                    {"Key": "request-id", "Value": request_id[:256]},
                    {"Key": "synthesis", "Value": "true"},
                    {"Key": "expires-at", "Value": expires_at_iso[:256]},
                ],
            )
        except Exception as e:
            if "EntityAlreadyExists" not in str(e) and "already exists" not in str(e):
                raise RuntimeError(
                    f"iam:CreateRole for synthesis role {role_name!r} failed: {e}"
                ) from e

        # Attach the synthesised policy as an inline policy.
        try:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="iam-jit-synthesis-grant",
                PolicyDocument=_json_local.dumps(policy),
            )
        except Exception as e:
            raise RuntimeError(
                f"iam:PutRolePolicy for synthesis role {role_name!r} failed: {e}"
            ) from e

        # Resolve the role ARN.
        try:
            role_resp = iam.get_role(RoleName=role_name)
            role_arn = role_resp["Role"]["Arn"]
        except Exception as e:
            raise RuntimeError(
                f"iam:GetRole for synthesis role {role_name!r} failed: {e}"
            ) from e

        # Assume the role to mint STS credentials.
        session_name = f"iam-jit-synth-{request_id[-32:]}"[:64]
        try:
            assume_resp = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=session_duration,
            )
        except Exception as e:
            raise RuntimeError(
                f"sts:AssumeRole into {role_arn!r} failed: {e}"
            ) from e

        creds = assume_resp["Credentials"]
        expiration = creds.get("Expiration")
        if hasattr(expiration, "isoformat"):
            expiration = expiration.isoformat()
        else:
            expiration = str(expiration)

        return {
            "AccessKeyId": creds["AccessKeyId"],
            "SecretAccessKey": creds["SecretAccessKey"],
            "SessionToken": creds["SessionToken"],
            "Expiration": expiration,
            "RoleArn": role_arn,
        }

    return _factory


def _resolve_expiry_from_duration(iso_duration: str) -> str:
    """Parse a simple ISO-8601 duration string (PTxH / PTxM / PTxS) into
    an absolute UTC timestamp.

    Only handles the PT<n>H / PT<n>M / PT<n>S forms that the synthesis
    surface uses (not full P1Y2M3DT... forms). Falls back to 1 hour on
    any parse failure — the fallback is safe because the IAM role's
    MaxSessionDuration gate enforces the wall-clock limit independently.
    """
    import re as _re
    import datetime as _dt_local

    s = iso_duration.strip().upper()
    # Match PT<n>H, PT<n>M, PT<n>S or combinations.
    hours = minutes = seconds = 0
    m = _re.search(r"(\d+)H", s)
    if m:
        hours = int(m.group(1))
    m = _re.search(r"(\d+)M", s)
    if m:
        minutes = int(m.group(1))
    m = _re.search(r"(\d+)S", s)
    if m:
        seconds = int(m.group(1))
    if not (hours or minutes or seconds):
        hours = 1  # fallback

    delta = _dt_local.timedelta(hours=hours, minutes=minutes, seconds=seconds)
    expires_at = _dt_local.datetime.now(_dt_local.timezone.utc) + delta
    return expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "DEFAULT_AUTO_APPROVE_THRESHOLD",
    "DEFAULT_MAX_LOOKBACK_DAYS",
    "SYNTHESIS_EVENT_TYPE",
    "SynthesisRequestError",
    "SynthesisVerdict",
    "build_local_credential_factory",
    "default_synthesis_audit_sink",
    "request_role_from_synthesis",
    "request_role_from_synthesis_for_mcp",
    "synthesis_row_to_ocsf",
]
