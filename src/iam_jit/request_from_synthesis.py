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
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import secrets
import time
import typing


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
    refs = evidence.get("codebase_references")
    if not isinstance(refs, list):
        raise SynthesisRequestError(
            "`evidence.codebase_references` must be a list of strings.",
            code="invalid_codebase_references",
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
            "from": str(window["from"]),
            "to": str(window["to"]),
            "bouncer": str(window["bouncer"]),
        },
        "codebase_references": [str(r) for r in refs],
        "operator_intent": intent.strip(),
    }


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
    serialises this to JSON for the agent."""

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
    )


# ---------------------------------------------------------------------------
# MCP adapter
# ---------------------------------------------------------------------------


def request_role_from_synthesis_for_mcp(
    args: dict[str, typing.Any],
) -> dict[str, typing.Any]:
    """MCP-tool entry point. Wraps :func:`request_role_from_synthesis`
    with arg unpacking + a stable JSON-friendly response."""
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
    )
    return verdict.as_dict()


__all__ = [
    "DEFAULT_AUTO_APPROVE_THRESHOLD",
    "SynthesisRequestError",
    "SynthesisVerdict",
    "request_role_from_synthesis",
    "request_role_from_synthesis_for_mcp",
]
