"""#407 / §A51 + #411 / §A55 — Severity-graded auto-apply.

Maps verified feed entries → bouncer actions per severity:

  * CRITICAL → auto-apply + log (admin_action.threat_feed.applied)
  * HIGH     → auto-apply + notify operator (stderr line)
  * MEDIUM   → enqueue in §A25 pending-approval queue
  * LOW      → informational only (recorded in applied ledger; no
              bouncer state change)

Posture rules (per [[ambient-autonomous-protection]]):

  * managed → REFUSES auto-apply for ALL severities (entries become
              "advisory" records the operator can review via
              ``iam-jit updates list`` + apply manually via PR)
  * ambient → applies per the matrix above

Per [[scorer-is-ground-truth]] feed entries do NOT mutate the scorer
or its calibration corpus. Only the deny/allow surface is touched.

Per [[creates-never-mutates]] applied entries are ADDITIVE only —
never overwrite operator rules.

Per [[ibounce-honest-positioning]] EVERY decision (apply, refuse,
verify-fail) emits an admin_action OCSF event so the audit story is
complete; the applied-ledger surfaces a single inventory for
``iam-jit updates list``.

Applied-ledger layout: ``~/.iam-jit/threat_feed/applied.jsonl`` —
one JSON-per-line record per applied entry, including provenance
(source feed URL, publisher pubkey, discovered_at, compliance_tags),
the verification result, and the bouncer-side artifact id (for
``dynamic_deny`` entries: the ``dd_<ULID>`` returned by the resolver
so ``iam-jit updates revoke <rule_id>`` knows which dynamic-deny to
remove).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import logging
import os
import pathlib
import sys
import typing

from .models import (
    Feed,
    FeedEntry,
    Severity,
    VerificationResult,
    severity_at_or_above,
)
from .signing import cosign_verify_entry, ed25519_verify_entry
from .subscription import Subscription

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


APPLIED_LEDGER_ENV = "IAM_JIT_THREAT_FEED_LEDGER_PATH"
_DEFAULT_LEDGER_REL = pathlib.Path(".iam-jit") / "threat_feed" / "applied.jsonl"


def resolve_ledger_path() -> pathlib.Path:
    raw = (os.environ.get(APPLIED_LEDGER_ENV) or "").strip()
    if raw:
        return pathlib.Path(raw).expanduser()
    return pathlib.Path.home() / _DEFAULT_LEDGER_REL


# ---------------------------------------------------------------------------
# Action classification (pure function — keeps the applier policy
# decision testable in isolation)
# ---------------------------------------------------------------------------


def classify_apply_action(
    severity: Severity,
    *,
    threshold: Severity,
    posture: str,
) -> str:
    """Return one of:

      * ``"auto_apply"``        — write to bouncer state immediately
      * ``"auto_apply_notify"`` — same as auto_apply + stderr notify
      * ``"pending_approval"``  — enqueue for operator review
      * ``"informational"``     — record only; no state change
      * ``"managed_refused"``   — posture=managed forbids auto-apply

    The threshold knob is per-feed (lets the operator pin "from the
    community feed, only CRITICAL auto-applies; from the official
    feed, CRITICAL+HIGH auto-applies").
    """
    if posture == "managed":
        return "managed_refused"
    if severity == Severity.LOW:
        return "informational"
    if severity == Severity.MEDIUM:
        return "pending_approval"
    if severity == Severity.HIGH:
        if severity_at_or_above(severity, threshold):
            return "auto_apply_notify"
        return "pending_approval"
    # CRITICAL
    if severity_at_or_above(severity, threshold):
        return "auto_apply"
    return "pending_approval"


# ---------------------------------------------------------------------------
# Per-entry outcome dataclass
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ApplyOutcome:
    """Per-entry outcome after verification + classification + apply."""

    rule_id: str
    verified: bool
    verification_reason: str
    action: str
    """One of the strings returned by :func:`classify_apply_action` OR
    ``"refused_verification"`` when verification failed (never
    auto-applied) OR ``"refused_already_applied"`` when the ledger
    shows we already processed this rule_id."""

    severity: Severity
    rule_kind: str
    target: str
    applied_artifact_id: str = ""
    """For ``dynamic_deny`` entries: the ``dd_<ULID>`` of the rule
    written. For pending entries: the ``pa_<ULID>`` from the queue.
    Empty for informational + refused."""

    pending_entry_id: str = ""
    error: str = ""
    explanation: str = ""

    def as_dict(self) -> dict[str, typing.Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        return d


# ---------------------------------------------------------------------------
# Verification dispatch
# ---------------------------------------------------------------------------


def _verify_entry(
    entry: FeedEntry,
    subscription: Subscription,
) -> VerificationResult:
    """Dispatch to the right verifier per the subscription's mode."""
    if subscription.verification_mode == "cosign-keyless":
        return cosign_verify_entry(
            entry,
            expected_identity=subscription.cosign_identity,
            expected_issuer=subscription.cosign_issuer,
        )
    # Default: ed25519.
    return ed25519_verify_entry(
        entry,
        publisher_pubkey=subscription.publisher_pubkey,
    )


# ---------------------------------------------------------------------------
# Ledger I/O
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_ledger(
    *,
    ledger_path: pathlib.Path | None = None,
) -> list[dict[str, typing.Any]]:
    """Read the full applied-ledger as a list of dicts. Returns ``[]``
    when the file doesn't exist."""
    lp = ledger_path or resolve_ledger_path()
    if not lp.exists():
        return []
    out: list[dict[str, typing.Any]] = []
    try:
        with lp.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        logger.warning("threat_feed: read ledger failed: %s", e)
    return out


def applied_rule_ids(
    *,
    ledger_path: pathlib.Path | None = None,
) -> set[str]:
    """Return the set of rule_ids that have already been processed."""
    return {
        str(r.get("rule_id") or "")
        for r in load_ledger(ledger_path=ledger_path)
        if r.get("rule_id")
    }


def _append_ledger(
    entry: dict[str, typing.Any],
    *,
    ledger_path: pathlib.Path | None = None,
) -> None:
    lp = ledger_path or resolve_ledger_path()
    lp.parent.mkdir(parents=True, exist_ok=True)
    with lp.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":"), default=str) + "\n")
    try:
        lp.chmod(0o600)
    except OSError:
        pass


def peek_latest_application(
    rule_id: str,
    *,
    ledger_path: pathlib.Path | None = None,
) -> dict[str, typing.Any] | None:
    """Return the most recent application record for ``rule_id`` WITHOUT
    mutating the ledger. Returns ``None`` when no such rule_id was ever
    applied.

    Used by :func:`record_revoked_in_ledger` callers that need to perform
    a bouncer-side removal BEFORE marking the ledger ([[ibounce-honest-
    positioning]] — ledger must reflect bouncer state, never advertise
    a revoke that didn't actually land).
    """
    lp = ledger_path or resolve_ledger_path()
    records = [
        r for r in load_ledger(ledger_path=lp)
        if str(r.get("rule_id") or "") == rule_id
    ]
    if not records:
        return None
    return records[-1]


def record_revoked_in_ledger(
    rule_id: str,
    prior: dict[str, typing.Any],
    *,
    ledger_path: pathlib.Path | None = None,
) -> None:
    """Append a ``status="revoked"`` record for ``rule_id`` to the
    append-only ledger. Caller is expected to have already performed
    the bouncer-side removal — this function MUST NOT be called when
    the bouncer removal failed (would violate [[ibounce-honest-
    positioning]] by claiming a revoke that didn't actually land)."""
    lp = ledger_path or resolve_ledger_path()
    _append_ledger(
        {
            "rule_id": rule_id,
            "status": "revoked",
            "revoked_at": _now_iso(),
            "previous_artifact_id": prior.get("applied_artifact_id"),
            "previous_action": prior.get("action"),
        },
        ledger_path=lp,
    )


def remove_from_ledger(
    rule_id: str,
    *,
    ledger_path: pathlib.Path | None = None,
) -> dict[str, typing.Any] | None:
    """Legacy peek-and-mark helper. Mark a rule_id as revoked in the
    ledger. Appends a ``status="revoked"`` record (the ledger is
    append-only) + returns the most recent application record for the
    rule_id. Returns None when no such rule_id was ever applied.

    DEPRECATED for the revoke flow — prefer the
    :func:`peek_latest_application` + :func:`record_revoked_in_ledger`
    pair so the ledger update can be deferred until AFTER the bouncer
    removal succeeds (see [[ibounce-honest-positioning]]). Retained for
    backward compatibility + tests that only exercise the ledger side.
    """
    latest = peek_latest_application(rule_id, ledger_path=ledger_path)
    if latest is None:
        return None
    record_revoked_in_ledger(rule_id, latest, ledger_path=ledger_path)
    return latest


# ---------------------------------------------------------------------------
# Audit emission (best-effort)
# ---------------------------------------------------------------------------


def _emit_admin_action(
    *,
    kind: str,
    rule_id: str,
    extra: dict[str, typing.Any] | None = None,
) -> None:
    """Best-effort admin_action OCSF emit. No-op outside the bouncer
    serve process (the autopilot loop runs out-of-process — the emit
    falls through quietly + the applied-ledger is the durable record)."""
    try:
        from ..bouncer.audit_export.admin_action import emit_admin_action_direct
        from ..bouncer.proxy import _emit_audit_event
    except Exception:
        return
    try:
        emit_admin_action_direct(
            _emit_audit_event,
            kind=kind,
            actor="threat-feed-applier",
            target_kind="threat_feed_entry",
            target_id=rule_id,
            source="autopilot",
            extra=extra or {},
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Bouncer-side apply
# ---------------------------------------------------------------------------


def _apply_dynamic_deny(
    entry: FeedEntry,
    *,
    skip_fanout: bool = False,
    bouncer_url_overrides: typing.Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Apply a ``dynamic_deny`` entry via the existing ``add_rule``
    path. Returns ``(artifact_id, explanation)``; raises on failure."""
    from ..dynamic_denies.operations import DenyOperationError, add_rule
    from ..dynamic_denies.store import DynamicDenyWriteError

    targets = [entry.target] if entry.target else list(entry.action)
    if not targets:
        raise RuntimeError(
            f"dynamic_deny entry {entry.rule_id} has no target or action"
        )
    reason = (
        f"threat-feed:{entry.rule_id} — {entry.source_incident or entry.description}"
    )
    # The feed's applies_to_bouncers becomes the routing override so
    # the resolver doesn't need to classify the target itself (which is
    # fragile for cross-product feeds).
    bouncer_overrides = list(entry.applies_to_bouncers) or None
    try:
        result = add_rule(
            targets=targets,
            reason=reason,
            duration="permanent",
            applies_to_recommender=True,
            bouncer_overrides=bouncer_overrides,
            bouncer_url_overrides=bouncer_url_overrides,
            source="threat-feed",
            skip_fanout=skip_fanout,
        )
    except (DenyOperationError, DynamicDenyWriteError) as e:
        raise RuntimeError(f"dynamic_deny add failed: {e}") from e
    artifact_id = str(result.get("id") or "")
    explanation = str(result.get("routing_explanation") or "")
    return artifact_id, explanation


def _enqueue_pending(
    entry: FeedEntry,
    *,
    profile_name: str = "",
) -> str:
    """Enqueue an entry into the §A25 pending-approval queue. Returns
    the ``pa_<ULID>`` ticket id."""
    from ..profile_allow.operations import _enqueue_pending as _pa_enqueue

    reason = (
        f"threat-feed:{entry.rule_id} severity={entry.severity.value} "
        f"-- {entry.source_incident or entry.description}"
    )
    target = entry.target or "(no_target)"
    actions = list(entry.action) or [entry.rule_kind]
    queue_kind = (
        "threat_feed_dynamic_deny"
        if entry.rule_kind == "dynamic_deny"
        else f"threat_feed_{entry.rule_kind}"
    )
    extra = {
        "rule_kind": entry.rule_kind,
        "severity": entry.severity.value,
        "source_incident": entry.source_incident,
        "compliance_tags": list(entry.compliance_tags),
        "applies_to_bouncers": list(entry.applies_to_bouncers),
        "feed_rule_id": entry.rule_id,
    }
    rec = _pa_enqueue(
        target=target,
        actions=actions,
        reason=reason,
        duration=None,
        expires_at=None,
        profile_name=profile_name or "(threat-feed)",
        actor="threat-feed-applier",
        source="threat-feed",
        kind=queue_kind,
        extra=extra,
    )
    return str(rec.get("id") or "")


# ---------------------------------------------------------------------------
# Public apply entrypoint
# ---------------------------------------------------------------------------


def apply_feed_entries(
    feed: Feed,
    subscription: Subscription,
    *,
    posture: str = "ambient",
    skip_fanout: bool = False,
    bouncer_url_overrides: typing.Mapping[str, str] | None = None,
    ledger_path: pathlib.Path | None = None,
    notify_stream: typing.IO[str] | None = None,
    dry_run: bool = False,
    skip_already_applied: bool = True,
) -> list[ApplyOutcome]:
    """Verify + classify + apply every entry in ``feed``.

    Returns one :class:`ApplyOutcome` per entry. The applied-ledger
    receives one append per processed entry (verification-failed
    entries get a record too so the operator can see them via
    ``iam-jit updates list --show-refused``).

    ``dry_run=True`` runs verification + classification but skips
    bouncer-side mutation + ledger writes. Use for the
    ``iam-jit updates dry-run`` CLI surface.
    """
    notify_stream = notify_stream if notify_stream is not None else sys.stderr
    already_applied = applied_rule_ids(ledger_path=ledger_path) if skip_already_applied else set()
    out: list[ApplyOutcome] = []

    for entry in feed.entries:
        # 1. Already applied?
        if entry.rule_id in already_applied:
            outcome = ApplyOutcome(
                rule_id=entry.rule_id,
                verified=True,
                verification_reason="ledger_hit",
                action="refused_already_applied",
                severity=entry.severity,
                rule_kind=entry.rule_kind,
                target=entry.target,
                explanation="rule_id already present in applied-ledger",
            )
            out.append(outcome)
            continue

        # 2. Verify signature.
        verify = _verify_entry(entry, subscription)
        if not verify.verified:
            outcome = ApplyOutcome(
                rule_id=entry.rule_id,
                verified=False,
                verification_reason=verify.reason,
                action="refused_verification",
                severity=entry.severity,
                rule_kind=entry.rule_kind,
                target=entry.target,
                explanation=(
                    f"signature verify failed: {verify.reason}; "
                    f"per [[ibounce-honest-positioning]] unsigned/invalid "
                    f"entries are NEVER applied"
                ),
            )
            out.append(outcome)
            _emit_admin_action(
                kind="threat_feed.entry.refused",
                rule_id=entry.rule_id,
                extra={
                    "reason": verify.reason,
                    "publisher_expected": subscription.publisher_pubkey[:32],
                    "feed_url": subscription.url,
                    "compliance_tags": list(entry.compliance_tags),
                },
            )
            if not dry_run:
                _append_ledger(
                    {
                        "rule_id": entry.rule_id,
                        "status": "refused_verification",
                        "applied_at": _now_iso(),
                        "feed_url": subscription.url,
                        "severity": entry.severity.value,
                        "rule_kind": entry.rule_kind,
                        "target": entry.target,
                        "verification_reason": verify.reason,
                        "compliance_tags": list(entry.compliance_tags),
                    },
                    ledger_path=ledger_path,
                )
            continue

        # 3. Classify per severity + posture + threshold.
        action = classify_apply_action(
            entry.severity,
            threshold=subscription.severity_auto_apply_threshold,
            posture=posture,
        )

        if dry_run:
            outcome = ApplyOutcome(
                rule_id=entry.rule_id,
                verified=True,
                verification_reason="ok",
                action=action,
                severity=entry.severity,
                rule_kind=entry.rule_kind,
                target=entry.target,
                explanation=f"dry_run: would have done {action}",
            )
            out.append(outcome)
            continue

        # 4. Apply per action.
        artifact_id = ""
        pending_id = ""
        error = ""
        explanation = ""

        try:
            if action in ("auto_apply", "auto_apply_notify"):
                if entry.rule_kind == "dynamic_deny":
                    artifact_id, explanation = _apply_dynamic_deny(
                        entry,
                        skip_fanout=skip_fanout,
                        bouncer_url_overrides=bouncer_url_overrides,
                    )
                elif entry.rule_kind == "profile_safety_floor_extension":
                    # MVP: route via the pending queue so the operator
                    # explicitly opts in. Profile-floor mutation needs
                    # operator review per [[creates-never-mutates]].
                    pending_id = _enqueue_pending(entry)
                    action = "pending_approval"
                    explanation = (
                        "profile_safety_floor_extension queued for "
                        "operator confirmation; auto-apply gated until "
                        "operator runs `iam-jit profile allow --approve <id>`"
                    )
                elif entry.rule_kind == "scope_primitive_recommendation":
                    pending_id = _enqueue_pending(entry)
                    action = "pending_approval"
                    explanation = (
                        "scope_primitive_recommendation queued for "
                        "operator review; will not auto-apply to roles"
                    )
                elif entry.rule_kind == "informational_alert":
                    action = "informational"
                    explanation = "informational only; no bouncer state change"
                else:
                    action = "informational"
                    explanation = (
                        f"unknown rule_kind {entry.rule_kind!r}; "
                        f"recorded only"
                    )

                if action == "auto_apply_notify" and notify_stream:
                    notify_stream.write(
                        f"[threat-feed] auto-applied HIGH-severity rule "
                        f"{entry.rule_id} from {subscription.label()} "
                        f"({entry.source_incident or entry.description})\n"
                    )

            elif action == "pending_approval":
                pending_id = _enqueue_pending(entry)
                explanation = (
                    f"queued for operator review via §A25 pending queue "
                    f"(ticket {pending_id})"
                )
            elif action == "informational":
                explanation = "LOW severity — informational only"
            elif action == "managed_refused":
                explanation = (
                    "posture=managed refuses auto-apply; review via "
                    "`iam-jit updates list` + apply manually via PR"
                )
            else:  # pragma: no cover
                explanation = f"unhandled action {action!r}"

        except Exception as e:
            error = str(e)
            explanation = f"apply failed: {e}"
            logger.warning(
                "threat_feed apply failed for %s: %s", entry.rule_id, e,
            )

        outcome = ApplyOutcome(
            rule_id=entry.rule_id,
            verified=True,
            verification_reason="ok",
            action=action,
            severity=entry.severity,
            rule_kind=entry.rule_kind,
            target=entry.target,
            applied_artifact_id=artifact_id,
            pending_entry_id=pending_id,
            error=error,
            explanation=explanation,
        )
        out.append(outcome)

        # 5. Ledger + audit.
        _append_ledger(
            {
                "rule_id": entry.rule_id,
                "status": "applied" if not error else "error",
                "action": action,
                "applied_at": _now_iso(),
                "feed_url": subscription.url,
                "feed_id": feed.feed_id,
                "publisher": feed.publisher,
                "severity": entry.severity.value,
                "rule_kind": entry.rule_kind,
                "target": entry.target,
                "applied_artifact_id": artifact_id,
                "pending_entry_id": pending_id,
                "compliance_tags": list(entry.compliance_tags),
                "source_incident": entry.source_incident,
                "discovered_at": entry.discovered_at,
                "applies_to_bouncers": list(entry.applies_to_bouncers),
                "error": error,
                "verification_publisher": verify.publisher,
                "verification_algorithm": verify.algorithm,
            },
            ledger_path=ledger_path,
        )
        kind_map = {
            "auto_apply": "threat_feed.applied",
            "auto_apply_notify": "threat_feed.applied",
            "pending_approval": "threat_feed.queued",
            "informational": "threat_feed.recorded",
            "managed_refused": "threat_feed.refused_managed",
        }
        _emit_admin_action(
            kind=kind_map.get(action, "threat_feed.recorded"),
            rule_id=entry.rule_id,
            extra={
                "severity": entry.severity.value,
                "rule_kind": entry.rule_kind,
                "applied_artifact_id": artifact_id,
                "pending_entry_id": pending_id,
                "feed_url": subscription.url,
                "compliance_tags": list(entry.compliance_tags),
            },
        )

    return out


__all__ = [
    "APPLIED_LEDGER_ENV",
    "ApplyOutcome",
    "applied_rule_ids",
    "apply_feed_entries",
    "classify_apply_action",
    "load_ledger",
    "peek_latest_application",
    "record_revoked_in_ledger",
    "remove_from_ledger",
    "resolve_ledger_path",
]
