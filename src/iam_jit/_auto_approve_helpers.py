"""Shared MFA-enforcement + provisioning-attempt + stuck-provisioning sweep.

These were previously duplicated between `routes/requests.py` (the API
submit + approver paths) and `auto_approve_evaluator.py` (the centralised
gate that both web paste-form and API submit dispatch through). Per
`[[cross-product-agent-parity]]` the duplication was a "kept-in-sync-
by-discipline" twin — comments in both files noted the duplication
existed only to avoid a circular import (routes → evaluator → routes).

This module is a LEAF — it imports from `iam_jit.auto_approve`,
`iam_jit.self_approve_reductions`, and the provisioning / lifecycle /
assume modules, but it does NOT import from `routes/*` or from
`auto_approve_evaluator`. That makes the cited circular-import concern
structurally impossible: both callers depend on this module, this
module depends on neither caller.

Per `[[ibounce-honest-positioning]]`: if the two call sites need to
differ in behavior, expose that as a parameter or wrap the helper —
NEVER fork the implementation. The shape that landed here is the more-
parameterised one (the evaluator's `_attempt_provisioning` took its
provisioning / lifecycle / assume modules as kwargs); the previous
routes/* shape was the lazy form that closed over module-level imports.

Test discipline (per `docs/CONTRIBUTING.md`):
  - Test changes via BOTH call sites' regression suites
  - Neither caller should re-export these as public API (the
    underscore-prefixed names communicate intent)
  - The state-verification parity tests in
    `tests/test_auto_approve_helpers_parity.py` assert observable
    extraction state (imports wired, no local twins, sabotage-check
    proves the wire is load-bearing).

#601 (independent code review 2026-05-25 HIGH-4).
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
from typing import Any

logger = logging.getLogger("iam_jit.auto_approve_helpers")


# #610 — provisioning_timeout watchdog default. Operators can override
# via `IAM_JIT_PROVISIONING_TIMEOUT_MINUTES`. 15 minutes is a generous
# upper bound for the synchronous provisioning path (which usually
# completes in <2s); anything stuck past this is almost certainly a
# crashed background task / wedged STS call / lost-then-recovered
# network partition that left the request dict mid-update.
DEFAULT_PROVISIONING_TIMEOUT_MINUTES = 15


def apply_mfa_and_self_approve_enforcement(
    auto_decision: Any,
    *,
    mfa_audit: dict[str, Any],
    self_approve_audit: dict[str, Any],
    analysis_score: int,
    user_id: str,
) -> tuple[Any, str, dict[str, Any] | None]:
    """Apply MFA + self-approve enforcement on top of the score-gate decision.

    Returns `(effective_decision, audit_actor, mfa_block_response)` where
      - `effective_decision` is the (possibly-overridden) AutoApproveDecision
        the caller should treat as authoritative.
      - `audit_actor` is the string written to the audit log
        ("system:auto-approver" by default; "self_approve_reduction:<id>"
        when the self-approve override fired).
      - `mfa_block_response` is a dict with structured fields the route
        can splat into the response body so the API client knows to
        re-authenticate. None when no MFA override fired.

    Enforcement order is deliberate:

    1. Self-approve override runs FIRST. If the user qualifies as an admin
       doing a reduction of their OWN authority, flip auto_decision to
       approve here. The MFA gate (stage 2) will then run against this
       FLIPPED decision so a self-approved high-risk request still
       requires fresh MFA.

       Override-eligible auto_approve reasons (the cases where the user
       would otherwise be deadlocked into human review):
         - "above_threshold"  — score-gate denial; self-approve flips it
         - "feature_disabled" — auto-approve disabled or unconfigured
           (the solo-mode default: `auto_approve_risk_below` is None).
           Without this, the solo-founder UX deadlocks: admin submits
           reduction, lands in pending, four-eyes refuses approver==
           owner. The self-approve gate's whole purpose is to short-
           circuit that case for admins reducing their own authority.

       WB13-08 closure: previously MFA ran first and only fired when
       auto_decision.auto_approve was originally True. Score-gate
       denial bypassed MFA, then self-approve flipped to True
       unconditionally — an admin with stale MFA could auto-provision
       a high-risk role. Reordering self-approve → MFA closes that
       gap so MFA is the final word regardless of intermediate flips.

       NOT override-eligible (platform-team floors / explicit denies):
         - strict_mode_action_wildcard, strict_mode_admin_fallback —
           deploy-time policy ceiling admins cannot individually override
           (per WB12-08).
         - toggle_force_review — admin-curated "always send to review"
           toggle; flipping would defeat its purpose.
         - service_blocked, account_blocked — blocklist floors. The SAR
           gate already enforces service_blocked (returns not-eligible);
           account_blocked is enforced here.
         - over_quota — anti-composability defense; chained low-risk
           reductions should still surface at the cap.
         - no_policy — nothing to grant; not actionable.

    2. MFA enforcement runs on the (possibly self-approve-flipped) decision.
       If the effective decision is approve AND the request is high-risk
       AND MFA is missing/stale → BLOCK with mfa_required_for_high_risk.
       Audit actor reverts to system since MFA is a system gate (not a
       user action).

    WB12-04 closure: use truthy-vs-falsy comparison rather than
    `is True` / `is False`. Any falsy / truthy values returned by the
    audit dicts (e.g., a future mfa_gate that returns a bool-like
    object, or a missing key returning None) are handled safely.

    WB12-11 closure: do NOT leak the original (would-have-been) reason
    or score back to the caller. A stale-MFA attacker probing for "what
    was the score" by submitting variations benefits from the oracle.
    Audit chain still captures everything; the response body strips it.

    WB13-09 closure: `mfa_step_up_at_score` is the score-floor at or
    above which MFA is required, not a duration. Was mis-labeled
    `_max_age_seconds` previously (copy/paste from the cookie max-age
    field).
    """
    _would_require_mfa = bool(mfa_audit.get("would_require_mfa"))
    _mfa_present = bool(mfa_audit.get("mfa_present"))
    _self_approve_eligible = bool(self_approve_audit.get("self_approve_eligible"))

    # Track the audit actor through the override chain.
    effective_decision = auto_decision
    audit_actor = "system:auto-approver"

    # STAGE 1: Self-approve override.
    _override_eligible_reasons = ("above_threshold", "feature_disabled")
    if (
        not bool(getattr(effective_decision, "auto_approve", False))
        and getattr(effective_decision, "reason", "") in _override_eligible_reasons
        and _self_approve_eligible
    ):
        _original_reason = getattr(effective_decision, "reason", "")
        from .auto_approve import AutoApproveDecision
        from . import self_approve_reductions as _sar_mod
        effective_decision = AutoApproveDecision(
            auto_approve=True,
            reason="self_approve_reduction",
            details={
                "score": analysis_score,
                "original_reason": _original_reason,
                "self_approve_reason": self_approve_audit.get("self_approve_reason"),
                "details_pre_override": dict(getattr(auto_decision, "details", {}) or {}),
            },
        )
        audit_actor = _sar_mod.audit_actor_for(user_id)

    # STAGE 2: MFA enforcement on the (possibly-flipped) decision.
    if (
        bool(getattr(effective_decision, "auto_approve", False))
        and _would_require_mfa
        and not _mfa_present
    ):
        from .auto_approve import AutoApproveDecision
        blocked = AutoApproveDecision(
            auto_approve=False,
            reason="mfa_required_for_high_risk",
            details={
                "mfa_step_up_required": True,
                "mfa_step_up_at_score": mfa_audit.get("mfa_step_up_floor"),
                "client_action": "re_authenticate_via_oidc",
            },
        )
        block_response = {
            "mfa_step_up_required": True,
            "reason": "fresh_mfa_required",
            "redirect_to": "/api/v1/auth/oidc/login",
        }
        # Actor reverts to system: MFA is a platform gate, not a user
        # decision. Even if self-approve fired first, the MFA block
        # takes precedence in the actor field.
        return blocked, "system:auto-approver", block_response

    return effective_decision, audit_actor, None


def attempt_provisioning(
    req: dict[str, Any],
    *,
    accounts_store: Any,
    provision_mod: Any,
    assume_mod: Any,
    lifecycle: Any,
    github_mint: Any = None,
    installations_path: str | None = None,
) -> None:
    """Synchronously provision after approval / auto-approve, persist
    result/error.

    GUARANTEE: this function NEVER raises. The state of the request
    after this returns is one of:
      - 'active' (provisioning succeeded, provisioned details populated)
      - 'provisioning_failed' (with provisioning_error set in status)
      - unchanged (only if the request wasn't in 'provisioning' to begin
        with, which means apply_transition didn't move it — that's fine)

    The all-failures-must-land-somewhere guarantee is what keeps requests
    from getting stuck in 'provisioning' and forces the UI to surface
    the failure to the approver. Callers MUST be able to call
    store.put() after this returns and rely on the state being terminal-
    or-actionable.

    Module dependencies are passed in (not imported here) because the
    two call sites — `routes/requests.py` and `auto_approve_evaluator.py`
    — already have their own canonical references to these modules and
    the leaf-module discipline forbids inbound imports from either
    caller. Passing as kwargs also makes test stubbing trivial.
    """
    logger_p = logging.getLogger("iam_jit.provisioning")

    # GitHubTokenRequest rides the SAME approve→provisioning→active path as an
    # AWS RoleRequest, but "provisioning" means minting a scoped GitHub App
    # installation token instead of creating an IAM role. Same terminal-state
    # guarantee (active | provisioning_failed). github_mint is injectable for
    # hermetic tests; default mints against the configured installation registry.
    if (req.get("kind") or "RoleRequest") == "GitHubTokenRequest":
        _attempt_github_provisioning(
            req, lifecycle=lifecycle, github_mint=github_mint,
            installations_path=installations_path,
        )
        return

    try:
        result = provision_mod.provision(req, accounts_store=accounts_store)
    except provision_mod.ProvisioningError as e:
        logger_p.warning("provisioning failed: %s", e)
        safe_mark_failed(req, str(e), lifecycle=lifecycle)
        return
    except Exception as e:
        logger_p.exception("unexpected error during provisioning")
        safe_mark_failed(req, f"unexpected error: {e}", lifecycle=lifecycle)
        return

    # Result-building can also raise (template render, dataclass access).
    # Belt and suspenders.
    try:
        instructions = assume_mod.render_instructions(
            req,
            role_arn=result.role_arn,
            external_id=result.external_id,
        )
        provisioned = {
            "role_arn": result.role_arn,
            "role_name": result.role_name,
            "account_id": result.account_id,
            "external_id": result.external_id,
            "assumer_principal_arn": result.assumer_principal_arn,
            "session_name": result.session_name,
            "expires_at": result.expires_at,
            "assume_instructions": instructions["assume_instructions"],
            "aws_cli_replay": list(result.aws_cli_replay),
            "creation_succeeded": True,
            # #324f — surface embedded dynamic-deny rule ids so the
            # UI / `iam-jit show` / audit replay sees which rules
            # contributed to the role's policy without re-parsing the
            # inline policy JSON.
            "embedded_dynamic_denies": list(
                getattr(result, "embedded_dynamic_denies", []) or []
            ),
        }
    except Exception as e:
        logger_p.exception("post-provision result rendering failed")
        safe_mark_failed(
            req,
            f"role created but result rendering failed: {e}. "
            "Check audit log; manual cleanup may be needed.",
            lifecycle=lifecycle,
        )
        return

    try:
        lifecycle.mark_provisioned(req, provisioned=provisioned)
    except Exception as e:
        logger_p.exception("mark_provisioned failed")
        safe_mark_failed(
            req,
            f"role created but state transition failed: {e}",
            lifecycle=lifecycle,
        )


def _attempt_github_provisioning(
    req: dict[str, Any],
    *,
    lifecycle: Any,
    github_mint: Any = None,
    installations_path: str | None = None,
) -> None:
    """Mint a scoped GitHub App installation token for a GitHubTokenRequest.

    The access level maps DIRECTLY to a GitHub permission preset (no scorer).
    duration_minutes (<=60) is honored by setting status.provisioned.github.
    expires_at to the requested cutoff so the existing expiry sweep early-
    revokes; GitHub's own 1h ceiling is the backstop. The minted token is
    stored under status._secret_github_token (server-only; redacted from
    summarize() and every list/API view) so the operator can early-revoke;
    it is shown to the requester exactly once via the claim flow. NEVER raises
    (same terminal-state guarantee as the AWS path)."""
    import datetime as _dt

    logger_p = logging.getLogger("iam_jit.provisioning")
    try:
        from . import github_scope
        from .github_installations import default_registry_path

        spec = req.get("spec") or {}
        gh = spec.get("github") or {}
        org = gh["org"]
        repositories = list(gh["repositories"])
        duration_minutes = int(gh.get("duration_minutes") or 60)
        duration_minutes = max(1, min(60, duration_minutes))
        # permissions are the GitHub {category: read|write} map, passed straight
        # through to the mint (no preset/level translation).
        permissions = github_scope.normalize_permissions(gh["permissions"])

        path = installations_path or default_registry_path()
        if github_mint is not None:
            tok = github_mint(org=org, repositories=repositories, permissions=permissions)
        else:
            tok = github_scope.mint_github_token(
                installations_path=path, org=org,
                repositories=repositories, permissions=permissions,
            )
    except Exception as e:  # noqa: BLE001 — terminal-state guarantee
        logger_p.warning("github token mint failed: %s", e)
        safe_mark_failed(req, f"github token mint failed: {e}", lifecycle=lifecycle)
        return

    try:
        now = _dt.datetime.now(_dt.UTC)
        expires_at = (now + _dt.timedelta(minutes=duration_minutes)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        provisioned = {
            # Top-level expires_at mirrors the github cutoff so the existing
            # dashboard-fade + expiry sweep treat a GitHub grant exactly like an
            # AWS one (no expiry-path changes needed). GitHub's own 1h ceiling
            # is the hard backstop if a sub-hour sweep is late.
            "expires_at": expires_at,
            "github": {
                "org": org,
                "repositories": list(getattr(tok, "repositories", None) or repositories),
                "permissions": dict(getattr(tok, "permissions", None) or permissions),
                "expires_at": expires_at,
                "token_active": True,
            },
            "creation_succeeded": True,
        }
        lifecycle.mark_provisioned(req, provisioned=provisioned)
        # Stash the secret token AFTER the transition (status now exists).
        # status.additionalProperties:true allows this; summarize() never reads
        # it and the web/API serializers redact it.
        req.setdefault("status", {})["_secret_github_token"] = tok.token
    except Exception as e:  # noqa: BLE001
        logger_p.exception("post-mint github result handling failed")
        safe_mark_failed(
            req, f"github token minted but state transition failed: {e}",
            lifecycle=lifecycle,
        )


def safe_mark_failed(
    req: dict[str, Any], error: str, *, lifecycle: Any
) -> None:
    """Set state=provisioning_failed without ever raising.

    If the request isn't in 'provisioning' state (e.g., a bug elsewhere
    advanced it already), we can't transition — but we can still record
    the error in status.provisioning_error so the UI sees something.

    Per #599 the last-resort fallback (after both `mark_provisioning_failed`
    and the manual dict mutation fail) logs loudly. The contract is
    "NEVER raises" so we can't propagate, but a silent pass leaves
    operators blind to a fully-broken request dict.
    """
    logger_p = logging.getLogger("iam_jit.provisioning")
    try:
        lifecycle.mark_provisioning_failed(req, error=error)
    except lifecycle.IllegalTransition:
        # Already moved past 'provisioning'. Record the error anyway.
        try:
            req.setdefault("status", {})["provisioning_error"] = error
        except Exception:
            logger_p.exception("failed to record provisioning error on request")
    except Exception:
        logger_p.exception("mark_provisioning_failed itself raised")
        try:
            req.setdefault("status", {})["provisioning_error"] = error
            req["status"]["state"] = "provisioning_failed"
        except Exception:
            # #599: last-resort fallback after both transition + manual
            # dict mutation failed. Cannot raise (caller contract is
            # "NEVER raises"), but the silent pass that used to live
            # here meant a totally broken request dict left zero
            # operator trace. Log loudly even though we can't recover.
            logger_p.exception(
                "_auto_approve_helpers: last-resort manual status mutation "
                "in safe_mark_failed also raised; the request dict is in "
                "an indeterminate state (error_message=%r)",
                error,
            )


def _parse_iso8601_z(value: str) -> _dt.datetime | None:
    """Parse the ISO8601 'Z' timestamps lifecycle._now() emits.

    Returns None on any parse failure so callers can treat the request
    as "no timestamp available" rather than blowing up the sweep on a
    single malformed record.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        # Accept both `...Z` (lifecycle._now shape) and `+00:00`.
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = _dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.UTC)
        return parsed
    except (ValueError, TypeError):
        return None


def _last_state_change_at(req: dict[str, Any]) -> _dt.datetime | None:
    """Find when the request entered its current state.

    Prefers the most recent history entry's `at` (which is the canonical
    "when did state change" record). Falls back to status.last_updated_at,
    then status.submitted_at. None means "no parseable timestamp."
    """
    status = req.get("status") or {}
    history = status.get("history") or []
    if isinstance(history, list) and history:
        # Walk backwards for the most recent transition into the current
        # state (any entry, since the latest one IS the current state
        # given _commit_system appends in order).
        for ev in reversed(history):
            if not isinstance(ev, dict):
                continue
            parsed = _parse_iso8601_z(str(ev.get("at") or ""))
            if parsed is not None:
                return parsed
    for fallback_key in ("last_updated_at", "submitted_at"):
        parsed = _parse_iso8601_z(str(status.get(fallback_key) or ""))
        if parsed is not None:
            return parsed
    return None


def sweep_stuck_provisioning(
    store: Any,
    *,
    lifecycle: Any,
    now: _dt.datetime | None = None,
    timeout_minutes: int | None = None,
) -> list[dict[str, Any]]:
    """Transition any request stuck in `provisioning` past the timeout
    to `provisioning_failed` with a `provisioning_timeout` reason.

    Per `[[ibounce-honest-positioning]]` (no silent zombie): even with
    the synchronous approve path always invoking provisioning, async
    edge cases (process crashed mid-provision, background task lost
    its handle, retry hung on STS) can leave requests wedged in
    `provisioning`. The watchdog is the floor that guarantees a
    request can NEVER stay in `provisioning` indefinitely; it bounds
    the worst-case time-to-actionable-state at `timeout_minutes`.

    Returns the list of summary dicts for swept requests so callers
    (CLI sweep command, periodic background worker) can log + report.
    NEVER raises — bad timestamps / store errors are logged and
    skipped. Per #599 we surface partial failures loudly so a
    fully-broken request leaves operator trace.

    Configurable per-deployment via
    `IAM_JIT_PROVISIONING_TIMEOUT_MINUTES` env var (default 15).
    """
    if timeout_minutes is None:
        try:
            timeout_minutes = int(
                os.environ.get("IAM_JIT_PROVISIONING_TIMEOUT_MINUTES")
                or DEFAULT_PROVISIONING_TIMEOUT_MINUTES
            )
        except (ValueError, TypeError):
            timeout_minutes = DEFAULT_PROVISIONING_TIMEOUT_MINUTES
    if timeout_minutes <= 0:
        # 0 / negative disables the sweep — useful for ops who want to
        # turn it off without modifying code.
        return []

    if now is None:
        now = _dt.datetime.now(_dt.UTC)
    timeout = _dt.timedelta(minutes=timeout_minutes)
    swept: list[dict[str, Any]] = []

    try:
        ids = list(store.list_ids())
    except Exception:
        logger.exception("sweep_stuck_provisioning: store.list_ids() raised")
        return []

    for rid in ids:
        try:
            req = store.get(rid)
        except Exception:
            logger.exception(
                "sweep_stuck_provisioning: store.get(%r) raised; skipping", rid,
            )
            continue
        status = req.get("status") or {}
        if status.get("state") != "provisioning":
            continue
        entered_at = _last_state_change_at(req)
        if entered_at is None:
            # Can't determine age. Conservatively skip so we don't
            # falsely fail a freshly-submitted request whose
            # timestamps are mid-write. The operator-facing dashboard
            # will still surface it as "stuck" via state==provisioning.
            continue
        if (now - entered_at) < timeout:
            continue
        # Stuck past the timeout — transition to provisioning_failed
        # with a structured reason so the audit chain captures the
        # watchdog decision (operators can grep for the literal
        # "provisioning_timeout" string in the audit log).
        reason = (
            f"provisioning_timeout: request was in 'provisioning' for "
            f"more than {timeout_minutes} minutes; the synchronous "
            f"provisioning call did not complete. Inspect the "
            f"`iam_jit.provisioning` log around {entered_at.isoformat()} "
            f"for the original failure."
        )
        safe_mark_failed(req, reason, lifecycle=lifecycle)
        try:
            store.put(rid, req)
        except Exception:
            logger.exception(
                "sweep_stuck_provisioning: store.put(%r) raised after "
                "marking failed; the in-memory state is updated but the "
                "persisted record may be stale", rid,
            )
            continue
        try:
            from . import audit as _audit
            _audit.emit(
                actor="system:provisioning_timeout_sweep",
                kind="request.provisioning_timeout",
                summary=(
                    f"swept stuck provisioning request {rid} "
                    f"(>{timeout_minutes}min)"
                ),
                details={
                    "request_id": rid,
                    "entered_provisioning_at": entered_at.isoformat(),
                    "timeout_minutes": timeout_minutes,
                    "reason": "provisioning_timeout",
                },
            )
        except Exception:
            logger.exception(
                "sweep_stuck_provisioning: audit.emit for %r raised", rid,
            )
        swept.append(
            {
                "request_id": rid,
                "entered_provisioning_at": entered_at.isoformat(),
                "timeout_minutes": timeout_minutes,
                "new_state": (req.get("status") or {}).get("state"),
            }
        )
    return swept
