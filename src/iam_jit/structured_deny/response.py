"""Structured agent-facing deny response (#402) + ``iam_jit_handle_deny`` MCP.

Two callers consume this module:

  1. The agent-facing 403 wrapper (when the bouncer denies a request,
     the wrapper attaches a structured payload built here as the
     response body).
  2. The MCP tool ``iam_jit_handle_deny`` (agent calls this after
     seeing a 403 to get the full structured context + recent audit
     trail).

Per ``[[ambient-value-prop-and-friction-framing]]`` every operator-facing
string here LEADS with ``caught_by_bouncer`` framing, NEVER ``ERROR``
/ ``DENIED`` / ``BLOCKED``.

Per ``[[creates-never-mutates]]`` this module never mutates a profile;
it only computes recommendations.

Per ``[[scorer-is-ground-truth]]`` the injection-classifier IS a
heuristic — we ship the ``ambiguous`` placeholder today and the #404
LLM classifier (sibling agent) plugs in via the
``IAM_JIT_INJECTION_CLASSIFIER_HOOK`` env-var dispatch when ready.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants (recommended_action enum + injection-classification enum)
# ---------------------------------------------------------------------------

RECOMMENDED_ACTION_EASY_ALLOW = "easy-allow"
"""Operator-friendly outcome: the deny looks legitimate; the agent can
prompt the operator with the ``suggested_allow_command`` (or
auto-allow if ``IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT`` is set)."""

RECOMMENDED_ACTION_HALT_ESCALATE = "halt+escalate"
"""High-confidence-adversarial outcome: the agent SHOULD NOT silently
work around the deny; surface to operator with explicit escalation."""

RECOMMENDED_ACTION_REPHRASE_RETRY = "rephrase+retry"
"""The deny was structural (e.g., dynamic-deny rule, org-distributed
floor) and the agent should rephrase its approach or pick a different
resource rather than ask for an allow."""

INJECTION_APPEARS_LEGITIMATE = "appears_legitimate"
INJECTION_AMBIGUOUS = "ambiguous"
INJECTION_APPEARS_ADVERSARIAL = "appears_adversarial"
INJECTION_PENDING_CLASSIFICATION = "pending_classification"
"""§A93 / #509 Phase 2 — local-dev / agent-in-loop default. The
synchronous LLM-classifier call has been REMOVED from the deny
hot-path per [[bouncer-zero-llm-when-agent-in-loop]]. When the
deterministic backstop (structural heuristic + KNOWN_ADVERSARIAL
match) does NOT flag the deny AND no env-pinned hook is configured,
classification is deferred to the agent: the agent receives the
``deny_event_id`` on the 403 body + calls the
``iam_jit_classify_deny`` MCP tool (which uses the agent's OWN
LLM via Claude Code / Cursor / etc.) to fill the gap. This avoids
making local-dev users supply API credits."""

_VALID_RECOMMENDED_ACTIONS = frozenset({
    RECOMMENDED_ACTION_EASY_ALLOW,
    RECOMMENDED_ACTION_HALT_ESCALATE,
    RECOMMENDED_ACTION_REPHRASE_RETRY,
})

_VALID_INJECTION_CLASSIFICATIONS = frozenset({
    INJECTION_APPEARS_LEGITIMATE,
    INJECTION_AMBIGUOUS,
    INJECTION_APPEARS_ADVERSARIAL,
    INJECTION_PENDING_CLASSIFICATION,
})

# Env-var-driven opt-in to keep the synchronous bouncer-side LLM
# classifier path in standalone-mode deployments (CI / cron / no
# agent in loop). Default OFF per
# [[bouncer-zero-llm-when-agent-in-loop]].
_SYNC_CLASSIFIER_OPT_IN_ENV = "IAM_JIT_ENABLE_SIDE_LLM"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class StructuredDenyResponse:
    """Canonical structured-deny payload returned to the agent.

    Lead with ``caught_by_bouncer`` per
    ``[[ambient-value-prop-and-friction-framing]]``.

    Per ``[[ibounce-honest-positioning]]`` the structured payload is the
    HONEST shape — every field reflects what the bouncer told us; we
    don't guess (unknown classifications stay ``ambiguous``)."""

    caught_by_bouncer: str
    """Which bouncer caught the request (e.g., ``ibounce``)."""

    deny_reason: str
    """Short operator-language reason (mirrors the existing deny_source
    enum from :mod:`iam_jit.profile_allow.denies`)."""

    deny_source: str
    """Internal classification (``static_profile`` / ``dynamic_deny`` /
    ``safe_default`` / ``profile_allow_baseline`` / etc)."""

    is_likely_injection_classification: str
    """One of ``appears_legitimate`` / ``ambiguous`` /
    ``appears_adversarial`` / ``pending_classification`` (#509 Phase 2).

    ``pending_classification`` is the local-dev / agent-in-loop
    default: the synchronous LLM call has been removed from the deny
    hot-path; the agent receives ``deny_event_id`` + calls the
    ``iam_jit_classify_deny`` MCP tool (using its OWN LLM) to fill in
    the real classification when desired. Operators in standalone
    mode (CI / cron) can re-enable the synchronous classifier path by
    setting ``IAM_JIT_ENABLE_SIDE_LLM=1`` + a real LLM backend."""

    suggested_allow_command: str
    """One-line ``iam-jit profile allow ...`` command (or a `#` comment
    when no allow is possible — e.g., dynamic-deny rules)."""

    recommended_action: str
    """One of ``easy-allow`` / ``halt+escalate`` / ``rephrase+retry``."""

    deny_event_id: str
    """Stable id the agent can pass to ``iam_jit_handle_deny`` for
    full audit-trail context. Format: ``evt_<bouncer>_<short_id>`` or
    ``evt_<utc_ts_ms>`` when no underlying id is available."""

    action: str = ""
    """The denied action (``service:Action`` form)."""

    resource: str = ""
    """The denied resource (ARN / hostname / table)."""

    when: str = ""
    """ISO-8601 timestamp of the deny."""

    agent_session_id: str = ""
    """If the bouncer captured the agent session id, surface it so the
    agent can confirm the deny belongs to its own session."""

    classifier_hook: str = ""
    """Name of the classifier hook that produced the
    ``is_likely_injection_classification`` value (empty when the
    placeholder fallback fired)."""

    schema_version: str = "1.1"
    """``1.1`` (#509 Phase 2): adds ``pending_classification`` as a
    valid ``is_likely_injection_classification`` value. Agents
    grepping the legacy three-value enum should add the new value to
    their match set; ``deny_event_id`` is unchanged + remains the key
    used to call ``iam_jit_classify_deny`` for agent-mediated
    enrichment."""

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    # ------------------------------------------------------------------
    # Per [[ambient-value-prop-and-friction-framing]]: a human-friendly
    # summary that's safe to print to stderr / Slack without ever using
    # "ERROR" / "DENIED" lead text.
    # ------------------------------------------------------------------
    def human_summary(self) -> str:
        action = self.action or "(unknown action)"
        resource = self.resource or "(unknown resource)"
        cls = self.is_likely_injection_classification
        cls_blurb = {
            INJECTION_APPEARS_LEGITIMATE: "looks legitimate",
            INJECTION_AMBIGUOUS: "ambiguous — needs your judgment",
            INJECTION_APPEARS_ADVERSARIAL: "looks adversarial",
            INJECTION_PENDING_CLASSIFICATION: (
                "pending — your agent can call iam_jit_classify_deny "
                "(MCP) to classify with its own LLM"
            ),
        }.get(cls, "ambiguous")
        lines = [
            f"Your {self.caught_by_bouncer} bouncer caught something:",
            f"  Agent tried: {action} on {resource}",
            f"  Why caught: {self.deny_reason or self.deny_source}",
            f"  Looks like: {cls_blurb}",
        ]
        if self.recommended_action == RECOMMENDED_ACTION_EASY_ALLOW:
            lines.append(f"  Suggested allow: {self.suggested_allow_command}")
        elif self.recommended_action == RECOMMENDED_ACTION_HALT_ESCALATE:
            lines.append(
                "  Recommended action: halt + escalate — do NOT auto-allow"
            )
        else:
            lines.append(
                "  Recommended action: rephrase the request or pick a "
                "different resource"
            )
        lines.append(f"  Deny event id (for handle_deny): {self.deny_event_id}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Injection-classification placeholder hook (#404 sibling agent will wire
# the real LLM classifier here when it lands).
# ---------------------------------------------------------------------------

_CLASSIFIER_ENV_VAR = "IAM_JIT_INJECTION_CLASSIFIER_HOOK"


def _load_classifier_hook() -> Optional[Any]:
    """Return a callable that accepts (action, resource, deny_source,
    raw_reason) and returns ``(classification, hook_name)``. Tries
    dynamic import of the path in ``IAM_JIT_INJECTION_CLASSIFIER_HOOK``;
    returns ``None`` when the env var is unset or the import fails.

    Per [[ibounce-honest-positioning]] failures here are SILENT (they
    fall back to ``ambiguous``); the alternative — hard-failing every
    deny because the optional classifier is offline — would itself be
    a bouncer outage.
    """
    spec = (os.environ.get(_CLASSIFIER_ENV_VAR) or "").strip()
    if not spec:
        return None
    try:
        import importlib

        module_name, _, func_name = spec.rpartition(":")
        if not module_name or not func_name:
            module_name, _, func_name = spec.rpartition(".")
        if not module_name or not func_name:
            return None
        mod = importlib.import_module(module_name)
        fn = getattr(mod, func_name, None)
        if fn is None or not callable(fn):
            return None
        return fn
    except Exception as e:  # pragma: no cover — diagnostic only
        logger.debug("classifier hook load failed: %s", e)
        return None


def _side_llm_opted_in() -> bool:
    """True iff operator EXPLICITLY enabled the synchronous bouncer-side
    LLM classifier (standalone-mode opt-in).

    Per [[bouncer-zero-llm-when-agent-in-loop]] this default is OFF.
    Local-dev / agent-in-loop deployments leave it unset; the agent
    classifies via the ``iam_jit_classify_deny`` MCP tool (using the
    agent's own LLM) when desired."""
    raw = (os.environ.get(_SYNC_CLASSIFIER_OPT_IN_ENV) or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def classify_injection_likelihood(
    *,
    action: str,
    resource: str,
    deny_source: str,
    deny_reason: str,
    agent_session_id: str = "",
) -> tuple[str, str]:
    """Return ``(classification, hook_name)``.

    Resolution order (#509 Phase 2 refactor — the synchronous
    bouncer-side LLM call is REMOVED from the local-dev hot-path per
    [[bouncer-zero-llm-when-agent-in-loop]]):

      1. If an env-var-pinned hook (``IAM_JIT_INJECTION_CLASSIFIER_HOOK``)
         is loadable, defer to it. Used by tests + custom integrations.
      2. ALWAYS run the deterministic structural heuristic first
         (KNOWN_ADVERSARIAL_PATTERNS + destructive-verb markers).
         This is the Bucket D safety floor per
         [[scorer-is-ground-truth]] and fires independent of LLM
         availability — operators in standalone-mode + local-dev get
         the same backstop.
      3. If the operator EXPLICITLY opted into standalone-mode by
         setting ``IAM_JIT_ENABLE_SIDE_LLM=1`` AND the #404
         :mod:`iam_jit.deny_classifier` module is importable AND a
         backend is reachable, defer to its
         :func:`classify_deny` for the synchronous LLM call.
      4. Otherwise return ``pending_classification`` + emit a
         structured ``report_skip`` so the operator's logs +
         ``/healthz`` show the local-dev mode. The agent receives the
         ``deny_event_id`` on the 403 + can call ``iam_jit_classify_deny``
         (MCP) for agent-mediated enrichment using its OWN LLM.
    """
    hook = _load_classifier_hook()
    if hook is not None:
        try:
            result = hook(
                action=action,
                resource=resource,
                deny_source=deny_source,
                deny_reason=deny_reason,
                agent_session_id=agent_session_id,
            )
            if isinstance(result, tuple) and len(result) == 2:
                cls, hook_name = result
                if cls in _VALID_INJECTION_CLASSIFICATIONS:
                    return cls, str(hook_name or _CLASSIFIER_ENV_VAR)
            if isinstance(result, str) and result in _VALID_INJECTION_CLASSIFICATIONS:
                return result, _CLASSIFIER_ENV_VAR
        except Exception as e:  # pragma: no cover
            logger.debug("classifier hook call failed: %s", e)

    # Structural heuristic (deterministic backstop for destructive
    # verbs — runs FIRST so the safety floor never depends on the LLM
    # path being reachable). Bucket D per [[scorer-is-ground-truth]].
    act = (action or "").lower()
    if act:
        adversarial_markers = (
            "delete", "destroy", "terminate", "remove",
            "drop", "stoploggingactivity", "putuserpolicy",
            "attachuserpolicy", "createaccesskey",
            "deactivatemfadevice", "passrole",
        )
        if any(m in act for m in adversarial_markers):
            return INJECTION_APPEARS_ADVERSARIAL, "structural_heuristic"

    # Standalone-mode opt-in path: operator explicitly enabled the
    # synchronous bouncer-side LLM. Honor it. Failures degrade to
    # pending_classification (agent enrichment) rather than a 500.
    if _side_llm_opted_in():
        try:
            from ..deny_classifier import classify_deny as _classify_deny
        except Exception:  # pragma: no cover
            _classify_deny = None
        if _classify_deny is not None:
            try:
                cls_result = _classify_deny(
                    deny_event={
                        "action": action,
                        "resource": resource,
                        "agent_prompt_context": "",
                        "operator_recent_pattern": "",
                    },
                    backend=None,
                    budget_usd=float(os.environ.get(
                        "IAM_JIT_CLASSIFIER_BUDGET_USD", "0.001",
                    ) or 0.001),
                )
                if isinstance(cls_result, dict):
                    cls = cls_result.get("classification")
                    backend = cls_result.get("backend") or ""
                    if cls in (INJECTION_APPEARS_LEGITIMATE, INJECTION_APPEARS_ADVERSARIAL):
                        return cls, f"deny_classifier:{backend or 'fallback'}"
                    # LLM said ambiguous OR returned a safe-fallback;
                    # report_skip to surface the degradation.
                    try:
                        from ..llm.report_skip import (
                            REASON_BACKEND_UNAVAILABLE,
                            report_skip,
                        )
                        report_skip(
                            feature="structured_deny.classify",
                            reason=REASON_BACKEND_UNAVAILABLE,
                            extra={
                                "llm_skip_backend": backend,
                                "llm_skip_classifier_note": str(
                                    cls_result.get("note") or ""
                                ),
                            },
                        )
                    except Exception:  # pragma: no cover
                        pass
                    return (
                        INJECTION_AMBIGUOUS,
                        f"deny_classifier:{backend or 'fallback'}",
                    )
            except Exception as e:  # pragma: no cover
                logger.debug("deny_classifier call failed: %s", e)
        # Opt-in set but classifier module unavailable; still skip.
        try:
            from ..llm.report_skip import (
                REASON_BACKEND_UNAVAILABLE,
                report_skip,
            )
            report_skip(
                feature="structured_deny.classify",
                reason=REASON_BACKEND_UNAVAILABLE,
                mode_hint=(
                    "IAM_JIT_ENABLE_SIDE_LLM is set but the deny_classifier "
                    "module is not importable. Install iam-jit with the "
                    "LLM extras or unset IAM_JIT_ENABLE_SIDE_LLM."
                ),
            )
        except Exception:  # pragma: no cover
            pass
        return INJECTION_PENDING_CLASSIFICATION, ""

    # Local-dev / agent-in-loop default: defer to the agent. Emit a
    # structured warning so operators see the deferral in their logs +
    # /healthz; agents see deny_event_id on the 403 body and can call
    # iam_jit_classify_deny (MCP) for enrichment using their own LLM.
    try:
        from ..llm.report_skip import REASON_NO_LLM_BACKEND, report_skip
        report_skip(
            feature="structured_deny.classify",
            reason=REASON_NO_LLM_BACKEND,
            mode_hint=(
                "Local-dev / agent-in-loop default: your agent can call "
                "the iam_jit_classify_deny MCP tool (with its own LLM) "
                "using the deny_event_id from the 403 response. To run "
                "the synchronous bouncer-side classifier instead "
                "(standalone / CI deployments), set "
                "IAM_JIT_ENABLE_SIDE_LLM=1 + IAM_JIT_LLM=anthropic|"
                "openai|bedrock|ollama with credentials."
            ),
        )
    except Exception:  # pragma: no cover
        pass
    return INJECTION_PENDING_CLASSIFICATION, ""


# ---------------------------------------------------------------------------
# Recommendation derivation
# ---------------------------------------------------------------------------


def derive_recommended_action(
    *,
    deny_source: str,
    classification: str,
    suggested_allow_command: str,
) -> str:
    """Pick a recommended_action for an agent.

    Decision table (lean-permissive per
    ``[[safety-mode-lean-permissive]]`` BUT halt on adversarial):

      * classification == appears_adversarial            → halt+escalate
      * deny_source in (dynamic_deny, profile_only_*)    → rephrase+retry
      * suggested_allow_command starts with ``#``        → rephrase+retry
      * classification == appears_legitimate             → easy-allow
      * classification == pending_classification         → easy-allow
        (lean-permissive — agent can call iam_jit_classify_deny via
         MCP to refine before deciding; operator still confirms)
      * default (ambiguous)                              → easy-allow
        (the friction-minimized default per
         ``[[ambient-value-prop-and-friction-framing]]``; the agent
         still prompts the operator to confirm)
    """
    if classification == INJECTION_APPEARS_ADVERSARIAL:
        return RECOMMENDED_ACTION_HALT_ESCALATE
    if deny_source in (
        "dynamic_deny",
        "profile_only_account_ids",
        "profile_only_regions",
    ):
        return RECOMMENDED_ACTION_REPHRASE_RETRY
    if suggested_allow_command and suggested_allow_command.lstrip().startswith("#"):
        return RECOMMENDED_ACTION_REPHRASE_RETRY
    return RECOMMENDED_ACTION_EASY_ALLOW


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------


def build_structured_deny(
    *,
    bouncer: str,
    action: str = "",
    resource: str = "",
    deny_reason: str = "",
    deny_source: str = "",
    rule_id_if_dynamic: str | None = None,
    suggested_allow_command: str = "",
    agent_session_id: str = "",
    when: str = "",
    deny_event_id: str | None = None,
) -> StructuredDenyResponse:
    """Produce a :class:`StructuredDenyResponse` from raw deny fields.

    Backwards-compatible with callers that already have a
    :class:`iam_jit.profile_allow.denies.DenyRow` — they just splat the
    row's fields into kwargs.

    The single source of truth for ``deny_source`` classification is the
    existing #345 :func:`iam_jit.profile_allow.denies.classify_deny_source`
    helper; this builder does NOT re-classify (avoids drift).
    """
    # If caller didn't run the classifier, do it now off the raw reason.
    if not deny_source and deny_reason:
        from ..profile_allow.denies import classify_deny_source as _classify
        deny_source, ruled = _classify(deny_reason)
        rule_id_if_dynamic = rule_id_if_dynamic or ruled

    # Compute suggested allow command if caller didn't pass one.
    if not suggested_allow_command:
        from ..profile_allow.denies import synth_suggested_allow_command
        suggested_allow_command = synth_suggested_allow_command(
            resource=resource,
            action=action,
            deny_source=deny_source,
            bouncer=bouncer,
        )

    classification, hook_name = classify_injection_likelihood(
        action=action,
        resource=resource,
        deny_source=deny_source,
        deny_reason=deny_reason,
        agent_session_id=agent_session_id,
    )

    recommended = derive_recommended_action(
        deny_source=deny_source,
        classification=classification,
        suggested_allow_command=suggested_allow_command,
    )

    if not deny_event_id:
        deny_event_id = _synth_deny_event_id(
            bouncer=bouncer, when=when, action=action, resource=resource,
            rule_id_if_dynamic=rule_id_if_dynamic,
        )

    return StructuredDenyResponse(
        caught_by_bouncer=bouncer or "unknown",
        deny_reason=deny_reason or deny_source or "unknown",
        deny_source=deny_source or "unknown",
        is_likely_injection_classification=classification,
        suggested_allow_command=suggested_allow_command,
        recommended_action=recommended,
        deny_event_id=deny_event_id,
        action=action,
        resource=resource,
        when=when,
        agent_session_id=agent_session_id,
        classifier_hook=hook_name,
    )


def _synth_deny_event_id(
    *,
    bouncer: str,
    when: str,
    action: str,
    resource: str,
    rule_id_if_dynamic: str | None,
) -> str:
    """Synthesize a stable-ish deny event id from the row's contents.

    Format: ``evt_<bouncer>_<sha8>``. Stable across re-projection of
    the same event so the agent can correlate.
    """
    import hashlib

    payload = json.dumps(
        {
            "bouncer": bouncer,
            "when": when,
            "action": action,
            "resource": resource,
            "rule": rule_id_if_dynamic or "",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"evt_{bouncer or 'unknown'}_{sha}"


# ---------------------------------------------------------------------------
# MCP backend: iam_jit_handle_deny
# ---------------------------------------------------------------------------


def handle_deny_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP backend for ``iam_jit_handle_deny``.

    Args:
      deny_event_id: stable id from a prior ``StructuredDenyResponse``.
      lookback_minutes: how far back to scan each bouncer's audit log
        for the matching event (default 60).
      include_recent_audit: when True, include the surrounding N recent
        events from that agent session for additional context.
      agent_session_id: optional hint that constrains the audit query.

    Returns a dict with:
      * ``status``: ``ok`` | ``not_found`` | ``error``
      * ``structured_deny``: the :class:`StructuredDenyResponse` dict
      * ``recent_audit``: list of dicts (when include_recent_audit)
      * ``classifier_reasoning``: textual rationale (today an honest
        no-op blurb when classifier is the placeholder; #404 will plug
        a real explanation here).
      * ``notes``: list of per-bouncer probe statuses.
    """
    deny_event_id = (args.get("deny_event_id") or "").strip()
    if not deny_event_id:
        return {
            "status": "error",
            "code": "missing_deny_event_id",
            "message": "deny_event_id is required",
        }

    lookback_minutes = int(args.get("lookback_minutes") or 60)
    include_recent_audit = bool(args.get("include_recent_audit", True))
    agent_session_id = (args.get("agent_session_id") or "").strip() or None

    since = _iso_minus_minutes(lookback_minutes)

    # Fetch recent deny rows from all bouncers; we look for the one whose
    # synthesized deny_event_id matches.
    try:
        from ..profile_allow.denies import fetch_recent_denies
    except Exception as e:  # pragma: no cover
        return {
            "status": "error",
            "code": "import_failed",
            "message": f"could not import deny fetcher: {e}",
        }

    rows, notes = fetch_recent_denies(
        since=since,
        agent_session_id=agent_session_id,
        limit=int(args.get("limit") or 200),
    )

    match: Any = None
    for r in rows:
        sd = build_structured_deny(
            bouncer=r.bouncer,
            action=r.action,
            resource=r.resource,
            deny_reason=r.deny_reason,
            deny_source=r.deny_source,
            rule_id_if_dynamic=r.rule_id_if_dynamic,
            suggested_allow_command=r.suggested_allow_command,
            agent_session_id=r.agent_session_id,
            when=r.when,
        )
        if sd.deny_event_id == deny_event_id:
            match = (r, sd)
            break

    if match is None:
        return {
            "status": "not_found",
            "deny_event_id": deny_event_id,
            "lookback_minutes": lookback_minutes,
            "notes": notes,
            "message": (
                f"no recent deny with id {deny_event_id} in the "
                f"last {lookback_minutes} minutes; try increasing "
                f"lookback_minutes or check `iam-jit denies recent`."
            ),
        }

    row, sd = match
    payload: dict[str, Any] = {
        "status": "ok",
        "structured_deny": sd.as_dict(),
        "notes": notes,
        "classifier_reasoning": _classifier_reasoning_for(sd),
        "lookback_minutes": lookback_minutes,
    }

    if include_recent_audit:
        # Best-effort: surface the surrounding rows from the same
        # bouncer + (optionally) same agent session.
        surrounding = [
            {
                "when": r.when,
                "bouncer": r.bouncer,
                "action": r.action,
                "resource": r.resource,
                "deny_reason": r.deny_reason,
                "deny_source": r.deny_source,
            }
            for r in rows
            if r.bouncer == row.bouncer
            and (not agent_session_id or r.agent_session_id == agent_session_id)
        ][:20]
        payload["recent_audit"] = surrounding

    return payload


# ---------------------------------------------------------------------------
# MCP backend: iam_jit_classify_deny (#509 Phase 2)
# ---------------------------------------------------------------------------


_VALID_ADVISORY_ACTIONS = frozenset({
    "easy-allow",
    "hold",
    "escalate",
})


def classify_deny_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP backend for ``iam_jit_classify_deny`` (#509 Phase 2).

    The agent calls this AFTER seeing a 403 with
    ``is_likely_injection_classification: pending_classification`` to
    fill in the classification using its OWN LLM. Per
    [[bouncer-zero-llm-when-agent-in-loop]] this is the seam where the
    agent's full task context replaces the bouncer-side LLM call —
    same architecture as ``iam_jit_improve_profile`` (#401) which
    already delegates to the agent.

    Two call shapes:

      A. Agent provides ``classification`` + ``confidence`` +
         ``reasoning`` (the agent's LLM has already analyzed the deny
         event using the structured payload + recent_audit from
         ``iam_jit_handle_deny``):

           - The deterministic KNOWN_ADVERSARIAL backstop applies on
             OUTPUT (mirroring the existing #404 safety floor) — if the
             action matches a known-adversarial pattern, the classifier
             OVERRIDES to ``appears_adversarial`` regardless of the
             agent's input.
           - ``advisory_action`` is computed via the canonical decision
             matrix in :mod:`iam_jit.deny_classifier.classifier`.

      B. Agent omits classification fields (look-up only):

           - Returns the structured deny + audit context (same shape
             as :func:`handle_deny_for_mcp`) so the agent can call
             back with a real classification once its LLM has weighed
             in.

    Args:
      deny_event_id: REQUIRED — stable id from a prior 403 / structured
        deny response.
      classification: optional — one of ``appears_legitimate`` /
        ``ambiguous`` / ``appears_adversarial``.
      confidence: optional float 0..1.
      reasoning: optional short operator-language explanation.

    Returns dict with:
      * ``status``: ``ok`` | ``not_found`` | ``error``
      * ``classification``: final classification (agent-input or
        backstop-overridden)
      * ``confidence``: final confidence (0..1)
      * ``reasoning``: final reasoning string (backstop annotation
        prepended when override fires)
      * ``advisory_action``: ``easy-allow`` | ``hold`` | ``escalate``
      * ``structured_deny``: the structured deny dict (so the agent
        sees the deny event in canonical shape)
      * ``deterministic_backstop_fired``: bool — True iff the
        KNOWN_ADVERSARIAL backstop overrode the agent's input
      * ``mode``: ``agent_classified`` | ``lookup_only``
    """
    deny_event_id = (args.get("deny_event_id") or "").strip()
    if not deny_event_id:
        return {
            "status": "error",
            "code": "missing_deny_event_id",
            "message": "deny_event_id is required",
        }

    # Resolve the deny event via the same fetch path as handle_deny.
    try:
        from ..profile_allow.denies import fetch_recent_denies
    except Exception as e:  # pragma: no cover
        return {
            "status": "error",
            "code": "import_failed",
            "message": f"could not import deny fetcher: {e}",
        }

    lookback_minutes = int(args.get("lookback_minutes") or 60)
    since = _iso_minus_minutes(lookback_minutes)
    rows, notes = fetch_recent_denies(
        since=since,
        agent_session_id=(args.get("agent_session_id") or "").strip() or None,
        limit=int(args.get("limit") or 200),
    )
    matched_sd: StructuredDenyResponse | None = None
    matched_row: Any = None
    for r in rows:
        sd = build_structured_deny(
            bouncer=r.bouncer,
            action=r.action,
            resource=r.resource,
            deny_reason=r.deny_reason,
            deny_source=r.deny_source,
            rule_id_if_dynamic=r.rule_id_if_dynamic,
            suggested_allow_command=r.suggested_allow_command,
            agent_session_id=r.agent_session_id,
            when=r.when,
        )
        if sd.deny_event_id == deny_event_id:
            matched_sd = sd
            matched_row = r
            break

    if matched_sd is None:
        return {
            "status": "not_found",
            "deny_event_id": deny_event_id,
            "lookback_minutes": lookback_minutes,
            "notes": notes,
            "message": (
                f"no recent deny with id {deny_event_id} in the last "
                f"{lookback_minutes} minutes; try increasing "
                "lookback_minutes."
            ),
        }

    # Agent-provided classification? If not, return lookup-only payload
    # so the agent can analyze + call back.
    raw_cls = args.get("classification")
    if raw_cls is None:
        return {
            "status": "ok",
            "mode": "lookup_only",
            "structured_deny": matched_sd.as_dict(),
            "notes": notes,
            "guidance": (
                "Call this MCP tool again with `classification` "
                "('appears_legitimate' | 'ambiguous' | "
                "'appears_adversarial'), `confidence` (0..1), and "
                "`reasoning` populated by your LLM. The bouncer's "
                "deterministic KNOWN_ADVERSARIAL backstop will still "
                "fire on output for safety."
            ),
        }

    classification = str(raw_cls).strip().lower()
    if classification not in {
        INJECTION_APPEARS_LEGITIMATE,
        INJECTION_AMBIGUOUS,
        INJECTION_APPEARS_ADVERSARIAL,
    }:
        return {
            "status": "error",
            "code": "invalid_classification",
            "message": (
                f"classification must be one of "
                f"'{INJECTION_APPEARS_LEGITIMATE}' / "
                f"'{INJECTION_AMBIGUOUS}' / "
                f"'{INJECTION_APPEARS_ADVERSARIAL}'; "
                f"got {classification!r}."
            ),
        }
    try:
        confidence = float(args.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    reasoning = str(args.get("reasoning") or "").strip()[:1000]

    # Apply the deterministic KNOWN_ADVERSARIAL backstop on the OUTPUT
    # side (mirroring the existing #404 safety floor). The agent's LLM
    # can't override the destructive-verb floor — the bouncer enforces
    # it regardless of agent input.
    backstop_fired = False
    try:
        from ..deny_classifier.classifier import _is_known_adversarial
        if _is_known_adversarial(matched_sd.action) and (
            classification != INJECTION_APPEARS_ADVERSARIAL
        ):
            backstop_fired = True
            classification = INJECTION_APPEARS_ADVERSARIAL
            confidence = max(confidence, 0.9)
            reasoning = (
                f"[backstop: action {matched_sd.action!r} matches "
                f"KNOWN_ADVERSARIAL_PATTERNS] " + (reasoning or "")
            )
    except Exception:  # pragma: no cover
        pass

    # Compute advisory_action via the canonical decision matrix.
    try:
        from ..deny_classifier.classifier import _decide_advisory_action
        advisory = _decide_advisory_action(
            classification,  # type: ignore[arg-type]
            confidence,
            is_adversarial_action=backstop_fired,
        )
    except Exception:  # pragma: no cover
        advisory = "hold"

    if advisory not in _VALID_ADVISORY_ACTIONS:
        advisory = "hold"

    return {
        "status": "ok",
        "mode": "agent_classified",
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning or "(no reasoning provided)",
        "advisory_action": advisory,
        "deterministic_backstop_fired": backstop_fired,
        "structured_deny": matched_sd.as_dict(),
        "notes": notes,
    }


def _classifier_reasoning_for(sd: StructuredDenyResponse) -> str:
    """Compose a short, operator-language explanation of why the
    classifier returned what it did.

    Today this is a structural-heuristic explanation; #404 LLM
    classifier will plug a real rationale (and the
    ``classifier_hook`` field will identify which classifier ran).
    """
    cls = sd.is_likely_injection_classification
    if sd.classifier_hook:
        return (
            f"Classifier ({sd.classifier_hook}) returned "
            f"{cls!r} for action={sd.action!r} on resource={sd.resource!r}."
        )
    if cls == INJECTION_APPEARS_ADVERSARIAL:
        return (
            f"Structural heuristic flagged {sd.action!r} as a "
            f"destructive verb (deterministic backstop)."
        )
    if cls == INJECTION_PENDING_CLASSIFICATION:
        return (
            "Local-dev / agent-in-loop mode (#509 Phase 2). The "
            "synchronous bouncer-side LLM classifier is OFF by default; "
            "the deterministic structural heuristic did not flag this "
            f"action ({sd.action!r}). Call the iam_jit_classify_deny "
            "MCP tool with this deny_event_id to classify with your "
            "agent's own LLM."
        )
    return (
        "Defaulting to 'ambiguous' so the agent prompts the operator "
        "for confirmation."
    )


def _iso_minus_minutes(minutes: int) -> str:
    when = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=minutes)
    return when.replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "INJECTION_AMBIGUOUS",
    "INJECTION_APPEARS_ADVERSARIAL",
    "INJECTION_APPEARS_LEGITIMATE",
    "INJECTION_PENDING_CLASSIFICATION",
    "RECOMMENDED_ACTION_EASY_ALLOW",
    "RECOMMENDED_ACTION_HALT_ESCALATE",
    "RECOMMENDED_ACTION_REPHRASE_RETRY",
    "StructuredDenyResponse",
    "build_structured_deny",
    "classify_deny_for_mcp",
    "classify_injection_likelihood",
    "derive_recommended_action",
    "handle_deny_for_mcp",
]
