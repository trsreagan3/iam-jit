"""#401 / §A47 — ``iam_jit_improve_profile`` MCP tool + CLI.

The autonomous-improvement cycle: agent (or autopilot daemon) calls this
periodically (per declaration ``improve.cadence``) so the bouncer's
profile tightens around the operator's actual observed traffic without
the operator having to author rules manually.

Algorithm (per [[ambient-autonomous-protection]] §A47):

  1. Pull recent OCSF audit events from each bouncer (since last improve
     run OR within the cadence window).
  2. Run the existing :func:`iam_jit.llm.profile_generator.generate_from_audit`
     pipeline to synthesize new profile YAML (+ §A38 scope-floor emission).
  3. Diff the generated profile against the current active profile.
  4. Compute change-size as a normalized 0..1 score
     (rules_added + rules_removed + scope_changes vs current rule count).
  5. If change-size < declaration's
     ``require_operator_approval_above_change_threshold``: auto-install
     via the existing #345 :func:`iam_jit.profile_allow.add_profile_allow_rule`
     path + admin_action audit emit.
  6. If change-size >= threshold: HOLD for operator approval via the
     existing §A25 pending queue.
  7. Return structured summary:

      {
        status: 'auto_installed' | 'pending_approval' | 'no_change' |
                'managed_posture_refused' | 'error',
        bouncer: str,
        change_size: float,
        rules_added: int,
        rules_removed: int,
        scope_changes: [str, ...],
        requires_approval: bool,
        audit_event_ids: [str, ...],
        pending_entry_ids: [str, ...],
        explanation: str,
      }

Per [[creates-never-mutates]] this NEVER overwrites manually-authored
allow rules — it ADDS to existing allow_rules via the same
:func:`iam_jit.profile_allow.operations.add_profile_allow_rule` path
the operator uses; removed rules become pending entries the operator
must approve, never silent deletes.

Per [[scorer-is-ground-truth]] this does NOT tune the scorer/corpus;
it only adjusts the *generator output* per the existing
:mod:`iam_jit.llm.profile_generator` quality bar.

Per `posture: managed` configs in [[ambient-autonomous-protection]] this
MUST refuse to run (clear error); managed-mode reproducibility forbids
silent profile drift.
"""

from .pipeline import (
    ImproveProfileError,
    ImproveProfileResult,
    improve_profile,
    improve_profile_for_cli,
    improve_profile_for_mcp,
)

__all__ = [
    "ImproveProfileError",
    "ImproveProfileResult",
    "improve_profile",
    "improve_profile_for_cli",
    "improve_profile_for_mcp",
]
