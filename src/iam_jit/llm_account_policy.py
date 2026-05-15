"""Per-account LLM-usage policy gate.

Enterprise feature: each Account record carries an optional
`llm_policy` ("use_llm" | "deterministic_only" | None). At score
time, this gate runs FIRST in the LLM-or-not decision chain:

  1. account.llm_policy set?      → honor it (most cost-effective)
  2. deployment default            → IAM_JIT_LLM_DEFAULT_POLICY
  3. per-customer monthly budget   → llm_budget.consume_or_reject
  4. confidence band               → LLMSkipBelow / LLMSkipAbove

Account-policy first because it's free to check AND saves the most
money — never spend a token on accounts the customer flagged.

This module ONLY exposes the decision; it doesn't reach into the
LLM backend or the score response. Callers wire it into whichever
flow needs an LLM-on/off decision.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from typing import Protocol

logger = logging.getLogger("iam_jit.llm_account_policy")


_VALID_POLICIES = frozenset({"use_llm", "deterministic_only"})
_DEFAULT_ENV = "IAM_JIT_LLM_DEFAULT_POLICY"


@dataclasses.dataclass(frozen=True)
class LLMDecision:
    """Outcome of the account-policy gate.

    `use_llm` is the final yes/no for the account-policy stage. A
    caller can still override (e.g., free tier always skips, budget
    is exhausted, deterministic-confidence band is tight). The
    skip_reason and skip_detail surface in the audit log + score
    response so approvers know WHY LLM was or wasn't used.
    """

    use_llm: bool
    source: str
    """Where the decision came from:
       'account_policy'      — account.llm_policy was set
       'deployment_default'  — env IAM_JIT_LLM_DEFAULT_POLICY
       'no_account_context'  — no account_id was passed (default to True)
       'unknown_account'     — account_id not in registry (default to deployment policy)
    """
    skip_reason: str | None
    """When use_llm=False, a short label for the audit log:
       'account_policy:deterministic_only'
       'deployment_default:deterministic_only'
       None when use_llm=True.
    """
    skip_detail: str | None
    """Human-readable detail. For account policy, this is the
    admin's `llm_policy_reason` if they set one. For deployment
    default, the env-var name. None when use_llm=True."""


class _AccountsView(Protocol):
    """The slice of accounts_store.AccountStore we need."""

    def get(self, account_id: str) -> object: ...


def decide(
    *,
    account_id: str | None,
    accounts_store: _AccountsView | None = None,
    default_policy_env: str = _DEFAULT_ENV,
) -> LLMDecision:
    """Compute the LLM-usage decision for a grant on `account_id`.

    `account_id` is the destination account the grant targets. None
    means the caller has no per-account context (e.g., the standalone
    /score endpoint) — in that case we default to using the LLM
    (subject to the caller's downstream budget gate).

    `accounts_store` is the registry to look up `account_id` in. If
    None, the function only consults the deployment default. This
    keeps the helper trivially testable.
    """
    # No account context → no account policy to honor; let LLM flow proceed.
    if account_id is None:
        return LLMDecision(
            use_llm=True,
            source="no_account_context",
            skip_reason=None,
            skip_detail=None,
        )

    # Look up the account record.
    account = None
    if accounts_store is not None:
        try:
            account = accounts_store.get(account_id)
        except Exception:
            account = None

    if account is not None:
        policy = getattr(account, "llm_policy", None)
        if policy in _VALID_POLICIES:
            reason = getattr(account, "llm_policy_reason", None) or None
            if policy == "use_llm":
                return LLMDecision(
                    use_llm=True,
                    source="account_policy",
                    skip_reason=None,
                    skip_detail=None,
                )
            else:  # deterministic_only
                return LLMDecision(
                    use_llm=False,
                    source="account_policy",
                    skip_reason="account_policy:deterministic_only",
                    skip_detail=reason,
                )

    # No explicit account policy → consult the deployment default.
    default = (os.environ.get(default_policy_env) or "").strip().lower()
    if default == "deterministic_only":
        return LLMDecision(
            use_llm=False,
            source="deployment_default",
            skip_reason="deployment_default:deterministic_only",
            skip_detail=f"{default_policy_env}=deterministic_only",
        )
    # Default-default (use_llm OR unset).
    return LLMDecision(
        use_llm=True,
        source=(
            "deployment_default" if default == "use_llm" else "unknown_account"
        ),
        skip_reason=None,
        skip_detail=None,
    )
