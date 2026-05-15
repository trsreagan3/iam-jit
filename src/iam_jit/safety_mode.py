"""Safety-mode configuration: read_write_swap (default) vs strict.

Per [[safety-mode-two-modes]] memo. Two modes differ in:

- Auto-approve threshold for read-only grants (very permissive
  in read_write_swap; tighter in strict)
- Auto-approve threshold for write grants (standard in
  read_write_swap; very tight in strict)
- Whether action wildcards are allowed in synthesized policies
  (yes in read_write_swap; no in strict)
- Whether admin-fallback escape hatch is allowed
  (yes in read_write_swap; NO in strict)
- Sensitive-reads floor applies in BOTH modes (kms:Decrypt,
  secretsmanager:GetSecretValue, sts:AssumeRole, etc.)

Mode resolution (in priority order):
  1. Per-session override (CLI flag / API param)
  2. Per-account override (Account.safety_mode_override field)
  3. Deployment default (IAM_JIT_SAFETY_MODE env var)
  4. Fallback default: read_write_swap

This is the single source of truth for mode decisions.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Protocol


SAFETY_MODE_READ_WRITE_SWAP = "read_write_swap"
SAFETY_MODE_STRICT = "strict"

_VALID_MODES = frozenset({SAFETY_MODE_READ_WRITE_SWAP, SAFETY_MODE_STRICT})
_DEFAULT_MODE = SAFETY_MODE_READ_WRITE_SWAP
_DEFAULT_ENV = "IAM_JIT_SAFETY_MODE"


@dataclasses.dataclass(frozen=True)
class SafetyModeThresholds:
    """Per-mode auto-approve thresholds + behavior flags.

    Thresholds are 1-10 score floors; score STRICTLY BELOW the
    threshold auto-approves. Higher value = MORE permissive.
    """

    mode: str
    auto_approve_read_below: int  # very permissive for read_write_swap
    auto_approve_write_below: int  # standard for read_write_swap; tight for strict
    allow_action_wildcards: bool
    allow_admin_fallback: bool
    extended_audit_retention: bool

    @property
    def is_strict(self) -> bool:
        return self.mode == SAFETY_MODE_STRICT


_THRESHOLDS_BY_MODE: dict[str, SafetyModeThresholds] = {
    SAFETY_MODE_READ_WRITE_SWAP: SafetyModeThresholds(
        mode=SAFETY_MODE_READ_WRITE_SWAP,
        # Reads auto-approve almost regardless (score < 9 in real
        # use means everything short of clear-and-present-danger).
        # See [[safety-mode-lean-permissive]] for the rationale.
        auto_approve_read_below=9,
        # Writes get the standard threshold; tunable by deployment.
        auto_approve_write_below=4,
        allow_action_wildcards=True,
        allow_admin_fallback=True,
        extended_audit_retention=False,
    ),
    SAFETY_MODE_STRICT: SafetyModeThresholds(
        mode=SAFETY_MODE_STRICT,
        # Tighter on reads — still permissive but with margin.
        auto_approve_read_below=5,
        # Very tight on writes — most go to human review.
        auto_approve_write_below=2,
        allow_action_wildcards=False,
        allow_admin_fallback=False,
        extended_audit_retention=True,
    ),
}


class _AccountsView(Protocol):
    """The slice of accounts_store we need to look up per-account overrides."""

    def get(self, account_id: str) -> object: ...


def resolve_mode(
    *,
    session_override: str | None = None,
    account_id: str | None = None,
    accounts_store: _AccountsView | None = None,
    default_env: str = _DEFAULT_ENV,
) -> str:
    """Resolve the effective safety mode for a request.

    Priority (highest to lowest):
      1. session_override (e.g., --strict CLI flag)
      2. account.safety_mode_override (per-account config)
      3. deployment default (IAM_JIT_SAFETY_MODE env var)
      4. fallback: read_write_swap

    Invalid values are coerced to read_write_swap (safe-by-default;
    falling back to strict would surprise the customer).
    """
    # 1. Session override
    if session_override is not None:
        candidate = (session_override or "").strip().lower()
        if candidate in _VALID_MODES:
            return candidate

    # 2. Per-account override
    if account_id is not None and accounts_store is not None:
        try:
            account = accounts_store.get(account_id)
            override = getattr(account, "safety_mode_override", None)
            if override:
                candidate = str(override).strip().lower()
                if candidate in _VALID_MODES:
                    return candidate
        except Exception:
            pass

    # 3. Deployment default from env
    env_val = (os.environ.get(default_env) or "").strip().lower()
    if env_val in _VALID_MODES:
        return env_val

    # 4. Fallback
    return _DEFAULT_MODE


def thresholds_for(mode: str) -> SafetyModeThresholds:
    """Return the threshold + behavior config for a mode.

    Unknown mode coerces to the read_write_swap defaults.
    """
    return _THRESHOLDS_BY_MODE.get(mode, _THRESHOLDS_BY_MODE[_DEFAULT_MODE])


# Mode strictness ranking: higher value = stricter. Used when a
# request spans multiple accounts: the most-restrictive mode across
# the set wins. Otherwise a [dev-no-override, prod-strict-override]
# request would silently inherit dev's (looser) mode and defeat the
# prod policy. (WB10-03 closure.)
_MODE_STRICTNESS: dict[str, int] = {
    SAFETY_MODE_READ_WRITE_SWAP: 0,
    SAFETY_MODE_STRICT: 1,
}


def resolve_mode_for_accounts(
    *,
    account_ids: list[str] | tuple[str, ...],
    accounts_store: _AccountsView | None = None,
    session_override: str | None = None,
    default_env: str = _DEFAULT_ENV,
) -> str:
    """Resolve the effective mode for a request targeting multiple
    accounts. Picks the MOST RESTRICTIVE mode across the set so that
    a mixed-account request can never weaken a strict-override account.

    Empty list → falls back to resolve_mode with no account_id.
    """
    if not account_ids:
        return resolve_mode(
            session_override=session_override,
            accounts_store=accounts_store,
            default_env=default_env,
        )
    seen: list[str] = []
    for aid in account_ids:
        if not aid:
            continue
        seen.append(
            resolve_mode(
                session_override=session_override,
                account_id=aid,
                accounts_store=accounts_store,
                default_env=default_env,
            )
        )
    if not seen:
        return _DEFAULT_MODE
    return max(seen, key=lambda m: _MODE_STRICTNESS.get(m, 0))


def auto_approve_threshold_for(
    mode: str,
    *,
    access_type: str = "read-only",
) -> int:
    """Return the auto-approve threshold for the given mode + access_type.

    `access_type` is one of "read" / "read-only" / "read-write".
    Reads use the read threshold; writes use the write threshold.
    """
    t = thresholds_for(mode)
    if access_type in ("read", "read-only"):
        return t.auto_approve_read_below
    return t.auto_approve_write_below
