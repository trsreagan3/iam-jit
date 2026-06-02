"""#724 — the CONSUMER side: should this egress request be tightened?

The :class:`ChainTightener` is the ibounce-side consumer. Given a
request's agent session id + its read/write shape, it:

  1. reads the active cross-bouncer signals for that session from the
     shared :class:`~.signal_store.SignalStore`;
  2. matches them against the loaded :class:`~.chains.ChainRule` set;
  3. returns a :class:`TightenResult` saying whether to TIGHTEN
     ALLOW->DENY (block mode) or merely flag (alert mode).

Tightening-only invariant
--------------------------
:meth:`evaluate` only ever returns ``tighten=True`` or a no-op. It can
NEVER return "allow this when the floor said deny" — the proxy only
consults the tightener when the floor verdict was NOT already a deny,
and the tightener only ever moves ALLOW -> DENY. A forged/replayed
signal is, at worst, a self-DoS on the attacker's exfil path.

Fail-soft / independence
-------------------------
If the signal store is unavailable (missing/corrupt/permission),
:meth:`evaluate` returns a no-op (``tighten=False``) and logs. The
bouncer then decides standalone against its own policy. A down signal
channel can NEVER stop the bouncer or flip a deny into an allow.

What counts as "exfil-shaped egress"
-------------------------------------
The canonical chain locks down EXFILTRATION. We treat a request as
exfil-shaped when it is NOT a pure read (i.e. ``is_write`` is True,
which by the proxy's convention includes ``unknown`` actions). A PII
signal active for the session therefore tightens writes/PUT/POST
data-out while still letting harmless reads through — honest,
narrowly-scoped, and erring toward not over-blocking
(``[[safety-mode-lean-permissive]]``).
"""

from __future__ import annotations

import dataclasses
import logging
import threading
from typing import Any

from .chains import ChainRule
from .signal_store import CrossBouncerSignal, SignalStore, SignalStoreError

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class TightenResult:
    """Outcome of one :meth:`ChainTightener.evaluate` call.

    ``tighten`` is True only when block-mode + a matching active signal
    + an exfil-shaped request all line up. ``fired`` is True whenever a
    chain MATCHED (block OR alert) so the proxy emits the audit event
    even in alert mode. A no-op result has both False."""

    tighten: bool
    fired: bool
    mode: str                       # "block" | "alert"
    source_bouncer: str | None      # attribution: who raised the signal
    trigger_kind: str | None
    action_bouncer: str | None
    action_verb: str | None
    ttl_seconds: int
    operator_message: str

    @classmethod
    def noop(cls) -> "TightenResult":
        return cls(
            tighten=False, fired=False, mode="", source_bouncer=None,
            trigger_kind=None, action_bouncer=None, action_verb=None,
            ttl_seconds=0, operator_message="",
        )


class ChainTightener:
    """Process-wide consumer. Installed by ``serve()`` when chaining is
    enabled; consulted by the proxy hot path on every non-deny floor
    verdict for an attributed session."""

    def __init__(
        self,
        *,
        store: SignalStore,
        rules: list[ChainRule],
        mode: str = "block",
    ) -> None:
        self._store = store
        # Only egress-tightening rules are actionable on the Python
        # (ibounce) side. Non-egress rules are kept for honest /healthz
        # reporting but never act here (the Go ports honour them).
        self._egress_rules = [r for r in rules if r.applies_to_egress]
        self._all_rules = list(rules)
        self._mode = mode if mode in ("block", "alert") else "block"
        self._tightenings_total = 0
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def egress_rule_count(self) -> int:
        return len(self._egress_rules)

    @property
    def tightenings_total(self) -> int:
        with self._lock:
            return self._tightenings_total

    def evaluate(
        self,
        *,
        session_id: str | None,
        is_write: bool,
        now: float | None = None,
    ) -> TightenResult:
        """Decide whether this egress request should be tightened.

        ``is_write`` follows the proxy's convention (``unknown`` counts
        as write). Fail-soft: any signal-store error -> no-op."""
        if not session_id:
            # No session = nothing to key cross-bouncer signals on.
            return TightenResult.noop()
        if not self._egress_rules:
            return TightenResult.noop()
        # Only exfil-shaped (non-read) egress is in scope for the PII
        # chain. A pure read can't exfiltrate the observed PII outward,
        # so we don't over-block it.
        if not is_write:
            return TightenResult.noop()

        trigger_kinds = tuple({r.trigger_kind for r in self._egress_rules})
        try:
            signals = self._store.active_signals_for_session(
                session_id, kinds=trigger_kinds, now=now,
            )
        except SignalStoreError as e:
            # Independence guarantee: a down/broken signal channel must
            # NEVER stop the bouncer or change its standalone verdict.
            logger.warning(
                "bouncer-chaining: signal store unavailable, deciding "
                "standalone (fail-soft): %s", e,
            )
            return TightenResult.noop()
        except Exception as e:  # noqa: BLE001 - belt-and-suspenders fail-soft
            logger.warning(
                "bouncer-chaining: unexpected signal-store error, "
                "deciding standalone (fail-soft): %s", e,
            )
            return TightenResult.noop()

        if not signals:
            return TightenResult.noop()

        match = self._first_matching(signals)
        if match is None:
            return TightenResult.noop()
        rule, signal = match

        msg = (
            f"Your bouncer noticed {signal.source} flagged "
            f"'{signal.kind}' earlier in this session, so HTTP egress that "
            f"could carry that data out is "
            f"{'paused' if self._mode == 'block' else 'flagged (alert mode; still allowed)'} "
            f"for the session."
        )
        tighten = self._mode == "block"
        if tighten:
            with self._lock:
                self._tightenings_total += 1
        return TightenResult(
            tighten=tighten,
            fired=True,
            mode=self._mode,
            source_bouncer=signal.source,
            trigger_kind=signal.kind,
            action_bouncer=rule.action_bouncer,
            action_verb=rule.action_verb,
            ttl_seconds=rule.ttl_seconds,
            operator_message=msg,
        )

    def _first_matching(
        self, signals: list[CrossBouncerSignal],
    ) -> tuple[ChainRule, CrossBouncerSignal] | None:
        """Return the first (rule, signal) pair where a rule's trigger
        matches an active signal's (source, kind). A rule with a
        wildcard source (``*``) matches any producer; otherwise the
        rule's declared source must equal the signal's source."""
        for rule in self._egress_rules:
            for sig in signals:
                if sig.kind != rule.trigger_kind:
                    continue
                if rule.trigger_source in ("*", sig.source):
                    return rule, sig
        return None

    def status(self) -> dict[str, Any]:
        """/healthz-friendly status block (honest reporting)."""
        return {
            "enabled": True,
            "mode": self._mode,
            "egress_rule_count": len(self._egress_rules),
            "total_rule_count": len(self._all_rules),
            "signal_db": str(self._store.db_path),
            "tightenings_total": self.tightenings_total,
        }


# ---------------------------------------------------------------------------
# Process-wide singleton — installed by serve() when chaining is enabled.
# None when chaining is disabled (the default) so the proxy hot path
# short-circuits with a single None check.
# ---------------------------------------------------------------------------

_active_tightener: ChainTightener | None = None
_active_tightener_lock = threading.Lock()


def register_chain_tightener(tightener: ChainTightener | None) -> None:
    """Install (or clear) the process-wide tightener."""
    global _active_tightener
    with _active_tightener_lock:
        _active_tightener = tightener


def active_chain_tightener() -> ChainTightener | None:
    """Return the installed tightener, or None when chaining is off."""
    with _active_tightener_lock:
        return _active_tightener


def reset_for_tests() -> None:
    global _active_tightener
    with _active_tightener_lock:
        _active_tightener = None


__all__ = [
    "ChainTightener",
    "TightenResult",
    "active_chain_tightener",
    "register_chain_tightener",
    "reset_for_tests",
]
