"""#724 / BUILD-3 — bouncer chaining: cross-protocol defense-in-depth.

One bouncer's observation should be able to TIGHTEN another bouncer's
posture for the SAME agent session — cross-protocol defense-in-depth.
Canonical chain (the one demonstrated end-to-end on the Python side):

    dbounce observes PII in a SQL result
      -> writes a `pii_observed` signal keyed on the agent session
      -> ibounce (HTTP egress) reads that signal on its next decision
         and TIGHTENS exfil-shaped egress (write/PUT/POST data-out)
         for that session, for the signal's TTL.

Honest scope (per ``[[ibounce-honest-positioning]]``)
-----------------------------------------------------
This is **same-host, session-scoped** signal sharing via a shared
on-disk signal store (SQLite in a shared directory). It is NOT a
distributed/real-time bus and we do not claim that. Producers and
consumers run on the same host and key on the canonical
``X-Agent-Session-Id`` (see ``[[cross-product-agent-parity]]``). The
"within 1s" UAT target is met because the consumer reads the store on
its very next decision; there is no polling delay on the hot path.

Independence is preserved (per ``[[independence-as-security-property]]``)
-------------------------------------------------------------------------
Chaining is **opt-in** and **default OFF**. Each bouncer remains fully
functional standalone:

  * If chaining is disabled, the consumer never reads the store and the
    proxy behaves exactly as before.
  * If the store is UNAVAILABLE (missing dir, corrupt DB, permission
    error), the consumer **fails soft** — it logs + decides standalone
    against its own policy. A down signal channel can never STOP a
    bouncer or flip a deny into an allow.

Tightening-only (the security invariant)
-----------------------------------------
A chained signal may only ever **TIGHTEN** (ALLOW -> DENY). It can
NEVER loosen another bouncer's decision. A forged or replayed signal
is therefore, at worst, a denial-of-service against the *attacker's
own* exfil path — it can never grant access. This is the property the
security review scrutinises, so it is enforced structurally: the
consumer only ever returns "tighten" or "no-op", and the proxy only
consults it on a floor verdict that was NOT already a deny.

The Go bouncers (gbounce / kbounce / dbounce) adopt the same on-disk
wire format via the porting contract in
``docs/BOUNCER-CHAINING.md``. This package ships the shared wire
format + the Python producer/consumer + the ibounce tightening hook.
"""

from __future__ import annotations

from .chains import (
    ChainRule,
    ChainRulesError,
    load_chain_rules,
)
from .config import ChainingConfig, ConfigError, load_config
from .events import (
    EVENT_TYPE_CHAIN_TIGHTENED,
    make_chain_tightened_event,
)
from .signal_store import (
    SIGNAL_KIND_PII_OBSERVED,
    SIGNAL_KIND_SECRET_OBSERVED,
    SIGNAL_STORE_VERSION,
    CrossBouncerSignal,
    SignalStore,
    SignalStoreError,
)
from .tightener import (
    ChainTightener,
    TightenResult,
    active_chain_tightener,
    register_chain_tightener,
    reset_for_tests,
)

__all__ = [
    "EVENT_TYPE_CHAIN_TIGHTENED",
    "SIGNAL_KIND_PII_OBSERVED",
    "SIGNAL_KIND_SECRET_OBSERVED",
    "SIGNAL_STORE_VERSION",
    "ChainRule",
    "ChainRulesError",
    "ChainTightener",
    "ChainingConfig",
    "ConfigError",
    "CrossBouncerSignal",
    "SignalStore",
    "SignalStoreError",
    "TightenResult",
    "active_chain_tightener",
    "load_chain_rules",
    "load_config",
    "make_chain_tightened_event",
    "register_chain_tightener",
    "reset_for_tests",
]
