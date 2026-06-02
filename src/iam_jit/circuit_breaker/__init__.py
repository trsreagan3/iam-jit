"""BUILD-4 / #725 — cost circuit breaker as a SECURITY primitive.

A runaway agent burning spend or hammering an API is a SECURITY
incident, not just a FinOps one (PDF §A-Compete; Waxell research:
$400M leaked from Fortune-500 retry-loop agents). This module treats
"an agent's cost/call rate just spiked 200×" as a real-time security
signal and TRIPS a circuit breaker that DENIES further gated calls
for the offending session until it resets.

How this differs from the existing LLM-budget machinery
--------------------------------------------------------
``iam_jit.llm_budget`` and ``iam_jit.llm.llm_spend_tracker`` guard
**iam-jit's own** LLM-narration spend (Bedrock/Anthropic cost the
SERVICE incurs when scoring policies). They are a billing/margin
control on iam-jit-the-product.

This module guards **the agent the bouncer is protecting** — the
proxied workload's cost/call rate against AWS / DB / LLM upstreams.
It is a security control on the customer's runaway-agent blast
radius. Different subject, different blast radius, different audit
event class. No code is shared with the LLM-budget modules; the only
overlap is the "sliding window + cap" shape, which we deliberately
mirror from :mod:`iam_jit.bouncer.burst` (the closest in-tree analog).

Honest framing per ``[[ibounce-honest-positioning]]``
-----------------------------------------------------
We cannot measure real USD spend precisely from inside an HTTP proxy
(we don't see your AWS bill in real time, and per-request cost
depends on result-set sizes we don't always parse). So the breaker
trips on whichever measurable dimension the operator configures:

  * ``max_calls_per_window`` — exact gated-call count. Always precise.
  * ``max_usd_per_window``   — an **ESTIMATE** from a coarse per-call
    rate card (see :mod:`.cost_estimator`). The breaker SAYS it's an
    estimate everywhere it surfaces a dollar figure.

Default OFF per ``[[v1-scope-bar]]`` + ``[[safety-mode-lean-permissive]]``;
when enabled the default threshold is generous so legitimate work is
never blocked by surprise.
"""

from __future__ import annotations

from .breaker import (
    CostCircuitBreaker,
    TripState,
    active_cost_circuit_breaker,
    register_cost_circuit_breaker,
    reset_for_tests,
)
from .config import CircuitBreakerConfig, ConfigError, load_config
from .cost_estimator import estimate_call_cost_usd

__all__ = [
    "CircuitBreakerConfig",
    "ConfigError",
    "CostCircuitBreaker",
    "TripState",
    "active_cost_circuit_breaker",
    "estimate_call_cost_usd",
    "load_config",
    "register_cost_circuit_breaker",
    "reset_for_tests",
]
