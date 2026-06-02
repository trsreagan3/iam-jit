"""Indirect-prompt-injection response-body scanner (task #730).

Scans OUTBOUND tool-response bodies for indirect prompt-injection
payloads — patterns that smuggle adversarial instructions into the
agent's context via the response of an external tool call. OWASP
draft Agentic Top-10 ranks this the top risk for autonomous agents.

This is a SEPARATE module from `iam_jit.prompt_injection`, which
scans INBOUND user prompts. The two modules share some regex shapes
but have different calibration profiles: legitimate user chat
sometimes mentions "ignore" / "previous" / "instruction" benignly;
legitimate tool responses almost never do.

Public API:

  - `scan_response_body(body, *, content_type=None, allowlist_patterns=())`
      → `ScanResult`
  - `ScanResult` (frozen dataclass)
  - `Indicator` (frozen dataclass)
  - `Action` (Literal: warn | strip | deny | allow)
  - `ProfileConfig` (frozen dataclass)
  - `decide_action(result, profile)` → `Action`
  - `apply_strip(body, result)` → str

Per [[ibounce-honest-positioning]] + [[scorer-is-ground-truth]]:
- Every indicator carries `rule`, `source`, `severity`, `layer`.
- Confidence is a deterministic function of indicators; we DON'T
  tune it post-hoc to make demos look better.
- The "we catch N% of injections" claim is INTENTIONALLY DEFERRED.
"""

from __future__ import annotations

from .config import ProfileConfig
from .scanner import (
    Action,
    Indicator,
    ScanResult,
    apply_strip,
    decide_action,
    scan_response_body,
)

__all__ = [
    "Action",
    "Indicator",
    "ProfileConfig",
    "ScanResult",
    "apply_strip",
    "decide_action",
    "scan_response_body",
]
