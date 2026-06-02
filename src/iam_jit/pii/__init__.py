# ADOPT-7 / #721 — custom PII detectors, defined DECLARATIVELY.
"""Operator-defined custom PII entities on top of Presidio's custom-
recognizer API.

WHAT THIS IS
------------
An operator declares org-specific PII entities in a simple config file
(YAML/JSON) — an entity name plus regex patterns, an optional deny-list
of literal terms, optional context words, and a confidence score. Each
declared entity compiles directly into a Presidio
``PatternRecognizer`` / deny-list recognizer. We then run those
recognizers over text (a bouncer request/response body, a SQL string, a
pasted blob) and redact every match. This extends the bouncer's
existing credential/PII redaction path
(``iam_jit.bouncer.audit_export.retention``) so PCI/PII protection
reaches entities AWS-shaped defaults can't know about — employee badge
IDs, internal project codenames, customer-account formats, and so on.

NO SERVER-SIDE LLM / NL PARSING  (per [[no-nl-synthesis]] +
[[bouncer-zero-llm-when-agent-in-loop]])
-------------------------------------------------------------------
"Plain-language" here means a SIMPLE DECLARATIVE config that maps 1:1
onto Presidio recognizer constructor arguments. There is NO model that
interprets prose. The operator writes the regex / examples / keywords;
we build recognizers from exactly those fields. An IDE agent (Claude
Code, Cursor) can help an operator AUTHOR the config off-line — but
iam-jit itself never calls an LLM to turn English into a recognizer.

OPTIONAL DEPENDENCY  (default-off / opt-in)
-------------------------------------------
``presidio-analyzer`` is an OPTIONAL extra (``pip install
'iam-jit[pii]'``). When it is absent the whole feature is a clean
no-op with a clear pip hint — never a crash. The feature only does
anything when the operator SUPPLIES a custom-entities config; there is
no default entity set here (the AWS-shaped credential defaults stay in
the retention module).

HONESTY  (per [[ibounce-honest-positioning]])
---------------------------------------------
Regex + keyword + deny-list detection has false positives AND false
negatives. We say so, loudly, in the CLI output and the scan-result
caveat. This is operator-defined pattern matching, NOT ML-grade named-
entity recognition. A too-broad regex over-redacts; a too-narrow one
misses real PII. The operator owns the tradeoff.
"""

from __future__ import annotations

from .config import (
    CustomEntity,
    CustomPiiConfig,
    PiiConfigError,
    load_config,
    parse_config,
)
from .recognizers import (
    HONESTY_CAVEAT,
    PiiMatch,
    PiiScanResult,
    PresidioUnavailableError,
    build_recognizers,
    presidio_available,
    redact_text,
    scan_text,
)

__all__ = [
    "CustomEntity",
    "CustomPiiConfig",
    "PiiConfigError",
    "load_config",
    "parse_config",
    "HONESTY_CAVEAT",
    "PiiMatch",
    "PiiScanResult",
    "PresidioUnavailableError",
    "build_recognizers",
    "presidio_available",
    "redact_text",
    "scan_text",
]
