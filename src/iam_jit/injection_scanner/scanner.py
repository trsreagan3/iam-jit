"""Response-body injection scanner — public entry points.

Per [[ibounce-honest-positioning]]:
  - Every detected indicator is reported with its rule name + source.
  - Confidence weights are documented (see `_compute_confidence`) and
    must not be tuned post-hoc per [[scorer-is-ground-truth]].
  - Below-confidence results include `low_confidence_explanation` —
    never silent passes.

The scanner is a PURE FUNCTION of its inputs (body bytes + config).
No network, no side effects. Bouncers wire the verdict into their
audit + response-mutation paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from iam_jit import prompt_injection

from .config import ProfileConfig
from .rules import (
    ALL_RULES,
    HIGH_SIGNAL_RULES,
    MEDIUM_SIGNAL_RULES,
    HEURISTIC_RULES,
    Rule,
)


Action = Literal["warn", "strip", "deny", "allow"]


@dataclass(frozen=True)
class Indicator:
    """Single rule match within a scanned body.

    `layer` is one of:
      - "curated"  — matched a rule from this module's HIGH/MEDIUM set
      - "heuristic" — matched a structural / obfuscation-shape rule
      - "delegated" — matched the input scanner's
        `iam_jit.prompt_injection.detect()` rule set

    `source` mirrors `Rule.source` ("iam-jit" / "owasp-llm01" /
    "owasp-agentic-01" / "indirect-pi-research") so audit logs can
    cite provenance.
    """

    rule: str
    snippet: str
    layer: str
    severity: str
    source: str


@dataclass(frozen=True)
class ScanResult:
    """Verdict from `scan_response_body`.

    `suggested_action` is the action mode the scanner WOULD pick if
    the operator hadn't overridden via profile config. Bouncers call
    `decide_action(result, profile)` to combine the verdict + the
    operator's profile-config-supplied action.

    `low_confidence_explanation` is populated when `confidence < 0.5`
    and `detected is True` — so callers always have a reason string
    they can log instead of just dropping low-confidence detections
    silently. None when confidence >= 0.5 or when nothing was detected.
    """

    detected: bool
    indicators: tuple[Indicator, ...] = field(default_factory=tuple)
    confidence: float = 0.0
    suggested_action: Action = "allow"
    low_confidence_explanation: str | None = None
    body_truncated: bool = False
    skipped_reason: str | None = None  # set when scanner skipped (e.g. allowlist)


# ----------------------------------------------------------------------
# Confidence weighting. Documented in the design memo. Per
# [[scorer-is-ground-truth]] this MUST NOT be tuned post-hoc to
# make individual demos pass.
# ----------------------------------------------------------------------


def _compute_confidence(
    high_count: int, medium_count: int
) -> tuple[float, Action]:
    """Map indicator counts → (confidence, suggested action)."""
    if high_count >= 2:
        return 0.95, "deny"
    if high_count == 1 and medium_count >= 1:
        return 0.85, "warn"
    if high_count == 1:
        return 0.8, "warn"
    if medium_count >= 2:
        return 0.55, "warn"
    if medium_count == 1:
        return 0.35, "allow"
    return 0.0, "allow"


def _normalize_input(body: str | bytes) -> str:
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if not isinstance(body, str):
        return ""
    return body


def _allowlist_matches(
    body: str, compiled_allowlist: tuple[re.Pattern[str], ...]
) -> str | None:
    """Return the matching allowlist pattern (str) or None."""
    for pat in compiled_allowlist:
        if pat.search(body):
            return pat.pattern
    return None


def _scan_with_rule_set(
    body: str, rules: tuple[Rule, ...], layer: str
) -> list[Indicator]:
    out: list[Indicator] = []
    for rule in rules:
        m = rule.pattern.search(body)
        if m:
            snippet = m.group(0)
            if len(snippet) > 80:
                snippet = snippet[:80]
            out.append(
                Indicator(
                    rule=rule.name,
                    snippet=snippet,
                    layer=layer,
                    severity=rule.severity,
                    source=rule.source,
                )
            )
    return out


def _delegate_input_scanner(body: str) -> list[Indicator]:
    """Layer 3 — run the existing input-side scanner.

    Per the design memo, the input scanner's rule set is a STRICT
    SUBSET of legitimate response space too: legitimate tool responses
    don't say "ignore previous instructions". We treat each of its
    `reasons` as a high-severity indicator with source `iam-jit`.

    The input scanner has its own confidence model; we collapse its
    verdict to one indicator per reason and let our own confidence
    function recombine.
    """
    verdict = prompt_injection.detect(body)
    if not verdict.detected:
        return []
    out: list[Indicator] = []
    for reason, snippet in zip(verdict.reasons, verdict.snippets):
        # Input scanner reasons can carry a `:variant` suffix
        # (e.g., `role-impersonation:base64`); preserve it as-is so
        # audit logs are unambiguous.
        out.append(
            Indicator(
                rule=f"input-scanner:{reason}",
                snippet=snippet[:80],
                layer="delegated",
                severity="high" if verdict.confidence == "high" else "medium",
                source="iam-jit",
            )
        )
    return out


def scan_response_body(
    body: str | bytes,
    *,
    content_type: str | None = None,
    allowlist_patterns: tuple[str, ...] = (),
    max_body_bytes: int = 64 * 1024,
) -> ScanResult:
    """Scan `body` for indirect-prompt-injection indicators.

    Args:
      body: response body text or bytes. Bytes are decoded utf-8 with
        `errors="replace"`; binary responses (images, etc.) are still
        decoded but the resulting mojibake has no injection shape so
        produces no false positive.
      content_type: optional Content-Type header. Currently used only
        to short-circuit `image/*` / `audio/*` / `video/*` / `font/*`
        bodies which have no text-injection surface. Other types
        are scanned normally.
      allowlist_patterns: tuple of regex strings. If any matches the
        body, scan is skipped and `skipped_reason="allowlist:<pat>"`
        is set.
      max_body_bytes: bodies above this size are truncated before
        scanning (ReDoS guard).

    Returns: `ScanResult` describing detection state + indicators.
    """
    text = _normalize_input(body)

    # Empty / trivial body: no point scanning.
    if len(text.strip()) < 4:
        return ScanResult(detected=False, suggested_action="allow")

    # Skip binary-shaped Content-Types. We still allow text/* and
    # application/* (HTML, JSON, XML, etc.) through.
    if content_type:
        ct = content_type.lower().split(";", 1)[0].strip()
        if (
            ct.startswith("image/")
            or ct.startswith("audio/")
            or ct.startswith("video/")
            or ct.startswith("font/")
        ):
            return ScanResult(
                detected=False,
                suggested_action="allow",
                skipped_reason=f"binary-content-type:{ct}",
            )

    # Compile allowlist once.
    compiled_allowlist: tuple[re.Pattern[str], ...] = tuple(
        re.compile(p) for p in allowlist_patterns if p
    )
    if compiled_allowlist:
        matched = _allowlist_matches(text, compiled_allowlist)
        if matched:
            return ScanResult(
                detected=False,
                suggested_action="allow",
                skipped_reason=f"allowlist:{matched[:80]}",
            )

    # Truncate (ReDoS guard).
    body_truncated = False
    if len(text) > max_body_bytes:
        text = text[:max_body_bytes]
        body_truncated = True

    indicators: list[Indicator] = []
    indicators.extend(_scan_with_rule_set(text, HIGH_SIGNAL_RULES, "curated"))
    indicators.extend(_scan_with_rule_set(text, MEDIUM_SIGNAL_RULES, "curated"))
    indicators.extend(_scan_with_rule_set(text, HEURISTIC_RULES, "heuristic"))
    indicators.extend(_delegate_input_scanner(text))

    if not indicators:
        return ScanResult(
            detected=False,
            suggested_action="allow",
            body_truncated=body_truncated,
        )

    # Dedupe by rule name (multiple variants can hit the same rule).
    seen: set[str] = set()
    unique: list[Indicator] = []
    for ind in indicators:
        if ind.rule in seen:
            continue
        seen.add(ind.rule)
        unique.append(ind)

    high_count = sum(1 for i in unique if i.severity == "high")
    medium_count = sum(1 for i in unique if i.severity == "medium")
    confidence, suggested = _compute_confidence(high_count, medium_count)

    low_conf_explanation: str | None = None
    if confidence < 0.5:
        low_conf_explanation = (
            f"matched {len(unique)} medium-signal rule(s) only: "
            + ", ".join(i.rule for i in unique)
        )

    return ScanResult(
        detected=True,
        indicators=tuple(unique),
        confidence=confidence,
        suggested_action=suggested,
        low_confidence_explanation=low_conf_explanation,
        body_truncated=body_truncated,
    )


# ----------------------------------------------------------------------
# Action decision + body mutation
# ----------------------------------------------------------------------


def decide_action(result: ScanResult, profile: ProfileConfig) -> Action:
    """Reconcile the scanner verdict with operator profile config.

    Rules:
      - Scanner says `allow` → always `allow` (no detection).
      - Profile says `deny` but confidence < `min_confidence_for_deny`
        → downgrade to `warn`.
      - Profile says `strip` but no high-severity indicators → downgrade
        to `warn` (no high-confidence region to redact).
      - Otherwise: profile's configured action wins.

    The scanner's `suggested_action` is informational; the operator's
    profile is the authority. We never UPGRADE the operator's chosen
    action (no surprise denies).
    """
    if not result.detected:
        return "allow"
    op_action: Action = profile.action
    if op_action == "deny":
        if result.confidence < profile.min_confidence_for_deny:
            return "warn"
        return "deny"
    if op_action == "strip":
        has_high = any(i.severity == "high" for i in result.indicators)
        if not has_high:
            return "warn"
        return "strip"
    if op_action == "allow":
        return "allow"
    return "warn"


def apply_strip(body: str | bytes, result: ScanResult) -> str:
    """Replace matching regions in the body with redaction markers.

    Strip is line-granular: any line containing one or more indicator
    snippets is replaced with `[iam-jit:injection-redacted: <rule>]`.
    Line-level (rather than offset-level) keeps the output readable
    + survives the line-ending normalization done by upstream HTTP
    clients.

    No-op when `result.detected` is False.
    """
    text = _normalize_input(body)
    if not result.detected or not result.indicators:
        return text

    # Build a list of substring → rule mappings. Match the indicator
    # snippet anywhere in a line.
    snippet_to_rule: list[tuple[str, str]] = [
        (i.snippet, i.rule) for i in result.indicators if i.snippet
    ]
    if not snippet_to_rule:
        return text

    lines = text.splitlines(keepends=True)
    out_lines: list[str] = []
    for line in lines:
        matched_rule: str | None = None
        for snippet, rule_name in snippet_to_rule:
            if snippet and snippet in line:
                matched_rule = rule_name
                break
        if matched_rule:
            # Preserve the original line ending so callers don't get
            # CRLF/LF surprises.
            ending = ""
            if line.endswith("\r\n"):
                ending = "\r\n"
            elif line.endswith("\n"):
                ending = "\n"
            elif line.endswith("\r"):
                ending = "\r"
            out_lines.append(
                f"[iam-jit:injection-redacted: {matched_rule}]{ending}"
            )
        else:
            out_lines.append(line)
    return "".join(out_lines)
