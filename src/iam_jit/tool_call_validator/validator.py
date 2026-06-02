"""Hallucinated-tool-call validator — public entry points.

Pure function of `(body, corpus, allowlist)`. No network, no IO. The
bouncer wires the verdict into its audit + body-mutation paths.

Per [[ibounce-honest-positioning]]:
- Every detected indicator carries `rule`, `shape`, `tool_name`,
  `severity`, `source`, `reason`.
- Confidence weighting is documented (see `_compute_confidence`) and
  per [[scorer-is-ground-truth]] MUST NOT be tuned post-hoc.
- Sub-0.5 confidence populates `low_confidence_explanation` so
  callers always have a reason string instead of silent drops.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from .config import ProfileConfig
from .corpus import SchemaCorpus, ToolSchema, default_corpus
from .rules import (
    has_naming_style_mix,
    is_placeholder_value,
    present_minus_allowed,
    required_minus_present,
)


Action = Literal["warn", "strip", "deny", "allow"]


@dataclass(frozen=True)
class Indicator:
    """One rule-match within a validated tool call.

    `shape` is the wire shape (`mcp` | `openai` | `anthropic`).
    `tool_name` is the name as observed in the body — even when
    hallucinated, we surface it so audit logs can correlate.
    `reason` is a short human-readable phrase explaining the match
    (per [[ibounce-honest-positioning]]).
    """

    rule: str
    shape: str
    tool_name: str
    severity: str  # "high" | "medium"
    source: str
    reason: str


@dataclass(frozen=True)
class ValidationResult:
    """Verdict from `validate`.

    `suggested_action` is what the validator would do absent operator
    override; `decide_action(result, profile)` reconciles it with the
    operator's profile config.
    """

    detected: bool
    indicators: tuple[Indicator, ...] = field(default_factory=tuple)
    confidence: float = 0.0
    suggested_action: Action = "allow"
    low_confidence_explanation: str | None = None
    body_truncated: bool = False
    skipped_reason: str | None = None
    # The set of tool-call (shape, name) pairs we extracted from the
    # body — useful for audit + for `apply_strip`. Empty when no
    # tool-call shape was recognized.
    extracted_calls: tuple[tuple[str, str], ...] = field(default_factory=tuple)


# ----------------------------------------------------------------------
# Confidence weighting. Per [[scorer-is-ground-truth]] this MUST NOT be
# tuned post-hoc to make individual demos pass. Documented in the
# design memo.
# ----------------------------------------------------------------------

_HIGH_SEVERITY_RULES: frozenset[str] = frozenset(
    {"hallucinated-tool-name", "placeholder-credential", "missing-required-arg"}
)
_MEDIUM_SEVERITY_RULES: frozenset[str] = frozenset(
    {"unexpected-arg", "naming-style-mix"}
)


def _compute_confidence(
    high_count: int, medium_count: int
) -> tuple[float, Action]:
    """Map indicator counts → (confidence, suggested action)."""
    if high_count >= 2:
        return 0.95, "deny"
    if high_count == 1 and medium_count >= 1:
        return 0.85, "warn"
    if high_count == 1:
        return 0.80, "warn"
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


# ----------------------------------------------------------------------
# Tool-call extraction — turn a parsed JSON body into a list of
# (shape, name, arguments) tuples. Each shape's extractor is independent
# so adding new shapes is local.
# ----------------------------------------------------------------------


def _extract_mcp_calls(parsed: Any) -> list[tuple[str, str, dict[str, Any]]]:
    """Recognize MCP `tools/call` + raw method-shape calls.

    Two MCP variants we recognize:

      A. `{"jsonrpc":"2.0","method":"tools/call",
            "params":{"name":"X","arguments":{...}}}`
         — the agent is asking the server to invoke a named tool.
         The TARGET tool is `params.name`; the OUTER method is the
         MCP transport, not the call.

      B. `{"jsonrpc":"2.0","method":"resources/read","params":{"uri":...}}`
         — the agent is invoking an MCP standard method directly. The
         method name itself is the tool.
    """
    out: list[tuple[str, str, dict[str, Any]]] = []
    if not isinstance(parsed, dict):
        return out
    if parsed.get("jsonrpc") != "2.0":
        return out
    method = parsed.get("method")
    if not isinstance(method, str):
        return out
    params = parsed.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if isinstance(name, str):
            if not isinstance(args, dict):
                args = {}
            out.append(("mcp", name, args))
            return out
    # Direct MCP method — treat the method itself as the tool name.
    out.append(("mcp", method, params))
    return out


def _extract_openai_calls(parsed: Any) -> list[tuple[str, str, dict[str, Any]]]:
    """Recognize OpenAI tool_calls / legacy function_call shapes.

    Several places these can appear:

      - Top-level `function_call` (legacy single-call shape from older
        Chat Completions outputs)
      - Top-level `tool_calls` list
      - Inside `messages[*].tool_calls`
      - Inside `messages[*].function_call`
    """
    out: list[tuple[str, str, dict[str, Any]]] = []
    if not isinstance(parsed, dict):
        return out

    # Top-level function_call (legacy)
    fc = parsed.get("function_call")
    if isinstance(fc, dict):
        name = fc.get("name")
        args_raw = fc.get("arguments")
        if isinstance(name, str):
            out.append(("openai", name, _decode_openai_arguments(args_raw)))

    # Top-level tool_calls
    tc = parsed.get("tool_calls")
    if isinstance(tc, list):
        for entry in tc:
            out.extend(_openai_one_tool_call(entry))

    # messages[*].tool_calls / messages[*].function_call
    messages = parsed.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            mfc = msg.get("function_call")
            if isinstance(mfc, dict):
                name = mfc.get("name")
                if isinstance(name, str):
                    out.append(
                        ("openai", name, _decode_openai_arguments(mfc.get("arguments")))
                    )
            mtc = msg.get("tool_calls")
            if isinstance(mtc, list):
                for entry in mtc:
                    out.extend(_openai_one_tool_call(entry))
    return out


def _openai_one_tool_call(entry: Any) -> list[tuple[str, str, dict[str, Any]]]:
    if not isinstance(entry, dict):
        return []
    # `{"type":"function","function":{"name":..., "arguments":"..."}}`
    fn = entry.get("function")
    if isinstance(fn, dict):
        name = fn.get("name")
        if isinstance(name, str):
            return [("openai", name, _decode_openai_arguments(fn.get("arguments")))]
    # Some bridges flatten directly:
    name = entry.get("name")
    if isinstance(name, str):
        return [("openai", name, _decode_openai_arguments(entry.get("arguments")))]
    return []


def _decode_openai_arguments(raw: Any) -> dict[str, Any]:
    """OpenAI arguments are STRINGIFIED JSON. Empty / malformed → {}."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        if not raw.strip():
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _extract_anthropic_calls(
    parsed: Any,
) -> list[tuple[str, str, dict[str, Any]]]:
    """Recognize Anthropic tool_use blocks inside messages content."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    if not isinstance(parsed, dict):
        return out
    # Anthropic Messages requests sometimes carry the assistant's
    # previously-emitted tool_use inside the messages array as
    # message.role == "assistant", content blocks of type "tool_use".
    # The agent then sends back the tool_result; we validate
    # `tool_use` blocks because those are what the model emitted.
    messages = parsed.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") != "tool_use":
                        continue
                    name = block.get("name")
                    inp = block.get("input") or {}
                    if isinstance(name, str):
                        if not isinstance(inp, dict):
                            inp = {}
                        out.append(("anthropic", name, inp))
    # Some clients put a single tool_use at the top level (rare but seen
    # in MCP-over-Anthropic bridges).
    if parsed.get("type") == "tool_use":
        name = parsed.get("name")
        inp = parsed.get("input") or {}
        if isinstance(name, str):
            if not isinstance(inp, dict):
                inp = {}
            out.append(("anthropic", name, inp))
    return out


def _extract_all_calls(
    parsed: Any,
) -> list[tuple[str, str, dict[str, Any]]]:
    out: list[tuple[str, str, dict[str, Any]]] = []
    out.extend(_extract_mcp_calls(parsed))
    out.extend(_extract_openai_calls(parsed))
    out.extend(_extract_anthropic_calls(parsed))
    return out


# ----------------------------------------------------------------------
# Public entry: validate
# ----------------------------------------------------------------------


def validate(
    body: str | bytes,
    *,
    schema_corpus: SchemaCorpus | None = None,
    allowlist_patterns: tuple[str, ...] = (),
    max_body_bytes: int = 64 * 1024,
) -> ValidationResult:
    """Validate `body` for hallucinated tool-call shapes.

    Args:
      body: request body text or bytes.
      schema_corpus: known-tool corpus to validate against. Defaults
        to the baked-in MCP + OpenAI + Anthropic set.
      allowlist_patterns: regex strings; matches suppress detection
        (skipped_reason set).
      max_body_bytes: bodies above this are truncated before parsing
        (ReDoS guard).

    Returns: `ValidationResult`.
    """
    corpus = schema_corpus if schema_corpus is not None else default_corpus()
    text = _normalize_input(body)

    if len(text.strip()) < 4:
        return ValidationResult(detected=False, suggested_action="allow")

    # Allowlist short-circuit.
    if allowlist_patterns:
        for raw_pat in allowlist_patterns:
            if not raw_pat:
                continue
            try:
                pat = re.compile(raw_pat)
            except re.error:
                continue
            if pat.search(text):
                snippet = raw_pat[:80]
                return ValidationResult(
                    detected=False,
                    suggested_action="allow",
                    skipped_reason=f"allowlist:{snippet}",
                )

    truncated = False
    if len(text) > max_body_bytes:
        text = text[:max_body_bytes]
        truncated = True

    # Parse JSON — non-JSON bodies aren't tool calls.
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return ValidationResult(
            detected=False,
            suggested_action="allow",
            body_truncated=truncated,
            skipped_reason="not-json",
        )

    calls = _extract_all_calls(parsed)
    if not calls:
        return ValidationResult(
            detected=False,
            suggested_action="allow",
            body_truncated=truncated,
            skipped_reason="no-tool-call-shape",
        )

    indicators: list[Indicator] = []
    for shape, name, args in calls:
        tool_schema = corpus.lookup(shape, name)
        if tool_schema is None:
            known_names = corpus.names_for_shape(shape)
            reason = (
                f"tool '{name}' not in known {shape} corpus "
                f"({len(known_names)} known tools)"
            )
            indicators.append(
                Indicator(
                    rule="hallucinated-tool-name",
                    shape=shape,
                    tool_name=name,
                    severity="high",
                    source="iam-jit",
                    reason=reason,
                )
            )
            if has_naming_style_mix(name):
                indicators.append(
                    Indicator(
                        rule="naming-style-mix",
                        shape=shape,
                        tool_name=name,
                        severity="medium",
                        source="iam-jit",
                        reason=(
                            f"tool name '{name}' mixes snake_case + "
                            f"camelCase — common hallucination tell"
                        ),
                    )
                )
            indicators.extend(_check_placeholders(shape, name, args))
            continue

        # Schema validation.
        for missing in required_minus_present(tool_schema.required, args):
            indicators.append(
                Indicator(
                    rule="missing-required-arg",
                    shape=shape,
                    tool_name=name,
                    severity="high",
                    source=tool_schema.source or "iam-jit",
                    reason=(
                        f"required field '{missing}' absent from "
                        f"'{name}' arguments"
                    ),
                )
            )
        for extra in present_minus_allowed(
            tool_schema.required, tool_schema.optional, args
        ):
            indicators.append(
                Indicator(
                    rule="unexpected-arg",
                    shape=shape,
                    tool_name=name,
                    severity="medium",
                    source=tool_schema.source or "iam-jit",
                    reason=(
                        f"field '{extra}' is not in schema for "
                        f"'{name}' (allowed: "
                        + ", ".join(
                            sorted(set(tool_schema.required) | set(tool_schema.optional))
                        )
                        + ")"
                    ),
                )
            )
        indicators.extend(_check_placeholders(shape, name, args))

    extracted = tuple((shape, name) for shape, name, _ in calls)

    if not indicators:
        return ValidationResult(
            detected=False,
            suggested_action="allow",
            body_truncated=truncated,
            extracted_calls=extracted,
        )

    # Dedupe by (rule, shape, tool_name) tuple so we don't double-count
    # the same finding when a single body has identical patterns
    # across multiple sub-calls.
    seen: set[tuple[str, str, str]] = set()
    unique: list[Indicator] = []
    for ind in indicators:
        key = (ind.rule, ind.shape, ind.tool_name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ind)

    high_count = sum(
        1 for i in unique if i.rule in _HIGH_SEVERITY_RULES
    )
    medium_count = sum(
        1 for i in unique if i.rule in _MEDIUM_SEVERITY_RULES
    )
    confidence, suggested = _compute_confidence(high_count, medium_count)

    low_conf: str | None = None
    if confidence < 0.5:
        low_conf = (
            f"matched {len(unique)} medium-signal indicator(s) only: "
            + ", ".join(i.rule for i in unique)
        )

    return ValidationResult(
        detected=True,
        indicators=tuple(unique),
        confidence=confidence,
        suggested_action=suggested,
        low_confidence_explanation=low_conf,
        body_truncated=truncated,
        extracted_calls=extracted,
    )


def _check_placeholders(
    shape: str, name: str, args: dict[str, Any]
) -> list[Indicator]:
    """Walk argument values for placeholder-credential shapes."""
    out: list[Indicator] = []
    if not isinstance(args, dict):
        return out
    for k, v in args.items():
        if is_placeholder_value(v):
            out.append(
                Indicator(
                    rule="placeholder-credential",
                    shape=shape,
                    tool_name=name,
                    severity="high",
                    source="iam-jit",
                    reason=(
                        f"argument '{k}' value looks like an LLM "
                        f"placeholder ('{str(v)[:40]}')"
                    ),
                )
            )
    return out


# ----------------------------------------------------------------------
# Action decision + body mutation
# ----------------------------------------------------------------------


def decide_action(result: ValidationResult, profile: ProfileConfig) -> Action:
    """Reconcile validator verdict with operator profile config.

    Same posture as BUILD-9:
      - Validator says allow → always allow.
      - Operator deny + confidence < min_floor → downgrade to warn.
      - Operator strip + no high-severity indicators → downgrade to warn.
      - Otherwise: operator's action wins (no surprise upgrades).
    """
    if not result.detected:
        return "allow"
    op_action: Action = profile.action
    if op_action == "deny":
        if result.confidence < profile.min_confidence_for_deny:
            return "warn"
        return "deny"
    if op_action == "strip":
        has_high = any(
            i.rule in _HIGH_SEVERITY_RULES for i in result.indicators
        )
        if not has_high:
            return "warn"
        return "strip"
    if op_action == "allow":
        return "allow"
    return "warn"


def apply_strip(body: str | bytes, result: ValidationResult) -> str:
    """Replace hallucinated tool-call entries with redaction markers.

    Strip is JSON-aware: we re-parse the body and remove (or replace
    with a marker dict) the offending tool-call sub-structures. If the
    body isn't parseable JSON we fall back to no-op (return original
    text unchanged) — the caller has already verified earlier that
    parse succeeded if `result.detected is True`.

    Returns the modified body as a string. Caller is responsible for
    re-setting `Content-Length`.
    """
    text = _normalize_input(body)
    if not result.detected or not result.indicators:
        return text

    flagged: set[tuple[str, str]] = {
        (ind.shape, ind.tool_name) for ind in result.indicators
    }

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text

    def marker(shape: str, name: str) -> dict[str, Any]:
        return {
            "_iam_jit_tool_call_redacted": True,
            "shape": shape,
            "original_name": name,
            "reason": "hallucinated-tool-call",
        }

    def visit(node: Any) -> Any:
        if isinstance(node, dict):
            # MCP tools/call: name at params.name
            if (
                node.get("jsonrpc") == "2.0"
                and node.get("method") == "tools/call"
            ):
                params = node.get("params") or {}
                if isinstance(params, dict):
                    n = params.get("name")
                    if isinstance(n, str) and ("mcp", n) in flagged:
                        return marker("mcp", n)
            # MCP raw method: method itself is the tool
            if (
                node.get("jsonrpc") == "2.0"
                and isinstance(node.get("method"), str)
            ):
                m = node["method"]
                if ("mcp", m) in flagged and m != "tools/call":
                    return marker("mcp", m)
            # Anthropic tool_use block
            if node.get("type") == "tool_use":
                n = node.get("name")
                if isinstance(n, str) and ("anthropic", n) in flagged:
                    return marker("anthropic", n)
            # OpenAI tool_calls / function_call shape
            fn = node.get("function")
            if isinstance(fn, dict):
                n = fn.get("name")
                if isinstance(n, str) and ("openai", n) in flagged:
                    return marker("openai", n)
            if isinstance(node.get("function_call"), dict):
                n = node["function_call"].get("name")
                if isinstance(n, str) and ("openai", n) in flagged:
                    new = dict(node)
                    new["function_call"] = marker("openai", n)
                    return new
            # Recurse into the remaining structure (handles
            # messages[*].content[*] / tool_calls[*] etc.).
            return {k: visit(v) for k, v in node.items()}
        if isinstance(node, list):
            return [visit(item) for item in node]
        return node

    cleaned = visit(parsed)
    return json.dumps(cleaned)
