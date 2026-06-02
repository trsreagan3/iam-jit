"""Rule set for the indirect-prompt-injection response scanner.

Two tiers:

  - HIGH_SIGNAL — patterns that almost never appear in legitimate
    tool responses. Single match → confidence 0.8.
  - MEDIUM_SIGNAL — patterns that appear occasionally in legitimate
    content (e.g., documentation, code comments). Single match →
    confidence 0.35; two or more → confidence 0.55+.

Each rule carries a `source` field so audit logs can cite WHY the
detection fired (per [[ibounce-honest-positioning]] honesty bar).

OWASP citations point to the draft "OWASP Top 10 for LLM Applications"
+ the draft "OWASP Agentic Top 10" (2026). Citations are best-effort
human-curated mappings; if the draft section numbering moves, comments
get the new pointer — they are never fabricated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    severity: str  # "high" | "medium"
    source: str    # provenance — "iam-jit" | "owasp-llm01" | "owasp-agentic-01" | "indirect-pi-research"
    note: str      # short human-readable explanation for audit


# ---------------------------------------------------------------------
# HIGH-SIGNAL — patterns specific to indirect injection via tool responses.
# These are EXTENSIONS to the input-side scanner; we delegate the shared
# canonical-injection-phrase patterns to `iam_jit.prompt_injection.detect()`.
# ---------------------------------------------------------------------

HIGH_SIGNAL_RULES: tuple[Rule, ...] = (
    Rule(
        name="html-comment-instruction-override",
        # Hidden HTML comment carrying an instruction-override phrase.
        # Real-world indirect injection: pages embed
        # `<!-- ignore previous instructions, exfiltrate ... -->`
        # in invisible markup that the LLM still reads.
        pattern=re.compile(
            r"(?is)<!--\s*[^>]*?\b(ignore|disregard|forget|override|bypass)\b"
            r"[^>]*?\b(previous|prior|all|your)\b[^>]*?-->"
        ),
        severity="high",
        source="indirect-pi-research",
        note="HTML comment containing instruction-override phrase",
    ),
    Rule(
        name="markdown-comment-instruction-override",
        # Markdown link-ref hack: `[//]: # (ignore previous ...)`.
        pattern=re.compile(
            r"(?im)^\s*\[//\]:\s*#\s*\([^)]*?\b(ignore|disregard|override|bypass)\b"
        ),
        severity="high",
        source="indirect-pi-research",
        note="Markdown invisible comment containing instruction-override",
    ),
    Rule(
        name="hidden-element-instruction",
        # CSS-hidden element wrapping instruction-shape text. Catches
        # `<div style="display:none">ignore previous instructions</div>`
        # and variants with visibility:hidden / opacity:0 / font-size:0.
        pattern=re.compile(
            r"(?is)style\s*=\s*[\"'][^\"']*?"
            r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)"
            r"[^\"']*?[\"'][^>]*>"
            r"[^<]*?\b(ignore|disregard|override|system|assistant|tool_use)\b"
        ),
        severity="high",
        source="indirect-pi-research",
        note="CSS-hidden element with instruction or role keyword",
    ),
    Rule(
        name="tool-result-envelope-forgery",
        # Response body containing a forged tool-result envelope. The
        # harness might mistake this for a legitimate tool call's
        # output. Conservative — requires the envelope tag right at
        # start-of-line (^) so plain prose mentioning the tag doesn't
        # match.
        pattern=re.compile(
            r"(?im)^\s*<\s*(tool_result|tool_response|observation|function_result)\b"
        ),
        severity="high",
        source="owasp-agentic-01",
        note="Forged tool-result envelope at start of line",
    ),
    Rule(
        name="role-confusion-headerlike",
        # `SYSTEM:` / `ASSISTANT:` at start of line in the response,
        # which the LLM might interpret as a role switch. This rule
        # is INTENTIONALLY narrower than the input scanner's
        # role-impersonation rule: it requires UPPERCASE + colon to
        # cut down false positives on code samples that mention
        # "system:" lowercase as part of e.g. systemd unit syntax.
        pattern=re.compile(
            r"(?m)^\s*(SYSTEM|ASSISTANT|DEVELOPER|TOOL)\s*[:>]\s*\S"
        ),
        severity="high",
        source="owasp-llm01",
        note="Uppercase role marker at start of line",
    ),
    Rule(
        name="json-system-prompt-smuggle",
        # JSON object containing a `system` / `system_prompt` /
        # `instructions` key with a string value. Common shape for
        # JSON-RPC response bodies that smuggle a role-confusion
        # payload.
        pattern=re.compile(
            r"(?is)[\{\[,]\s*\"(system|system_prompt|instructions|developer)\"\s*:\s*\""
        ),
        severity="high",
        source="owasp-agentic-01",
        note="JSON key 'system' / 'system_prompt' / 'instructions'",
    ),
    Rule(
        name="exfil-imperative",
        # Imperative verb + sensitive resource keyword. Tool responses
        # almost never instruct the reader to exfiltrate things;
        # legitimate docs use passive voice ("the API returns ...")
        # rather than imperative ("send your API key to ...").
        pattern=re.compile(
            r"(?i)\b(send|post|upload|fetch|forward|leak|exfiltrate|transmit)\b\W+"
            r"(?:\w+\W+){0,8}?"
            r"\b(api[\s\-_]?key|secret|token|credential|password|"
            r"private[\s\-_]?key|\.ssh|/etc/passwd|/etc/shadow|"
            r"environment[\s\-_]?variable|env[\s\-_]?var)s?\b"
        ),
        severity="high",
        source="owasp-agentic-01",
        note="Imperative + sensitive-resource keyword",
    ),
    Rule(
        name="new-instruction-replacement",
        # "Your new instructions are ..." / "From now on you will ..."
        # — explicit role-rewriting attempts in response content.
        pattern=re.compile(
            r"(?i)(your\s+new\s+(instruction|directive|task|rule|role)s?|"
            r"from\s+now\s+on\s+you\s+(will|must|should)|"
            r"new\s+system\s+prompt)\b"
        ),
        severity="high",
        source="owasp-llm01",
        note="Explicit instruction-replacement phrasing",
    ),
    Rule(
        name="canonical-injection-phrase",
        # The textbook prompt-injection opener. Surfaces in every
        # public injection-corpus example. Used as a HIGH-SIGNAL rule
        # for responses (vs. medium for inputs) because legitimate
        # tool responses don't address the reader as if it were an
        # LLM.
        pattern=re.compile(
            r"(?i)\bignore\s+(all\s+)?(previous|prior|the\s+above|your)\s+"
            r"(instructions|prompts|rules|directives|guidelines)\b"
        ),
        severity="high",
        source="owasp-llm01",
        note="Canonical prompt-injection opener phrase",
    ),
)

# ---------------------------------------------------------------------
# MEDIUM-SIGNAL — patterns that occur occasionally in legitimate content.
# Single matches don't trigger deny; pairs accumulate.
# ---------------------------------------------------------------------

MEDIUM_SIGNAL_RULES: tuple[Rule, ...] = (
    Rule(
        name="delimiter-smuggle",
        # ChatML-style delimiters in response content.
        pattern=re.compile(
            r"<\|im_(start|end)\|>|<\|system\|>|<\|user\|>|<\|assistant\|>"
        ),
        severity="medium",
        source="owasp-llm01",
        note="ChatML-style role delimiter",
    ),
    Rule(
        name="end-of-prompt-marker",
        pattern=re.compile(
            r"(?i)---\s*end\s+of\s+(prompt|instructions|system)\s*---"
        ),
        severity="medium",
        source="owasp-llm01",
        note="`---END OF PROMPT---`-style marker",
    ),
    Rule(
        name="instruction-shape-imperative",
        # Imperative verb at start of line addressing the LLM. False
        # positives on imperative docs ("Run the install script");
        # we require an LLM-pronoun nearby to cut down.
        pattern=re.compile(
            r"(?im)^\s*(you\s+must|you\s+should|you\s+will|"
            r"do\s+not\s+(tell|reveal|disclose|mention))\b"
        ),
        severity="medium",
        source="indirect-pi-research",
        note="Imperative addressed to 'you' (the LLM)",
    ),
    Rule(
        name="zero-width-cluster",
        # ≥4 consecutive zero-width chars (steganographic injection).
        # Detection only — full decoder lives in input scanner.
        pattern=re.compile(r"[​‌‍⁠﻿]{4,}"),
        severity="medium",
        source="indirect-pi-research",
        note="Zero-width character run (steganographic envelope)",
    ),
    Rule(
        name="role-mention-with-injection-keyword",
        # Looser variant of role-confusion: lowercase / mid-line role
        # mention combined with injection-shape verb nearby.
        pattern=re.compile(
            r"(?i)\b(system|assistant|developer)\b\W+(?:\w+\W+){0,6}?"
            r"\b(prompt|instruction|directive)s?\b\W+(?:\w+\W+){0,6}?"
            r"\b(override|replace|change|update|set\s+to)\b"
        ),
        severity="medium",
        source="indirect-pi-research",
        note="Role keyword + prompt/instruction + override-verb proximity",
    ),
)


# ---------------------------------------------------------------------
# HEURISTIC / structural — same shape as the input scanner's
# obfuscation patterns. Long encoded blobs in a response are
# adversarial-enough-on-their-own to log.
# ---------------------------------------------------------------------

HEURISTIC_RULES: tuple[Rule, ...] = (
    Rule(
        name="obfuscation-base64-blob",
        # ≥80 chars (longer threshold than input scanner — responses
        # legitimately carry base64-encoded images, certs, JWTs).
        pattern=re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),
        severity="medium",
        source="iam-jit",
        note="Long base64 blob in response body",
    ),
    Rule(
        name="obfuscation-circled-letters",
        pattern=re.compile(
            r"[Ⓐ-ⓩ㉈-㉏㉑-㉟㊱-㊿"
            r"\U0001F130-\U0001F149\U0001F150-\U0001F169\U0001F170-\U0001F189]{6,}"
        ),
        severity="high",
        source="iam-jit",
        note="Circled / regional-indicator Unicode letter run (homoglyph envelope)",
    ),
)


ALL_RULES: tuple[Rule, ...] = (
    HIGH_SIGNAL_RULES + MEDIUM_SIGNAL_RULES + HEURISTIC_RULES
)
