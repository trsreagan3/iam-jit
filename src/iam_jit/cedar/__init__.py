# ADOPT-5 / #719 — IAM <-> Cedar policy interop (portability layer).
"""AWS IAM policy <-> Cedar policy *interoperability* (portability).

iam-jit produces and consumes AWS IAM policy JSON. AWS Bedrock
AgentCore (and AWS Verified Permissions) use the **Cedar** policy
language. This module lets a customer move a policy between iam-jit /
Bounce and a Cedar-based system **without rewriting it by hand**.

POSITIONING (read this before extending — per [[cedar-positioning]]):

    iam-jit is NOT Cedar and does NOT compete with Cedar. Cedar is an
    application-level authorization language (sister to OPA / Casbin /
    Permit.io). iam-jit is AWS IAM credential issuance (sister to Apono
    / Opal / ConductorOne). They live in different lanes and many
    customers use both. This module is strictly an **interop /
    portability convenience** so a policy authored in one system can be
    carried to the other. It is emphatically NOT a claim that iam-jit
    "is Cedar," "uses Cedar internally," or "evaluates Cedar." The
    scorer still has AWS IAM semantics directly; nothing here changes
    that.

HONESTY (per [[ibounce-honest-positioning]] — a wrong policy
translation is a SECURITY RISK, so this layer fails LOUD, never silent):

    AWS IAM and Cedar are structurally similar (both allow/deny over
    principal / action / resource / condition) but they are NOT 1:1.
    Several IAM constructs have no faithful Cedar equivalent, and vice
    versa. Wherever a construct cannot be translated without changing
    its meaning, this module emits an explicit *translation note* and a
    visible `// UNTRANSLATABLE:` / `// NOTE:` marker in the output — it
    NEVER silently drops the construct or emits a subtly-wrong policy.
    Callers can inspect `TranslationResult.notes` and
    `TranslationResult.is_lossy` to gate on faithfulness.

Public API:

    iam_to_cedar(policy_json)  -> TranslationResult   (cedar text + notes)
    cedar_to_iam(cedar_text)   -> TranslationResult   (iam policy + notes)

Both are pure / read-only — they translate text, they NEVER touch AWS.
"""

from __future__ import annotations

from .translate import (
    TranslationError,
    TranslationNote,
    TranslationResult,
    cedar_to_iam,
    iam_to_cedar,
)

__all__ = [
    "TranslationError",
    "TranslationNote",
    "TranslationResult",
    "cedar_to_iam",
    "iam_to_cedar",
]
