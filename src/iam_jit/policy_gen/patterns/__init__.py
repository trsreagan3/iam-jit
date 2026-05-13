"""Heuristic pattern library — task-description phrases → action sets.

Each Pattern declares:
  - A name (used in audit logs as "matched_patterns: [...]")
  - Phrases that trigger the match (substrings of the lowercased
    description; `phrase in description.lower()` semantics — simple
    and predictable, easy for users to reason about)
  - Two action lists: `allow_actions` (broader, used with bias=allow)
    and `deny_actions` (the strict subset used with bias=deny). The
    `deny_actions` set should be a SUBSET of `allow_actions` — we
    never silently grant more actions in deny mode than in allow mode.
  - Resource kinds the pattern's actions operate on (so the resource
    extractor knows which extracted resources to pair with the
    pattern).
  - Wildcard fallback ARNs to use when no explicit resource was
    found in the description.
  - Access-type hint so the scorer's read-only mismatch rule fires
    correctly.

ADD A NEW PATTERN: Append to the relevant service file (e.g.
`s3.py`). For new services, create a new file and import the
patterns list at the bottom of this module. Each file is a flat
list of Pattern objects; no inheritance, no metaclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

AccessHint = Literal["read", "write", "read-write", "any"]


@dataclass(frozen=True)
class Pattern:
    """One mapping from task-description phrases → action set."""

    name: str
    # If ANY phrase appears (case-insensitively) in the description,
    # this pattern fires. Phrases are matched as substrings, NOT
    # whole-word — so "read s3" matches "I want to read s3 logs"
    # even though the description never says "read s3 logs" as one
    # phrase.
    phrases: tuple[str, ...]

    # Actions to include when bias=allow. Used as the union — every
    # matched pattern contributes its allow_actions.
    allow_actions: tuple[str, ...]

    # Actions to include when bias=deny. Should be a subset of
    # allow_actions. Empty list = "this pattern contributes nothing
    # in deny mode" (the user has to be more explicit).
    deny_actions: tuple[str, ...] = ()

    # Service-kind tags this pattern's actions consume. The generator
    # matches extracted resources of these kinds into the pattern's
    # statement.
    resource_kinds: tuple[str, ...] = ()

    # ARN patterns to use as the statement's Resource when no explicit
    # resource of a matching kind was extracted. Should contain `*`
    # so the deterministic scorer flags the breadth.
    wildcard_resources: tuple[str, ...] = ("*",)

    # Access type the actions imply. Used to bias the read-only flag
    # in the resulting JIT request. "any" = don't constrain.
    access_hint: AccessHint = "read-write"


def matched_patterns(description: str, library: list[Pattern]) -> list[Pattern]:
    """Return every pattern whose phrase set fires for the description.

    A phrase fires in two cases:
      1. Substring match — `phrase in description.lower()`. Catches the
         common "<verb> <service>" cases ("read s3", "query dynamodb").
      2. Whitespace-tolerant token match — when a phrase has multiple
         space-separated tokens (e.g. "deploy lambda"), it also fires
         if every token appears as a separate word in the description
         AND the tokens appear in the same order. This catches
         "deploy MY lambda", "deploy A lambda", "deploy the prod lambda"
         without expanding the phrase library exponentially. Single-
         token phrases ("decrypt") still only do substring match.
    """
    import re as _re
    desc_lc = description.lower()
    # Tokenize keeping hyphens INSIDE words — `deploy-api` is one
    # token, not two. Otherwise the token-gap matcher fires "deploy"
    # + "lambda" against "invoke the deploy-api lambda function" as
    # a false positive for the lambda-deploy pattern.
    desc_tokens = _re.findall(r"[a-z0-9*][a-z0-9*\-_]*", desc_lc)
    out: list[Pattern] = []
    for p in library:
        if any(_phrase_matches(phrase, desc_lc, desc_tokens) for phrase in p.phrases):
            out.append(p)
    return out


def _phrase_matches(phrase: str, desc_lc: str, desc_tokens: list[str]) -> bool:
    """One phrase vs one description."""
    if phrase in desc_lc:
        return True
    tokens = phrase.split()
    if len(tokens) < 2:
        return False
    # Order-preserving token-with-gaps match. Walk desc_tokens looking
    # for tokens[0] then tokens[1] (after tokens[0]) etc.
    i = 0
    j = 0
    while i < len(desc_tokens) and j < len(tokens):
        if desc_tokens[i] == tokens[j]:
            j += 1
        i += 1
    return j == len(tokens)


# Import service-specific pattern files. Each module exposes a
# module-level `PATTERNS: list[Pattern]` constant. The order here is
# stable so audit logs are reproducible.
from . import (  # noqa: E402
    api_gateway,
    cloudformation,
    dynamodb,
    ec2,
    ecs,
    iam_passrole,
    kms_misc,
    lambda_,
    logs,
    rds,
    s3,
    ssm_secrets,
)

ALL_PATTERNS: list[Pattern] = (
    s3.PATTERNS
    + lambda_.PATTERNS
    + dynamodb.PATTERNS
    + logs.PATTERNS
    + ssm_secrets.PATTERNS
    + iam_passrole.PATTERNS
    + ecs.PATTERNS
    + rds.PATTERNS
    + kms_misc.PATTERNS
    + api_gateway.PATTERNS
    + cloudformation.PATTERNS
    + ec2.PATTERNS
)
