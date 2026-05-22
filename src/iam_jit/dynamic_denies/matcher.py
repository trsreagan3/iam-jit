# #324a — ARN target matcher for the ibounce dynamic-deny path.
"""Classify a request's resource ARN against a :class:`RuleSet`'s
compiled patterns.

The matcher uses the SAME glob grammar as
``src/iam_jit/bouncer/rules.py`` so an operator who already wrote
``--arn-scope 'arn:aws:s3:::prod-*'`` for a static rule gets the
identical match semantics from a dynamic deny rule. AWS-IAM-style
glob: ``*`` matches any run of chars; ``?`` matches one char; no
character classes (``[abc]``) per IAM policy spec.

Per ``[[scorer-is-ground-truth]]`` the matcher is deterministic — no
LLM, no heuristics, no provenance-based scoring. A rule either
matches or it doesn't.

Service-only shortcuts (``arn:aws:iam:*``) are accepted; they expand
to ``arn:aws:iam:*`` which matches any IAM resource. The expansion
happens in the regex translation step — operators don't have to
write ``arn:aws:iam:*:*:*`` to match all IAM.

Secret shorthand: a target of ``secret:my-app-creds`` matches an
incoming ARN that's a Secrets Manager secret carrying the same name
suffix (``arn:aws:secretsmanager:*:*:secret:my-app-creds-RANDOM``).
The translation runs at MATCH time, not LOAD time, so the operator
can hand-edit a shorthand rule without re-resolving the ARN.
"""

from __future__ import annotations

import dataclasses
import re

from .types import Rule, RuleSet


@dataclasses.dataclass(frozen=True)
class ArnMatch:
    """The result of a successful match. Carries the rule + the
    specific target pattern that fired so the audit event surfaces
    both the rule id AND the operator-written pattern (an operator
    debugging a 403 wants both: "which rule" + "which of its targets
    fired")."""

    rule: Rule
    target_pattern: str

    @property
    def rule_id(self) -> str:
        return self.rule.id

    @property
    def reason(self) -> str:
        """Operator-supplied free-text reason — surfaces verbatim in
        the 403 ``deny_reason`` body."""
        return self.rule.reason


def match_arn(ruleset: RuleSet, arn: str | None) -> ArnMatch | None:
    """Return the first matching :class:`ArnMatch`, or ``None`` when no
    rule in ``ruleset`` matches ``arn``.

    A ``None`` or empty ARN never matches — ibounce's request parser
    surfaces ARN-less calls (e.g. some legacy STS calls) and the
    dynamic-deny check skips them cleanly so the existing decision
    pipeline runs unchanged for that traffic.

    First-match semantics (not best-match) — order is preserved from
    the on-disk file so an operator hand-editing the YAML controls
    which rule "wins" when multiple match. This mirrors the existing
    :class:`bouncer.rules.RuleSet.evaluate` first-DENY-wins
    convention.
    """
    if not arn or not ruleset.rules:
        return None
    for rule in ruleset.rules:
        for target in rule.targets:
            if _target_matches_arn(target, arn):
                return ArnMatch(rule=rule, target_pattern=target)
    return None


# ---------------------------------------------------------------------------
# Internal: glob compilation + match
# ---------------------------------------------------------------------------


_compiled_cache: dict[str, re.Pattern[str]] = {}
"""Compiled regex cache. Patterns are static once a rule is loaded;
caching avoids re-compiling on every request. Bounded growth — the
operator's deny rule count is small (single digits per design doc's
incident-window framing); a 1000-entry cap below is paranoia."""

_CACHE_CAP = 1000


def _target_matches_arn(target: str, arn: str) -> bool:
    """True iff the operator-written target pattern matches the
    request's resource ARN.

    Handles three target shapes:

      * AWS ARN glob: ``arn:aws:s3:::prod-*`` matches
        ``arn:aws:s3:::prod-data-bucket``. Service-only forms
        (``arn:aws:iam:*``) get expanded so they match any resource
        under that service.
      * Secret shorthand: ``secret:my-app-creds`` matches
        ``arn:aws:secretsmanager:<region>:<account>:secret:my-app-creds-<suffix>``.
        The trailing AWS-randomised suffix is stripped before compare.
    """
    if target.startswith("secret:"):
        return _secret_shorthand_matches(target[len("secret:") :], arn)
    # Service-only short form: expand `arn:aws:iam:*` -> `arn:aws:iam:*:*:*`
    # so the glob matches resources of any sub-shape.
    target = _normalise_arn_glob(target)
    return _glob_match(target, arn)


def _normalise_arn_glob(target: str) -> str:
    """Expand a short-form ARN glob so a single trailing ``*`` covers
    all remaining segments. The schema accepts service-only short
    forms; without this they'd literal-match only the colons-zero
    cardinality (the bare 4-segment ARN), missing the 5+segment
    resource ARNs operators expect.
    """
    # ARN structure: arn:partition:service:region:account:resource[/...]
    parts = target.split(":", 5)
    if len(parts) < 6:
        # Missing components: pad with `*` so a 4-segment short form
        # like `arn:aws:iam:*` becomes `arn:aws:iam:*:*:*`.
        parts = parts + ["*"] * (6 - len(parts))
        return ":".join(parts)
    return target


def _glob_match(pattern: str, value: str) -> bool:
    """AWS-IAM-style glob match (``*`` and ``?`` only)."""
    rx = _compile_glob(pattern)
    return rx.match(value) is not None


def _compile_glob(pattern: str) -> re.Pattern[str]:
    """Translate an AWS-IAM-style glob into a compiled regex. Cached."""
    cached = _compiled_cache.get(pattern)
    if cached is not None:
        return cached
    out: list[str] = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    rx = re.compile(r"\A" + "".join(out) + r"\Z")
    if len(_compiled_cache) >= _CACHE_CAP:
        # Cap exceeded; clear cache. Simple defense vs. pathological
        # input (an attacker who controls the YAML can already do
        # anything — the cap exists for hand-edit typos that produce
        # thousands of unique patterns).
        _compiled_cache.clear()
    _compiled_cache[pattern] = rx
    return rx


def _secret_shorthand_matches(secret_name_pattern: str, arn: str) -> bool:
    """Match a ``secret:NAME`` shorthand against an incoming
    Secrets-Manager ARN. The shorthand's NAME is itself a glob.

    Secrets Manager ARNs:
      ``arn:aws:secretsmanager:<region>:<account>:secret:<NAME>-<RANDOM>``

    AWS appends a randomised 6-char suffix to every secret name; we
    strip it before comparing so an operator writing
    ``secret:my-app-creds`` matches the live ARN regardless of the
    suffix.
    """
    if ":secret:" not in arn:
        return False
    # Tail starts after the last `:secret:` marker.
    secret_segment = arn.split(":secret:", 1)[1]
    # Strip the AWS-appended `-<RANDOM>` suffix if present. The suffix
    # is 6 chars of Crockford-ish base32; the test is "trailing dash +
    # 6 chars" — if absent (operator-imported secret), compare as-is.
    name_for_compare = secret_segment
    if (
        len(secret_segment) > 7
        and secret_segment[-7] == "-"
        and all(c.isalnum() for c in secret_segment[-6:])
    ):
        name_for_compare = secret_segment[:-7]
    return _glob_match(secret_name_pattern, name_for_compare)
