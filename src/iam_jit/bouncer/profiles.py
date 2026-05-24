"""Environment profiles (AWS Slice 7) — named, switchable rule layers
that add environment-aware keyword denies on top of existing per-task
scopes + global rules.

Per project_environment_profiles_feature memory. Symmetric with the
kbouncer Go-side K-Slice 7 (same YAML shape, same composition order).

A profile is a hard floor: when active, profile denies fire BEFORE
task/global rules and CANNOT be overridden by a permissive task
scope or global allow. This is the property SecOps teams want when
approving the install — "even with admin, this can't touch prod."

Composition order (load-bearing):
  1. Profile `deny_keywords` match (and not in `exceptions`) → DENY
  2. Profile `only_account_ids` mismatch → DENY
  3. Profile `only_regions` mismatch → DENY (§A39 #371)
  4. Profile `deny_verbs` match → DENY
  5. Active task scope denies → DENY
  6. Active task scope allows → ALLOW
  7. Global rules → standard match flow

Profiles do NOT replace per-task scopes; they layer above them.

Honest limitations (must be documented):
- Bypass-able by renaming a resource. Defense-in-depth, not primary
  security boundary.
- False positives possible. Default `word_boundary` matching reduces
  but doesn't eliminate them; per-profile `exceptions` list closes
  remaining false positives.
- The `only_account_ids` + `only_regions` fields are the STRUCTURED
  boundaries; keywords are the human-friendly 80%-coverage layer on
  top.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import functools
import os
import pathlib
import re
from typing import Any, Literal

import yaml

# Path resolution: per `IAM_JIT_BOUNCER_PROFILES_FILE` env var, then
# `~/.iam-jit/bouncer/profiles.yaml`. Tests inject the path.
PROFILES_PATH_ENV = "IAM_JIT_BOUNCER_PROFILES_FILE"

# Env var that names the active profile. Falls back to the CLI flag
# value (the CLI plumbs --profile through to this module's
# `load_active_profile`).
ACTIVE_PROFILE_ENV = "IAM_JIT_BOUNCER_PROFILE"


KeywordMatchMode = Literal["word_boundary", "substring"]


@dataclasses.dataclass(frozen=True)
class ProfileAllowRule:
    """One ALLOW rule embedded in a profile. Mirrors ProxyRule's shape
    intentionally so loading + applying is a no-op translation. Kept
    as a separate dataclass so profiles.py doesn't import rules.py
    (would create a cycle: rules → store → profiles)."""

    pattern: str
    arn_scope: str | None = None
    region_scope: str | None = None
    note: str = ""


@dataclasses.dataclass(frozen=True)
class Profile:
    """One named profile: a layered rule set keyed on environment."""

    name: str
    description: str = ""
    deny_keywords: tuple[str, ...] = ()
    keyword_targets: tuple[str, ...] = ("arn", "resource_name")
    keyword_match: KeywordMatchMode = "word_boundary"
    only_account_ids: tuple[str, ...] = ()
    # ----------------------------------------------------------------
    # §A39 #371 — top-level region scope, symmetric with only_account_ids.
    # Multi-region operators need a profile-level region floor without
    # hand-crafting per-rule region_scope on every allow_rule. When
    # non-empty, request region MUST be in the set or evaluation
    # short-circuits with DENY reason "profile_only_regions". Empty
    # tuple (default) means "no region restriction" — matches the
    # only_account_ids convention. Per [[multi-account-region-cluster-use-case]]
    # this closes the cross-region launch-blocker.
    only_regions: tuple[str, ...] = ()
    deny_verbs: tuple[str, ...] = ()
    exceptions: tuple[str, ...] = ()
    # Profile-scoped ALLOW rules. Only consulted when this profile is
    # active. Merged into the rule engine ALONGSIDE global rules; do
    # NOT short-circuit profile DENY layers above. Composition order
    # is documented in evaluate_profile / proxy.evaluate_request.
    allow_rules: tuple[ProfileAllowRule, ...] = ()
    # ----------------------------------------------------------------
    # Readonly-admin-minus framing (per safe_default_is_readonly_admin_minus
    # memo, 2026-05-17). The hardened `safe-default` profile uses these
    # three fields instead of enumerating destructive verbs:
    #
    #   - allow_baseline: a NAMED allow-set resolved at evaluation time.
    #     For v1.0 the supported baselines are:
    #       * "aws_managed_readonly_access" — every action policy_sentry
    #         classifies as Read or List access level (matches the AWS
    #         managed ReadOnlyAccess policy by construction; inherits
    #         new-service coverage as policy_sentry updates)
    #       * "*" — sentinel meaning "allow all" (used by `full-user`-
    #         style profiles that don't want to gate the baseline at all
    #         but still want to layer deny_actions on top; not used by
    #         any built-in today, kept for symmetry)
    #     When the profile's `allow_baseline` is set, the FIRST profile
    #     check is "is this action IN the baseline." If not, DENY with
    #     reason "action svc:Action not in allow_baseline X." This is
    #     the readonly-admin-minus architectural shape.
    #
    #   - deny_actions: exact-match `service:action` strings that get
    #     DENIED even if they're in the allow_baseline. The "subtract"
    #     half of "allow X minus Y." Used for sensitive-Read carve-outs
    #     like secretsmanager:GetSecretValue, ssm:GetParameter*, etc.
    #
    #   - deny_actions_with_condition: list of `{action, condition}`
    #     entries. Condition shapes supported in v1.0:
    #       * {"resource_pattern": "arn:aws:s3:::sensitive-*"} —
    #         glob-match the request's ARN
    #       * {"tag/<key>": "<value>"} — best-effort; AWS API does not
    #         always surface tags so this fails-open (documented).
    allow_baseline: str | None = None
    deny_actions: tuple[str, ...] = ()
    deny_actions_with_condition: tuple[dict[str, Any], ...] = ()
    # ----------------------------------------------------------------
    # Provenance: where this profile came from. Set to "local" for
    # user-edited profiles, set to a source URL for profiles
    # installed via `profile install --from URL`. Profiles with a
    # non-local source are READ-ONLY at the CLI surface — engineers
    # can't edit org-distributed profiles to bypass them.
    source: str = "local"

    def matches_exception(self, candidate: str) -> bool:
        """Substring match against the exceptions list. An exception
        beats a keyword match — used to permit known false-positive
        cases like `eng-productivity-tooling` triggering `prod`."""
        if not candidate or not self.exceptions:
            return False
        lower = candidate.lower()
        return any(exc.lower() in lower for exc in self.exceptions)


@dataclasses.dataclass(frozen=True)
class ProfileVerdict:
    """Result of evaluating a request against the active profile.
    `denied=False` means "no profile-level objection; fall through
    to task/global rules." `denied=True` means short-circuit DENY."""

    denied: bool
    reason: str = ""
    source: str = ""  # always "profile" when denied; empty otherwise


# Built-in default profiles. Shipped on `init` if profiles.yaml is
# absent. Per `feedback_bounce_default_profile_pattern` (2026-05-17):
# the cross-product (ibounce + kbounce + future) default reduces to
# TWO general-purpose profiles — `full-user` (passthrough, default
# active) and `safe-default` (readonly-admin-minus baseline + sensitive
# carve-outs). More opinionated profiles (`dev-only`, `staging-work`,
# `incident-response`) moved to `tools/community-profiles/` and are
# installable via `ibounce profile install --from URL`.
#
# safe-default replaces the v1.0-alpha `readonly` deny-verbs shape
# per `safe_default_is_readonly_admin_minus` (2026-05-17). The Opus
# AWS-side audit (ibounce-safe-default-audit-2026-05-17) found CRIT
# gaps in the verb-enumeration model: sts:AssumeRole / lambda:Invoke /
# ssm:SendCommand / iam:PassRole / iam:Attach*Policy etc all passed.
# The new model uses policy_sentry's Read+List access-level
# classification as the baseline (matches AWS managed ReadOnlyAccess,
# automatically inherits coverage of every AWS service current as of
# the policy_sentry release we depend on) and subtracts a small list
# of sensitive Read actions + resource-pattern carve-outs.
DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "full-user": {
        "description": (
            "No profile active; calls forwarded as-is + audit-logged. "
            "Default; opt into 'safe-default' for the readonly-admin-minus floor."
        ),
    },
    "safe-default": {
        "description": (
            "AWS readonly admin baseline minus sensitive reads. "
            "BASELINE: allow everything classified as Read+List access level by "
            "policy_sentry (matches AWS managed policy ReadOnlyAccess; covers "
            "every AWS service current as of the policy_sentry release we "
            "depend on; automatically inherits new-service coverage as "
            "policy_sentry updates). "
            "SUBTRACT: a small list of sensitive Read actions "
            "(kms:Decrypt, secretsmanager:GetSecretValue, etc) + "
            "resource-pattern carve-outs. "
            "WHAT IT COVERS: state-changing operations (Write + "
            "Permissions-management + Tagging access levels are NOT in the "
            "baseline, so they're denied by construction; CRIT primitives "
            "sts:AssumeRole, lambda:InvokeFunction, ssm:SendCommand, "
            "iam:PassRole, iam:Attach*Policy etc are all Write-classified "
            "and thus already denied). "
            "WHAT IT DOES NOT COVER: this is NOT a confidentiality boundary. "
            "The baseline allows reads of S3 objects, RDS data, CloudWatch "
            "logs, IAM user metadata, etc. Pair with column-masking / "
            "sensitive-bucket policies for confidentiality."
        ),
        "allow_baseline": "aws_managed_readonly_access",
        "deny_actions": [
            # All of these are sensitive Reads that need explicit subtract.
            # Some (kms:Decrypt, secretsmanager:GetSecretValue) happen to
            # be policy_sentry-classified as Write in current data and are
            # therefore ALREADY excluded by the allow_baseline; keeping
            # them in deny_actions is defensive belt-and-suspenders so a
            # future policy_sentry reclassification can't silently make
            # them flow through.
            "kms:Decrypt",
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter",          # may return SecureString
            "ssm:GetParameters",          # ditto
            "ssm:GetParametersByPath",    # ditto
            "ec2:GetPasswordData",
            "ec2:GetConsoleScreenshot",
            "cognito-idp:AdminGetUser",
            "cognito-idp:AdminListGroupsForUser",
        ],
        "deny_actions_with_condition": [
            {
                "action": "s3:GetObject",
                "condition": {"tag/sensitive": "true"},
            },
            {
                "action": "dynamodb:Scan",
                "condition": {
                    "resource_pattern": "arn:aws:dynamodb:*:*:table/secrets-*",
                },
            },
            {
                "action": "dynamodb:Query",
                "condition": {
                    "resource_pattern": "arn:aws:dynamodb:*:*:table/secrets-*",
                },
            },
        ],
    },
}


# Deprecated profile-name aliases. Map old name → new name. Kept
# working for v1.0; remove in v1.1. Per the rename plan, `none` →
# `full-user` (rename only); `prod-readonly` (v1.0-alpha) and
# `readonly` (v1.0-alpha-2, post-rename batch 47b616a) both map to
# `safe-default` (v1.0 launch name + new readonly-admin-minus
# architecture per safe_default_is_readonly_admin_minus memo).
# Both old names resolve via `resolve_active_profile`; resolution
# emits a one-line stderr deprecation banner.
DEPRECATED_PROFILE_ALIASES: dict[str, str] = {
    "none": "full-user",
    "prod-readonly": "safe-default",
    "readonly": "safe-default",
}


def _default_profiles_path() -> pathlib.Path:
    return pathlib.Path.home() / ".iam-jit" / "bouncer" / "profiles.yaml"


def resolve_profiles_path(explicit: str | None = None) -> pathlib.Path:
    """Resolve the profiles.yaml path: explicit arg → env var → default."""
    if explicit:
        return pathlib.Path(explicit)
    env = os.environ.get(PROFILES_PATH_ENV)
    if env:
        return pathlib.Path(env)
    return _default_profiles_path()


def load_profiles(path: str | pathlib.Path | None = None) -> dict[str, Profile]:
    """Read profiles.yaml + return name→Profile mapping. Returns the
    DEFAULT_PROFILES set if the file is absent (so first-run works).
    Raises ValueError on malformed YAML — never silently degrades.

    Per GH #6: when the user file IS present, DEFAULT_PROFILES are
    merged in so callers (`/healthz`, `safe-default` lookups, etc.)
    never crash with KeyError just because the user authored a
    profiles.yaml that omits a default. User-defined entries win on
    name collision — DEFAULT_PROFILES are the floor, not the ceiling.
    Honest framing per [[ibounce-honest-positioning]]: the merge is
    additive only; a malformed user file still raises ValueError
    rather than silently falling back to defaults.
    """
    resolved = resolve_profiles_path(str(path) if path else None)
    if not resolved.exists():
        return _build_default_profile_map()

    try:
        data = yaml.safe_load(resolved.read_text())
    except yaml.YAMLError as e:
        raise ValueError(f"profiles file at {resolved} is not valid YAML: {e}") from e
    if data is None:
        # Empty YAML file → treat as "user defined nothing"; fall back
        # to pure DEFAULT_PROFILES (post-GH-#6 merge semantics).
        return _build_default_profile_map()
    if not isinstance(data, dict):
        raise ValueError(f"profiles file at {resolved} must be a YAML object")
    raw = data.get("profiles", {})
    if not isinstance(raw, dict):
        raise ValueError(f"profiles file at {resolved} must have a 'profiles' object")

    user_profiles: dict[str, Profile] = {}
    for name, body in raw.items():
        if not isinstance(body, dict):
            raise ValueError(f"profile {name!r} must be a YAML object")
        user_profiles[name] = _profile_from_dict(name, body)

    # Per GH #6: start with the full DEFAULT_PROFILES set so callers
    # depending on `safe-default` / `full-user` / etc. always find
    # them. User entries override on name collision.
    out: dict[str, Profile] = _build_default_profile_map()
    out.update(user_profiles)

    # Always ensure the default-active profile exists so callers can
    # fall back safely. `full-user` is the v1.0 canonical name (was
    # `none`); the alias is added below for v1.0 backward-compat and
    # removed in v1.1 per DEPRECATED_PROFILE_ALIASES.
    out.setdefault("full-user", Profile(
        name="full-user",
        description=(
            "No profile active; calls forwarded as-is + audit-logged."
        ),
    ))
    # Backward-compat: every deprecated alias must resolve to the same
    # Profile instance as its canonical name so existing users of
    # `--profile none` / `--profile prod-readonly` keep working in
    # v1.0. The deprecation banner is printed in
    # `resolve_active_profile`, not here (avoids double-printing on
    # every load).
    for old_name, new_name in DEPRECATED_PROFILE_ALIASES.items():
        if old_name not in out and new_name in out:
            out[old_name] = out[new_name]
    return out


def write_default_profiles(path: str | pathlib.Path | None = None) -> pathlib.Path:
    """If profiles.yaml is absent, write the default set to disk +
    return the path. Idempotent: returns the existing path without
    modification if the file already exists."""
    resolved = resolve_profiles_path(str(path) if path else None)
    if resolved.exists():
        return resolved
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(yaml.safe_dump({"profiles": DEFAULT_PROFILES}, sort_keys=False))
    return resolved


def _build_default_profile_map() -> dict[str, Profile]:
    out = {name: _profile_from_dict(name, body) for name, body in DEFAULT_PROFILES.items()}
    # Backward-compat aliases (v1.0; removed in v1.1). Map old name →
    # same Profile object as the canonical name. The deprecation
    # banner is printed in resolve_active_profile, not here.
    for old_name, new_name in DEPRECATED_PROFILE_ALIASES.items():
        if old_name not in out and new_name in out:
            out[old_name] = out[new_name]
    return out


# Top-level field names emitted by the LLM-driven profile generator
# (`_render_profile_yaml` in iam_jit.llm.profile_generator) that the
# canonical parser doesn't natively know about. `bouncer:` is a
# routing field (a single bundle file targets one bouncer); the rules
# live under `allows:` and `denies:` as objects with `target` +
# `actions` + optional `reason` / `scope`. The schema-bridge step in
# _translate_generator_shape projects these onto deny_actions +
# allow_rules so the runtime enforcement layer can consume them.
_GENERATOR_RULE_KEYS: tuple[str, ...] = ("denies", "allows")


def _translate_generator_shape(name: str, body: dict[str, Any]) -> dict[str, Any]:
    """Bridge the LLM-generated profile shape into the parser's
    canonical shape. Pure function — returns a NEW dict, never mutates
    the caller's body.

    For each rule under `denies:` / `allows:`:
      - If `actions:` is present, every `service:Action` entry is
        added to the parser's `deny_actions` (for denies) or as an
        ALLOW rule with `pattern: <action>` and `arn_scope: <target>`
        (for allows). Action entries without a colon are skipped
        (those are dbounce / kbounce shapes; ibounce's bouncer only
        speaks `service:Action`).
      - If a rule has NO actions but has a `target:` only, it is left
        for downstream bouncers (dbounce SQL patterns / kbouncer
        verbs); ibounce's runtime can't enforce a target-only rule
        and skipping it is safer than fabricating a deny.

    The translation is additive: pre-existing `deny_actions` /
    `allow_rules` in `body` are preserved; the generator's rules are
    appended after them with de-duplication on identical entries.

    `bouncer:`, `profile_name:`, `schema_version:`, `provenance:`,
    `flagged_for_review:`, `skipped:` are recognized + stripped (they
    are bundle metadata, not enforcement rules).
    """
    if not isinstance(body, dict):
        return body
    # Fast path: no generator-shape keys means nothing to translate.
    if not any(k in body for k in _GENERATOR_RULE_KEYS):
        # Still strip generator-only metadata that the canonical
        # parser would otherwise pass through to str(body.get(...))
        # callers (description etc.). Conservative: only drop the
        # known-safe keys, leave everything else.
        return body

    out: dict[str, Any] = {
        k: v
        for k, v in body.items()
        if k not in {
            "denies", "allows",
            "bouncer", "profile_name", "schema_version",
            "provenance", "flagged_for_review", "skipped",
        }
    }
    # Pre-load any pre-existing canonical fields so we merge cleanly.
    existing_deny_actions: list[str] = list(out.get("deny_actions") or [])
    existing_allow_rules: list[Any] = list(out.get("allow_rules") or [])

    new_deny_actions: list[str] = []
    new_allow_rules: list[dict[str, Any]] = []

    for rule in (body.get("denies") or []):
        if not isinstance(rule, dict):
            continue
        target = rule.get("target")
        target_str = target if isinstance(target, str) else None
        actions = rule.get("actions") or []
        reason = rule.get("reason") or ""
        for a in actions:
            if not isinstance(a, str) or ":" not in a:
                continue
            if a not in new_deny_actions and a not in existing_deny_actions:
                new_deny_actions.append(a)
        # Rules with no actions are bouncer-other shapes (dbounce /
        # kbounce / gbounce); ibounce skips them silently.

    for rule in (body.get("allows") or []):
        if not isinstance(rule, dict):
            continue
        target = rule.get("target")
        target_str = target if isinstance(target, str) else None
        actions = rule.get("actions") or []
        reason = rule.get("reason") or ""
        for a in actions:
            if not isinstance(a, str) or ":" not in a:
                continue
            entry: dict[str, Any] = {"pattern": a}
            if target_str and target_str != "*":
                entry["arn_scope"] = target_str
            if reason:
                entry["note"] = str(reason)
            # De-dupe on (pattern, arn_scope) tuple.
            key = (entry["pattern"], entry.get("arn_scope"))
            seen_keys = {
                (
                    r.get("pattern") if isinstance(r, dict) else None,
                    r.get("arn_scope") if isinstance(r, dict) else None,
                )
                for r in (existing_allow_rules + new_allow_rules)
            }
            if key not in seen_keys:
                new_allow_rules.append(entry)

    if new_deny_actions:
        out["deny_actions"] = existing_deny_actions + new_deny_actions
    elif existing_deny_actions:
        out["deny_actions"] = existing_deny_actions
    if new_allow_rules:
        out["allow_rules"] = existing_allow_rules + new_allow_rules
    elif existing_allow_rules:
        out["allow_rules"] = existing_allow_rules
    return out


def _profile_from_dict(name: str, body: dict[str, Any]) -> Profile:
    """Construct a Profile from a YAML object. Tolerant of missing
    optional fields; strict on field types when present.

    Per §A26 (#349) the parser ALSO accepts the
    `iam-jit profile generate-from-audit` emitter shape — a richer
    cross-bouncer rule list under `denies: [{target, actions, reason}]`
    plus `allows: [{target, actions, reason}]`. When those keys are
    present they are translated into the canonical `deny_actions` /
    `allow_rules` shape BEFORE the existing parser runs. Both shapes
    can coexist in one body; the generator-shape rules are merged in
    additively. The translation is intentionally lossy on metadata
    that the runtime engine doesn't consult (reason / scope) but the
    enforcement-relevant fields (action set, target glob) are
    preserved one-to-one.

    Operator-authored profiles that use the old shape continue to
    parse unchanged (per [[creates-never-mutates]] this is an
    additive parser change, not a schema migration).
    """
    body = _translate_generator_shape(name, body)

    def _str_tuple(field: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
        v = body.get(field)
        if v is None:
            return default
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ValueError(f"profile {name!r}: {field} must be a list of strings")
        return tuple(v)

    keyword_match = body.get("keyword_match", "word_boundary")
    if keyword_match not in ("word_boundary", "substring"):
        raise ValueError(
            f"profile {name!r}: keyword_match must be 'word_boundary' or 'substring'"
        )
    allow_rules = _parse_allow_rules(name, body.get("allow_rules"))
    allow_baseline = body.get("allow_baseline")
    if allow_baseline is not None:
        if not isinstance(allow_baseline, str) or not allow_baseline:
            raise ValueError(
                f"profile {name!r}: allow_baseline must be a non-empty string or null"
            )
        if allow_baseline not in _SUPPORTED_ALLOW_BASELINES:
            raise ValueError(
                f"profile {name!r}: allow_baseline {allow_baseline!r} is not supported; "
                f"known: {sorted(_SUPPORTED_ALLOW_BASELINES)}"
            )
    deny_actions_with_condition = _parse_deny_actions_with_condition(
        name, body.get("deny_actions_with_condition"),
    )
    return Profile(
        name=name,
        description=str(body.get("description", "")),
        deny_keywords=_str_tuple("deny_keywords"),
        keyword_targets=_str_tuple("keyword_targets", default=("arn", "resource_name")),
        keyword_match=keyword_match,  # type: ignore[arg-type]
        only_account_ids=_str_tuple("only_account_ids"),
        only_regions=_str_tuple("only_regions"),
        deny_verbs=_str_tuple("deny_verbs"),
        exceptions=_str_tuple("exceptions"),
        allow_rules=allow_rules,
        allow_baseline=allow_baseline,
        deny_actions=_str_tuple("deny_actions"),
        deny_actions_with_condition=deny_actions_with_condition,
        source=str(body.get("source", "local")),
    )


_SUPPORTED_ALLOW_BASELINES: frozenset[str] = frozenset({
    "aws_managed_readonly_access",
    "*",
})


def _parse_deny_actions_with_condition(
    profile_name: str, raw: Any,
) -> tuple[dict[str, Any], ...]:
    """Parse the optional `deny_actions_with_condition` list from YAML.
    Each entry: `{action: "service:Action", condition: {<key>: <val>}}`.
    Validates shape strictly (the field is security-relevant — a typo
    that silently no-ops a conditional deny is worse than a crash)."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError(
            f"profile {profile_name!r}: deny_actions_with_condition must be a list"
        )
    out: list[dict[str, Any]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"profile {profile_name!r}: "
                f"deny_actions_with_condition[{i}] must be an object"
            )
        action = entry.get("action")
        if not isinstance(action, str) or ":" not in action:
            raise ValueError(
                f"profile {profile_name!r}: "
                f"deny_actions_with_condition[{i}].action must be a "
                f"'service:Action' string"
            )
        # condition is OPTIONAL — an entry with no condition reduces to
        # an unconditional deny of the action (same as putting it in
        # deny_actions). We allow it for YAML-author convenience but
        # the resolver below has to handle it.
        condition = entry.get("condition", {})
        if not isinstance(condition, dict):
            raise ValueError(
                f"profile {profile_name!r}: "
                f"deny_actions_with_condition[{i}].condition must be an "
                f"object (or omitted for unconditional deny)"
            )
        out.append({"action": action, "condition": dict(condition)})
    return tuple(out)


def _parse_allow_rules(
    profile_name: str, raw: Any,
) -> tuple[ProfileAllowRule, ...]:
    """Parse the optional `allow_rules` list from YAML. Each entry is
    a small dict mirroring ProxyRule shape: pattern (required), plus
    optional arn_scope, region_scope, note. Pattern must be `service:action`
    glob shape (e.g. `s3:GetObject`, `ec2:Describe*`) — same shape the
    rule engine validates."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError(
            f"profile {profile_name!r}: allow_rules must be a list of objects"
        )
    out: list[ProfileAllowRule] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"profile {profile_name!r}: allow_rules[{i}] must be a dict"
            )
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(
                f"profile {profile_name!r}: allow_rules[{i}].pattern is required + must be a string"
            )
        arn_scope = entry.get("arn_scope")
        region_scope = entry.get("region_scope")
        note = entry.get("note", "")
        if arn_scope is not None and not isinstance(arn_scope, str):
            raise ValueError(
                f"profile {profile_name!r}: allow_rules[{i}].arn_scope must be a string or null"
            )
        if region_scope is not None and not isinstance(region_scope, str):
            raise ValueError(
                f"profile {profile_name!r}: allow_rules[{i}].region_scope must be a string or null"
            )
        if not isinstance(note, str):
            raise ValueError(
                f"profile {profile_name!r}: allow_rules[{i}].note must be a string"
            )
        out.append(ProfileAllowRule(
            pattern=pattern,
            arn_scope=arn_scope,
            region_scope=region_scope,
            note=note,
        ))
    return tuple(out)


def profile_to_yaml_dict(profile: Profile) -> dict[str, Any]:
    """Inverse of _profile_from_dict — serialize a Profile back to the
    dict shape stored under `profiles.<name>` in profiles.yaml. Used
    by `bouncer recommend --save-as-profile` (#6b) + the interactive
    deny-prompt (#5) when persisting profile mutations."""
    body: dict[str, Any] = {}
    if profile.description:
        body["description"] = profile.description
    if profile.deny_keywords:
        body["deny_keywords"] = list(profile.deny_keywords)
    if profile.keyword_targets and profile.keyword_targets != ("arn", "resource_name"):
        body["keyword_targets"] = list(profile.keyword_targets)
    if profile.keyword_match != "word_boundary":
        body["keyword_match"] = profile.keyword_match
    if profile.only_account_ids:
        body["only_account_ids"] = list(profile.only_account_ids)
    if profile.only_regions:
        body["only_regions"] = list(profile.only_regions)
    if profile.deny_verbs:
        body["deny_verbs"] = list(profile.deny_verbs)
    if profile.exceptions:
        body["exceptions"] = list(profile.exceptions)
    if profile.allow_rules:
        body["allow_rules"] = [
            {k: v for k, v in {
                "pattern": r.pattern,
                "arn_scope": r.arn_scope,
                "region_scope": r.region_scope,
                "note": r.note or None,
            }.items() if v is not None}
            for r in profile.allow_rules
        ]
    if profile.allow_baseline:
        body["allow_baseline"] = profile.allow_baseline
    if profile.deny_actions:
        body["deny_actions"] = list(profile.deny_actions)
    if profile.deny_actions_with_condition:
        body["deny_actions_with_condition"] = [
            dict(entry) for entry in profile.deny_actions_with_condition
        ]
    if profile.source and profile.source != "local":
        body["source"] = profile.source
    return body


def upsert_profile(
    profile: Profile,
    path: str | pathlib.Path | None = None,
) -> pathlib.Path:
    """Persist a single profile to profiles.yaml — insert if absent,
    replace if present. Returns the resolved file path.

    Refuses to overwrite a profile whose `source` field is anything
    other than 'local' — org-distributed profiles are read-only at
    this CLI surface (see [[enterprise-profile-distribution]] memo).
    If the user wants to override an org profile they must define a
    new personal profile name.

    Used by `bouncer recommend --save-as-profile NAME`."""
    resolved = resolve_profiles_path(str(path) if path else None)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    if resolved.exists():
        try:
            existing = yaml.safe_load(resolved.read_text()) or {}
        except yaml.YAMLError as e:
            raise ValueError(
                f"profiles file at {resolved} is not valid YAML: {e}"
            ) from e
        if not isinstance(existing, dict):
            existing = {}
        profiles_obj = existing.get("profiles")
        if not isinstance(profiles_obj, dict):
            profiles_obj = {}
            existing["profiles"] = profiles_obj
    else:
        existing = {"profiles": {}}
        profiles_obj = existing["profiles"]

    # READ-ONLY check: refuse to overwrite an org-distributed profile.
    prior = profiles_obj.get(profile.name)
    if isinstance(prior, dict):
        prior_source = prior.get("source", "local")
        if prior_source != "local":
            raise ValueError(
                f"profile {profile.name!r} is sourced from {prior_source!r} "
                f"and is read-only. Pick a different name for your local "
                f"override."
            )

    profiles_obj[profile.name] = profile_to_yaml_dict(profile)
    resolved.write_text(yaml.safe_dump(existing, sort_keys=False))
    return resolved


def resolve_active_profile(
    *,
    cli_flag: str | None = None,
    explicit: Profile | None = None,
    profiles: dict[str, Profile] | None = None,
) -> Profile:
    """Resolve which profile is active for this request, in priority:
    explicit override → CLI flag → env var → 'full-user'. Returns the
    `full-user` (passthrough) profile if no other source specified it.

    Deprecated profile names (`none`, `prod-readonly`) still resolve
    in v1.0 but emit a one-line stderr deprecation banner so users
    know to switch before v1.1 removes the alias.
    """
    import sys as _sys

    if explicit is not None:
        return explicit
    if profiles is None:
        profiles = load_profiles()
    name = cli_flag or os.environ.get(ACTIVE_PROFILE_ENV) or "full-user"
    if name in DEPRECATED_PROFILE_ALIASES:
        new_name = DEPRECATED_PROFILE_ALIASES[name]
        print(
            f"WARN: profile name {name!r} is deprecated; use "
            f"{new_name!r}. Both work in v1.0; {name!r} is removed in v1.1.",
            file=_sys.stderr,
        )
        name = new_name
    if name not in profiles:
        # Surface the misconfiguration loudly rather than silently
        # falling back to 'full-user' — a typo in --profile that
        # silently disables enforcement is worse than a crash.
        raise ValueError(
            f"profile {name!r} not found; available: {sorted(profiles.keys())}"
        )
    return profiles[name]


# ---------------------------------------------------------------------------
# Evaluation — the hot path called from proxy.evaluate_request()
# ---------------------------------------------------------------------------


def _build_keyword_regex(keyword: str, mode: KeywordMatchMode) -> re.Pattern[str]:
    """Compile a case-insensitive regex for a single keyword. Cached
    in `_KEYWORD_REGEX_CACHE` to avoid recompiling per-request."""
    if mode == "word_boundary":
        # \b doesn't match between letter and dash, so we use a custom
        # boundary that treats dashes, dots, underscores, and slashes
        # as separators in addition to word boundaries. This matches
        # `prod` in `prod-cluster`, `cluster-prod`, `prod.staging`,
        # `prod_app` but not in `productivity` or `reproduce`.
        pat = rf"(?:^|[^A-Za-z0-9]){re.escape(keyword)}(?:$|[^A-Za-z0-9])"
    else:
        pat = re.escape(keyword)
    return re.compile(pat, re.IGNORECASE)


_KEYWORD_REGEX_CACHE: dict[tuple[str, str], re.Pattern[str]] = {}


def _cached_regex(keyword: str, mode: KeywordMatchMode) -> re.Pattern[str]:
    key = (keyword, mode)
    if key not in _KEYWORD_REGEX_CACHE:
        _KEYWORD_REGEX_CACHE[key] = _build_keyword_regex(keyword, mode)
    return _KEYWORD_REGEX_CACHE[key]


def _verb_pattern_matches(pattern: str, service: str, action: str) -> bool:
    """Match a deny_verb pattern like `*:Delete*` against a `service:action`
    pair. Pattern is glob-style (`*` matches any chars, `?` matches one)."""
    if ":" not in pattern:
        # Pattern is just an action glob (kbouncer-shape); match against action.
        return _glob_match(pattern, action)
    svc_pat, act_pat = pattern.split(":", 1)
    return _glob_match(svc_pat, service) and _glob_match(act_pat, action)


def _glob_match(pattern: str, candidate: str) -> bool:
    """Case-sensitive simple glob match. `*` matches any chars, `?`
    matches one. No character classes. Empty pattern matches empty
    string. `*` alone matches anything."""
    if pattern == "*":
        return True
    # Translate glob → regex
    regex = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return bool(re.match(regex, candidate))


# ---------------------------------------------------------------------------
# allow_baseline resolution — uses policy_sentry for the AWS managed
# ReadOnlyAccess shape. Per the readonly-admin-minus framing, the
# baseline is the structural "what reads are even on the table"; the
# profile's deny_actions + deny_actions_with_condition subtract from it.
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=None)
def _service_read_list_actions(service: str) -> frozenset[str]:
    """Return the lowercased `service:action` set classified by
    policy_sentry as Read or List for `service`. Cached per-service so
    the policy_sentry lookup happens once per process.

    Returns an empty set for services policy_sentry doesn't know
    (e.g. brand-new AWS services not yet in the data version we depend
    on). The caller treats "not in baseline" as DENY, so an unknown
    service fails CLOSED — which is the right safety default: an agent
    asking for a service the baseline can't classify gets the same
    treatment as asking for a Write-classified action.
    """
    try:
        from policy_sentry.querying.actions import get_actions_with_access_level
    except ImportError:
        # Defensive: if policy_sentry isn't importable, fail closed by
        # returning the empty set so every action is "not in baseline."
        return frozenset()
    out: set[str] = set()
    for level in ("Read", "List"):
        try:
            for action_full in get_actions_with_access_level(service, level) or []:
                if not isinstance(action_full, str) or ":" not in action_full:
                    continue
                out.add(action_full.lower())
        except Exception:
            # policy_sentry raises KeyError on unknown services + can
            # raise on data-shape changes between versions. Swallow +
            # fall through to next level / return what we have.
            continue
    return frozenset(out)


def _action_in_baseline(baseline_name: str, service: str, action: str) -> bool:
    """Resolve whether `service:action` is in the named allow-baseline.

    Supported baselines:
      - "aws_managed_readonly_access": policy_sentry's Read+List classifications
      - "*": always True (sentinel — disables baseline gating entirely)

    Unknown baseline names raise ValueError (caught at profile-load
    time by _SUPPORTED_ALLOW_BASELINES validation; raising here is the
    last-line defense)."""
    if baseline_name == "*":
        return True
    if baseline_name == "aws_managed_readonly_access":
        if not service or not action:
            return False
        full = f"{service}:{action}".lower()
        return full in _service_read_list_actions(service)
    raise ValueError(f"unknown allow_baseline {baseline_name!r}")


def _matches_conditional_deny(
    entry: dict[str, Any],
    *,
    service: str | None,
    action: str | None,
    arn: str | None,
) -> bool:
    """Resolve whether a `deny_actions_with_condition` entry fires for
    the current request. Returns True → DENY.

    Condition shapes:
      - {"resource_pattern": "arn:aws:s3:::sensitive-*"} — fnmatch
        glob against the request ARN (case-insensitive). If no ARN is
        available on the request, the resource_pattern condition
        FAILS CLOSED (returns False — caller does not deny), because
        we can't evaluate the predicate. This is documented as a
        best-effort condition; high-confidence enforcement requires
        AWS-side resource policies or IAM Condition keys.
      - {"tag/<key>": "<value>"} — AWS API does not always surface
        request tags through the proxy boundary, so we treat tag
        conditions as best-effort and they currently always evaluate
        False. Operators relying on tag-based denial should layer an
        AWS-side IAM policy with `aws:ResourceTag/<key>` Condition.
      - empty / missing condition: unconditional deny when the action
        matches (same shape as deny_actions but expressed in the
        conditional-list YAML for grouping convenience).
    """
    if not isinstance(entry, dict):
        return False
    entry_action = entry.get("action")
    if not entry_action or not service or not action:
        return False
    if entry_action != f"{service}:{action}":
        return False
    cond = entry.get("condition") or {}
    if not cond:
        # Unconditional deny shape; action match alone fires it.
        return True
    if "resource_pattern" in cond:
        pattern = cond["resource_pattern"]
        if not isinstance(pattern, str) or not pattern:
            return False
        if not arn:
            # Can't evaluate — fail open at this condition (caller may
            # still deny via other layers; this entry abstains).
            return False
        return fnmatch.fnmatchcase(arn.lower(), pattern.lower())
    if any(isinstance(k, str) and k.startswith("tag/") for k in cond):
        # Tag-based conditions are best-effort + currently always
        # abstain. Documented above.
        return False
    # Unknown condition shape — abstain rather than crash. Profile
    # validation at load-time is responsible for catching truly
    # malformed conditions.
    return False


def evaluate_profile(
    profile: Profile,
    *,
    arn: str | None = None,
    resource_name: str | None = None,
    account_id: str | None = None,
    account_alias: str | None = None,
    service: str | None = None,
    action: str | None = None,
    region: str | None = None,
) -> ProfileVerdict:
    """Evaluate a request against a single active profile. Returns a
    DENY verdict on the first matching rule; otherwise returns the
    no-objection verdict (denied=False).

    Composition (within a profile):
      1. allow_baseline gate (if set, action NOT in baseline → DENY)
      2. deny_actions exact match → DENY (subtracts from baseline)
      3. deny_actions_with_condition match → DENY (subtracts conditionally)
      4. Account-ID restriction (only_account_ids) → DENY
      5. Region restriction (only_regions) → DENY (§A39 #371)
      6. Keyword denies against `keyword_targets` (with exceptions) → DENY
      7. Verb denies against `deny_verbs` → DENY
      8. No objection → allow downstream rules to decide

    Layers 1-3 are the readonly-admin-minus framing (per
    safe_default_is_readonly_admin_minus memo); layers 4-7 are the
    pre-existing keyword/verb model (+ §A39 region floor). Both are
    supported simultaneously so operator-authored profiles with only
    `deny_keywords` keep working unchanged (no allow_baseline → layer 1
    abstains).
    """
    # Profile 'full-user' (or any empty profile — incl. the legacy
    # 'none' alias) is a no-op. Note we also check the new fields.
    if (
        not profile.deny_keywords
        and not profile.deny_verbs
        and not profile.only_account_ids
        and not profile.only_regions
        and not profile.allow_baseline
        and not profile.deny_actions
        and not profile.deny_actions_with_condition
    ):
        return ProfileVerdict(denied=False)

    full_action = (
        f"{service}:{action}" if (service and action) else None
    )

    # 1. allow_baseline gate — first thing checked when set. The
    # readonly-admin-minus shape: "is the requested action even in the
    # baseline of permitted reads?" An action not in the baseline is
    # denied here BEFORE we look at any subtract list, so a profile
    # author who omits a sensitive action from deny_actions still gets
    # protection via the structural classification (Write-classified
    # actions never reach the subtract step).
    if profile.allow_baseline and service and action:
        if not _action_in_baseline(profile.allow_baseline, service, action):
            return ProfileVerdict(
                denied=True,
                reason=(
                    f"profile {profile.name!r}: action {full_action} not in "
                    f"allow_baseline {profile.allow_baseline!r}"
                ),
                source="profile",
            )

    # 2. deny_actions — exact-match subtract list, fires after baseline.
    if profile.deny_actions and full_action:
        if full_action in profile.deny_actions:
            return ProfileVerdict(
                denied=True,
                reason=(
                    f"profile {profile.name!r}: action {full_action} in "
                    f"deny_actions (subtract list)"
                ),
                source="profile",
            )

    # 3. deny_actions_with_condition — resource-pattern + tag-based.
    if profile.deny_actions_with_condition and service and action:
        for entry in profile.deny_actions_with_condition:
            if _matches_conditional_deny(
                entry, service=service, action=action, arn=arn,
            ):
                return ProfileVerdict(
                    denied=True,
                    reason=(
                        f"profile {profile.name!r}: action {full_action} "
                        f"matched conditional deny {entry!r}"
                    ),
                    source="profile",
                )

    # 4. Account-ID lock
    if profile.only_account_ids:
        if account_id is None or account_id not in profile.only_account_ids:
            return ProfileVerdict(
                denied=True,
                reason=(
                    f"profile {profile.name!r} restricts to accounts "
                    f"{sorted(profile.only_account_ids)}; request account "
                    f"{account_id or 'unknown'} (profile_only_account_ids)"
                ),
                source="profile",
            )

    # 5. Region lock (§A39 #371). Mirrors only_account_ids exactly:
    # when non-empty, the request's region MUST be in the allowed set
    # or the profile short-circuits with DENY. Unknown / unspecified
    # region fails CLOSED so a parser that didn't surface the region
    # can't bypass the multi-region floor. Empty tuple = no
    # restriction (default).
    if profile.only_regions:
        if region is None or region not in profile.only_regions:
            return ProfileVerdict(
                denied=True,
                reason=(
                    f"profile {profile.name!r} restricts to regions "
                    f"{sorted(profile.only_regions)}; request region "
                    f"{region or 'unknown'} (profile_only_regions)"
                ),
                source="profile",
            )

    # 6. Keyword denies
    if profile.deny_keywords:
        target_values: dict[str, str | None] = {
            "arn": arn,
            "resource_name": resource_name,
            "account_alias": account_alias,
            "namespace": None,  # AWS bouncer has no namespaces; kbouncer fills this
        }
        for target_field in profile.keyword_targets:
            candidate = target_values.get(target_field)
            if not candidate:
                continue
            # Exceptions short-circuit BEFORE keyword scan
            if profile.matches_exception(candidate):
                continue
            for keyword in profile.deny_keywords:
                regex = _cached_regex(keyword, profile.keyword_match)
                if regex.search(candidate):
                    return ProfileVerdict(
                        denied=True,
                        reason=(
                            f"profile {profile.name!r}: keyword {keyword!r} "
                            f"matched {target_field}={candidate!r}"
                        ),
                        source="profile",
                    )

    # 7. Verb denies (legacy shape; safe-default no longer uses these
    # but operator-authored profiles + community profiles still can)
    if profile.deny_verbs and service and action:
        for verb_pat in profile.deny_verbs:
            if _verb_pattern_matches(verb_pat, service, action):
                return ProfileVerdict(
                    denied=True,
                    reason=(
                        f"profile {profile.name!r}: verb {service}:{action} "
                        f"matched deny pattern {verb_pat!r}"
                    ),
                    source="profile",
                )

    return ProfileVerdict(denied=False)
