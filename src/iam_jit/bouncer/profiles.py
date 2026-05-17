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
  3. Profile `deny_verbs` match → DENY
  4. Active task scope denies → DENY
  5. Active task scope allows → ALLOW
  6. Global rules → standard match flow

Profiles do NOT replace per-task scopes; they layer above them.

Honest limitations (must be documented):
- Bypass-able by renaming a resource. Defense-in-depth, not primary
  security boundary.
- False positives possible. Default `word_boundary` matching reduces
  but doesn't eliminate them; per-profile `exceptions` list closes
  remaining false positives.
- The `only_account_ids` field is the STRUCTURED boundary; keywords
  are the human-friendly 80%-coverage layer on top.
"""

from __future__ import annotations

import dataclasses
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
    deny_verbs: tuple[str, ...] = ()
    exceptions: tuple[str, ...] = ()
    # Profile-scoped ALLOW rules. Only consulted when this profile is
    # active. Merged into the rule engine ALONGSIDE global rules; do
    # NOT short-circuit profile DENY layers above. Composition order
    # is documented in evaluate_profile / proxy.evaluate_request.
    allow_rules: tuple[ProfileAllowRule, ...] = ()
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
# active) and `readonly` (block write/destructive verbs). More
# opinionated profiles (`dev-only`, `staging-work`,
# `incident-response`) moved to `tools/community-profiles/` and are
# installable via `ibounce profile install --from URL`.
DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "full-user": {
        "description": (
            "No profile active; calls forwarded as-is + audit-logged. "
            "Default; opt into 'readonly' for the cross-product write block."
        ),
    },
    "readonly": {
        "description": (
            "Cross-product read-only floor: block write + destructive verbs "
            "regardless of credentials. The general-purpose 'readonly' default."
        ),
        "deny_verbs": [
            "*:Delete*", "*:Put*", "*:Update*", "*:Create*",
            "*:Terminate*", "*:Stop*", "*:Reboot*",
        ],
    },
}


# Deprecated profile-name aliases. Map old name → new name. Kept
# working for v1.0; remove in v1.1. Per the rename plan, `none` →
# `full-user` (rename only) and `prod-readonly` → `readonly` (rename
# + drop the "prod" connotation). Both old names still resolve via
# `resolve_active_profile`; resolution emits a one-line stderr
# deprecation banner.
DEPRECATED_PROFILE_ALIASES: dict[str, str] = {
    "none": "full-user",
    "prod-readonly": "readonly",
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
    Raises ValueError on malformed YAML — never silently degrades."""
    resolved = resolve_profiles_path(str(path) if path else None)
    if not resolved.exists():
        return _build_default_profile_map()

    try:
        data = yaml.safe_load(resolved.read_text())
    except yaml.YAMLError as e:
        raise ValueError(f"profiles file at {resolved} is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"profiles file at {resolved} must be a YAML object")
    raw = data.get("profiles", {})
    if not isinstance(raw, dict):
        raise ValueError(f"profiles file at {resolved} must have a 'profiles' object")

    out: dict[str, Profile] = {}
    for name, body in raw.items():
        if not isinstance(body, dict):
            raise ValueError(f"profile {name!r} must be a YAML object")
        out[name] = _profile_from_dict(name, body)
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


def _profile_from_dict(name: str, body: dict[str, Any]) -> Profile:
    """Construct a Profile from a YAML object. Tolerant of missing
    optional fields; strict on field types when present."""
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
    return Profile(
        name=name,
        description=str(body.get("description", "")),
        deny_keywords=_str_tuple("deny_keywords"),
        keyword_targets=_str_tuple("keyword_targets", default=("arn", "resource_name")),
        keyword_match=keyword_match,  # type: ignore[arg-type]
        only_account_ids=_str_tuple("only_account_ids"),
        deny_verbs=_str_tuple("deny_verbs"),
        exceptions=_str_tuple("exceptions"),
        allow_rules=allow_rules,
        source=str(body.get("source", "local")),
    )


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


def evaluate_profile(
    profile: Profile,
    *,
    arn: str | None = None,
    resource_name: str | None = None,
    account_id: str | None = None,
    account_alias: str | None = None,
    service: str | None = None,
    action: str | None = None,
) -> ProfileVerdict:
    """Evaluate a request against a single active profile. Returns a
    DENY verdict on the first matching rule; otherwise returns the
    no-objection verdict (denied=False).

    Composition (within a profile):
      1. Account-ID restriction (if `only_account_ids` is set and the
         request's account is not in the list) → DENY
      2. Keyword denies against `keyword_targets` (with exceptions) → DENY
      3. Verb denies against `deny_verbs` → DENY
      4. No objection → allow downstream rules to decide
    """
    # Profile 'full-user' (or any empty profile — incl. the legacy
    # 'none' alias) is a no-op
    if not profile.deny_keywords and not profile.deny_verbs and not profile.only_account_ids:
        return ProfileVerdict(denied=False)

    # 1. Account-ID lock
    if profile.only_account_ids:
        if account_id is None or account_id not in profile.only_account_ids:
            return ProfileVerdict(
                denied=True,
                reason=(
                    f"profile {profile.name!r} restricts to accounts "
                    f"{sorted(profile.only_account_ids)}; request account "
                    f"{account_id or 'unknown'}"
                ),
                source="profile",
            )

    # 2. Keyword denies
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

    # 3. Verb denies
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
