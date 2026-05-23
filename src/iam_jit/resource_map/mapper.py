# #420 / §A59 — declarative resource-mapping logic.
"""Apply an operator-declared resource mapping to a permission set.

The mapping shape (validated by ``ambient_config/schema.py``):

    iam-jit:
      resource_mappings:
        staging_to_prod:
          account_id: { "111122223333": "999988887777" }
          region: { "us-east-1": "us-west-2" }
          name_patterns:
            - { match: "staging-*", replace: "prod-*" }
            - { match: "*-dev", replace: "*-prod" }

Substitution order (matters for predictability):

  1. ``account_id`` — exact-match substitution within ARNs.
  2. ``region`` — exact-match substitution within ARNs + observed_scope.
  3. ``name_patterns`` — glob-style ``*`` substitution on resource
     names (the last ARN component or the bare resource string).

Globs use ASCII ``*`` only; ``?`` is NOT supported (intentional: ``*``
covers the operator-mapping use case; ``?`` invites ambiguity around
literal vs wildcard at substitution time).
"""

from __future__ import annotations

import dataclasses
import re
import typing


@dataclasses.dataclass(frozen=True)
class _NamePattern:
    match: str
    replace: str


@dataclasses.dataclass(frozen=True)
class ResourceMapping:
    """One named mapping (e.g. ``staging_to_prod``) from the operator
    config file."""

    name: str
    account_id: dict[str, str]
    region: dict[str, str]
    name_patterns: tuple[_NamePattern, ...]

    @classmethod
    def from_dict(cls, name: str, raw: dict[str, typing.Any]) -> "ResourceMapping":
        acct_raw = raw.get("account_id") or {}
        region_raw = raw.get("region") or {}
        patterns_raw = raw.get("name_patterns") or []
        if not isinstance(acct_raw, dict):
            raise ValueError(
                f"resource_mappings.{name}.account_id must be a mapping; "
                f"got {type(acct_raw).__name__}"
            )
        if not isinstance(region_raw, dict):
            raise ValueError(
                f"resource_mappings.{name}.region must be a mapping; "
                f"got {type(region_raw).__name__}"
            )
        if not isinstance(patterns_raw, list):
            raise ValueError(
                f"resource_mappings.{name}.name_patterns must be a "
                f"list; got {type(patterns_raw).__name__}"
            )
        # Coerce keys + values to strings (YAML can give us ints for
        # AWS account IDs).
        account_id = {
            str(k): str(v) for k, v in acct_raw.items() if k and v
        }
        region = {
            str(k): str(v) for k, v in region_raw.items() if k and v
        }
        patterns: list[_NamePattern] = []
        for entry in patterns_raw:
            if not isinstance(entry, dict):
                raise ValueError(
                    f"resource_mappings.{name}.name_patterns entries "
                    "must be {match, replace} maps"
                )
            m = entry.get("match")
            r = entry.get("replace")
            if not isinstance(m, str) or not isinstance(r, str):
                raise ValueError(
                    f"resource_mappings.{name}.name_patterns entries "
                    "require string `match` + `replace`"
                )
            patterns.append(_NamePattern(match=m, replace=r))
        return cls(
            name=name,
            account_id=account_id,
            region=region,
            name_patterns=tuple(patterns),
        )


def _glob_to_regex(glob: str) -> tuple[re.Pattern[str], list[int]]:
    """Compile a simple ``*``-glob into a regex. Returns the compiled
    pattern + a list of `*` positions in the original glob (used to
    align ``replace`` template ``*`` placeholders with captured groups).

    Example: ``staging-*`` → ``^staging-(.*)$`` with [9] (one star at
    index 9). ``*-dev-*`` → ``^(.*)-dev-(.*)$``.
    """
    parts: list[str] = []
    star_positions: list[int] = []
    last = 0
    for i, ch in enumerate(glob):
        if ch == "*":
            parts.append(re.escape(glob[last:i]))
            parts.append("(.*)")
            star_positions.append(i)
            last = i + 1
    parts.append(re.escape(glob[last:]))
    return re.compile("^" + "".join(parts) + "$"), star_positions


def _apply_name_pattern(value: str, pat: _NamePattern) -> str | None:
    """Apply one glob pattern. Returns the substituted string, or None
    if the glob didn't match. The ``replace`` template uses ``*``
    placeholders aligned positionally with ``match`` ``*``s — if the
    counts differ, the extra placeholders are left as literal ``*``
    in the output.
    """
    regex, _stars = _glob_to_regex(pat.match)
    m = regex.match(value)
    if m is None:
        return None
    captures = list(m.groups())
    # Walk the replace string and substitute ``*`` with captures in order.
    out_parts: list[str] = []
    cap_i = 0
    for ch in pat.replace:
        if ch == "*":
            if cap_i < len(captures):
                out_parts.append(captures[cap_i])
                cap_i += 1
            else:
                out_parts.append("*")  # literal; no capture available
        else:
            out_parts.append(ch)
    return "".join(out_parts)


_ARN_PARTS_RE = re.compile(
    r"^(arn:(?:aws|aws-cn|aws-us-gov)):([^:]*):([^:]*):([^:]*):(.*)$"
)


def _substitute_in_arn(arn: str, mapping: ResourceMapping) -> str:
    """Apply account/region/name substitutions inside an ARN. Returns
    the original string unchanged when nothing matched.

    The ARN structure is preserved: only the account-id positional
    field is account-substituted; only the region positional field is
    region-substituted; the resource tail is run through the name
    patterns.

    Standard ARN shape: ``arn:partition:service:region:account:resource``
    where ``resource`` may itself contain colons (e.g.
    ``arn:aws:iam::111122223333:role/foo`` or
    ``arn:aws:lambda:us-east-1:111122223333:function:my-func``).

    Pseudo-ARNs (non-AWS-shaped) fall through to ``_substitute_in_name``
    so the operator's name_patterns still apply.
    """
    m = _ARN_PARTS_RE.match(arn)
    if not m:
        return _substitute_in_name(arn, mapping)
    arn_prefix, service, region, account, resource = (
        m.group(1), m.group(2), m.group(3), m.group(4), m.group(5),
    )
    if region in mapping.region:
        region = mapping.region[region]
    if account in mapping.account_id:
        account = mapping.account_id[account]
    resource = _substitute_in_name(resource, mapping)
    return f"{arn_prefix}:{service}:{region}:{account}:{resource}"


def _substitute_in_name(value: str, mapping: ResourceMapping) -> str:
    """Apply the name_patterns to a non-ARN string (or the resource
    tail of an ARN).

    Tries (in order):

      1. Whole-string match — e.g. ``staging-cache-bucket`` against
         ``staging-*``.
      2. Component-wise match — split on ``:`` and ``/`` (the
         delimiters AWS uses inside ARN resource tails like
         ``function:my-func`` or ``role/path/name``) and apply
         the first matching pattern per component.

    First matching pattern wins per component; order in the config
    file controls precedence.
    """
    if not value:
        return value
    # Whole-string attempt first — matches operator intuition for
    # plain hostnames + bucket names.
    for pat in mapping.name_patterns:
        out = _apply_name_pattern(value, pat)
        if out is not None:
            return out
    # Component-wise fallback for resource tails like
    # ``function:staging-lambda-1`` or ``role/staging-foo``.
    if ":" not in value and "/" not in value:
        return value
    # Split on both delimiters while preserving them in the output.
    tokens = re.split(r"([:/])", value)
    changed = False
    for i, tok in enumerate(tokens):
        if tok in (":", "/") or not tok:
            continue
        for pat in mapping.name_patterns:
            out = _apply_name_pattern(tok, pat)
            if out is not None:
                tokens[i] = out
                changed = True
                break
    return "".join(tokens) if changed else value


def apply_resource_mapping(
    resource: str,
    mapping: ResourceMapping,
) -> str:
    """Apply a mapping to one resource string (ARN or non-ARN). Pure
    function — no I/O."""
    return _substitute_in_arn(resource, mapping)


def map_observed_scope(
    observed_scope: dict[str, typing.Any],
    mapping: ResourceMapping,
) -> dict[str, list[str]]:
    """Translate the ``observed_scope`` block through account/region
    substitution. Sorted output for diff-stability."""
    raw_accts = observed_scope.get("account_ids") or []
    raw_regions = observed_scope.get("regions") or []
    accts = sorted({
        mapping.account_id.get(str(a), str(a))
        for a in raw_accts
        if a
    })
    regions = sorted({
        mapping.region.get(str(r), str(r))
        for r in raw_regions
        if r
    })
    return {"account_ids": accts, "regions": regions}


def apply_resource_mapping_to_permissions(
    permissions_doc: dict[str, typing.Any],
    mapping: ResourceMapping,
) -> dict[str, typing.Any]:
    """Apply a mapping to a full extract-permissions document.

    Returns a NEW dict — the input is not mutated.

    The action set is preserved verbatim (mapping a staging audit to
    prod doesn't change WHAT the agent did, only WHERE). Resource ARNs
    + observed_scope are substituted. ``count`` carries through
    unchanged.
    """
    perms_raw = permissions_doc.get("permissions") or []
    new_perms: list[dict[str, typing.Any]] = []
    for p in perms_raw:
        if not isinstance(p, dict):
            continue
        old_resources = p.get("resources") or []
        new_resources_set: dict[str, None] = {}
        for r in old_resources:
            if not isinstance(r, str):
                continue
            new_r = apply_resource_mapping(r, mapping)
            new_resources_set[new_r] = None
        new_perms.append({
            "action": p.get("action"),
            "resources": sorted(new_resources_set.keys()),
            "count": int(p.get("count") or 0),
        })
    new_doc: dict[str, typing.Any] = {
        "time_window": dict(permissions_doc.get("time_window") or {}),
        "bouncer": permissions_doc.get("bouncer"),
        "events_analyzed": permissions_doc.get("events_analyzed"),
        "permissions": new_perms,
        "observed_scope": map_observed_scope(
            permissions_doc.get("observed_scope") or {}, mapping,
        ),
        "resource_mapping_applied": mapping.name,
    }
    # Preserve notes if present.
    if permissions_doc.get("notes"):
        new_doc["notes"] = list(permissions_doc["notes"])
    return new_doc


def load_mapping_from_config(
    declaration: dict[str, typing.Any],
    mapping_name: str,
) -> ResourceMapping:
    """Look up a named mapping in a loaded ``.iam-jit.yaml`` declaration.

    Raises ``KeyError`` with a helpful message when the named mapping
    is missing — the agent then knows to either ask the operator to
    define it or fall back to the un-mapped permission set.
    """
    block = declaration.get("iam-jit") or {}
    if not isinstance(block, dict):
        raise KeyError("declaration missing top-level `iam-jit` block")
    mappings = block.get("resource_mappings") or {}
    if not isinstance(mappings, dict):
        raise KeyError(
            "declaration `iam-jit.resource_mappings` must be a mapping"
        )
    raw = mappings.get(mapping_name)
    if raw is None:
        available = sorted(mappings.keys())
        raise KeyError(
            f"resource mapping {mapping_name!r} not defined in config; "
            f"available: {available or '(none)'}"
        )
    return ResourceMapping.from_dict(mapping_name, raw)


def list_mappings_in_config(
    declaration: dict[str, typing.Any],
) -> list[str]:
    """List the names of all mappings defined in a loaded declaration.
    Sorted for stable CLI output."""
    block = declaration.get("iam-jit") or {}
    if not isinstance(block, dict):
        return []
    mappings = block.get("resource_mappings") or {}
    if not isinstance(mappings, dict):
        return []
    return sorted(mappings.keys())


__all__ = [
    "ResourceMapping",
    "apply_resource_mapping",
    "apply_resource_mapping_to_permissions",
    "list_mappings_in_config",
    "load_mapping_from_config",
    "map_observed_scope",
]
