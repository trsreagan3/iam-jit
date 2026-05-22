# #324e — Cross-protocol target resolver for `iam-jit deny add`.
"""Classify a deny target pattern by shape + route to the appropriate
bouncer(s).

The resolver is the routing brain of ``iam-jit deny add`` (#324e). It
takes operator-written target strings — ARNs, hostnames, k8s
namespaces, URLs — and decides which bouncer(s) should receive the
rule. The mapping lives at the design doc's `Cross-protocol target
resolver` table; this module is the executable form.

Per ``[[cross-product-agent-parity]]`` the resolver is invoked from
both the CLI (`iam-jit deny add`) AND the MCP tool
(`bounce_deny_add`), so an agent gets identical routing as a typed
operator.

Heuristics, evaluated top-to-bottom:

  1. ARN-shaped (``arn:aws:...``, including ``aws-cn`` / ``aws-us-gov``
     partitions) → ibounce.
  2. ``secret:<name-or-arn>`` shorthand → ibounce.
  3. Explicit prefixes: ``namespace:<name>`` / ``cluster:<name>`` →
     kbouncer. ``rds:<host>`` → dbounce.
  4. Hostname matching DB-shaped patterns (``*.rds.amazonaws.com``,
     ``*-db*``, ``*postgres*``, ``*mysql*``, ``*db.<domain>``) →
     dbounce. RDS-shaped hostnames ALSO land on gbounce since gbounce
     proxies the CONNECT establishment.
  5. ``https://...`` / ``http://...`` URL or bare hostname or IP /
     CIDR → gbounce.
  6. Bare lowercase identifier (no dots, hyphens-ok, k8s-namespace
     shape) → kbouncer.
  7. Unclassifiable → empty ``applied_to`` + warning surfaced in the
     CLI/MCP response (per the design doc's "ambiguous: no shape
     matches" handling).

Per ``[[ibounce-honest-positioning]]`` the resolver does NOT guess at
ambiguous patterns. When a string could shape-match more than one
bouncer (e.g. RDS endpoints route to dbounce + gbounce) the resolver
emits the union + the routing-explanation surface names every
contributing rule. Operators who want a different routing pass
``--bouncer NAME`` per the design doc.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
import typing

# Bouncer name canonical set. Mirrors the schema enum
# (`docs/schemas/dynamic-denies-v1.json::applied_to.enum`). Kept here
# so the resolver doesn't have to import the schema at runtime.
BOUNCER_IBOUNCE = "ibounce"
BOUNCER_KBOUNCER = "kbouncer"
BOUNCER_DBOUNCE = "dbounce"
BOUNCER_GBOUNCE = "gbounce"

VALID_BOUNCERS: frozenset[str] = frozenset({
    BOUNCER_IBOUNCE,
    BOUNCER_KBOUNCER,
    BOUNCER_DBOUNCE,
    BOUNCER_GBOUNCE,
})


# AWS ARN partition prefixes the resolver recognises. ARNs land on
# ibounce regardless of partition (commercial / China / GovCloud);
# operators may legitimately route a deny against any of them.
_AWS_ARN_PREFIXES = ("arn:aws:", "arn:aws-cn:", "arn:aws-us-gov:")

# ``secret:`` shorthand is a convenience for "lock out this Secrets
# Manager secret"; expanded to an arn pattern at match time inside
# ibounce's matcher.
_SECRET_PREFIX = "secret:"

# k8s shorthand prefixes — exact-prefix routing to kbouncer.
_NAMESPACE_PREFIX = "namespace:"
_CLUSTER_PREFIX = "cluster:"

# dbounce shorthand prefix — exact-prefix routing.
_RDS_PREFIX = "rds:"

# URL/scheme prefixes route to gbounce.
_HTTP_SCHEMES = ("http://", "https://")

# DB-shaped hostname substring hints. Matched case-insensitively
# against bare hostnames; matches route the rule to dbounce. RDS
# endpoints additionally land on gbounce (the CONNECT-establishment
# proxy).
_DB_HOSTNAME_HINTS = (
    "postgres",
    "mysql",
    "mariadb",
    "redshift",
    "aurora",
)

# Bare k8s identifier shape (RFC 1123 label-ish). Allowed in
# ``namespace:NAME`` shorthand AND as a standalone token. Cluster /
# namespace names are bounded to 63 chars per k8s.
_K8S_LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# k8s GVR shape (group/version/resource). Three slash-separated parts
# — routes to kbouncer.
_K8S_GVR_PATTERN = re.compile(
    r"^[a-z0-9.-]+/[a-z0-9]+/[a-z0-9.-]+$"
)


@dataclasses.dataclass(frozen=True)
class TargetClassification:
    """One target's resolution result.

    Carries enough provenance for the CLI/MCP output to render a
    routing explanation: which target landed on which bouncer(s) and
    via which heuristic.
    """

    target: str
    """The original target string (verbatim — case + whitespace
    preserved so the audit row mirrors what the operator typed)."""

    applied_to: tuple[str, ...]
    """The set of bouncers the target routed to. Empty when
    unclassifiable; the CLI surfaces an error + the MCP tool returns
    a structured ``unclassifiable_targets`` block."""

    rationale: str
    """Single-line human-readable explanation. Examples:

      * "ARN partition `arn:aws:` -> ibounce"
      * "hostname matched DB-shape `postgres` -> dbounce + gbounce"
      * "no shape matched; pass --bouncer NAME to override"
    """


@dataclasses.dataclass(frozen=True)
class ResolutionResult:
    """The aggregated result of resolving a multi-target rule.

    Combines the per-target classifications + the union of bouncers
    + any unclassifiable targets so the CLI/MCP layer can produce a
    single routing-explanation block AND the resulting ``applied_to``
    field with one call.
    """

    classifications: tuple[TargetClassification, ...]
    """One :class:`TargetClassification` per input target, in input
    order."""

    applied_to: tuple[str, ...]
    """The UNION of every successful target's bouncers (sorted, with
    duplicates removed). Becomes the rule's ``applied_to`` field
    on disk."""

    unclassifiable_targets: tuple[str, ...]
    """Subset of the input targets that did not match any shape AND
    were not covered by an explicit ``bouncer_override``. When
    non-empty + no override was supplied, ``iam-jit deny add`` refuses
    the rule with a structured error pointing at the design doc's
    `Cross-protocol target resolver table`."""

    @property
    def is_complete(self) -> bool:
        """``True`` when every input target was successfully
        classified (or covered by an override). The CLI uses this as
        the "safe to write the rule" gate."""
        return not self.unclassifiable_targets and bool(self.applied_to)


def resolve_targets(
    targets: typing.Iterable[str],
    *,
    bouncer_overrides: typing.Iterable[str] | None = None,
) -> ResolutionResult:
    """Classify ``targets``; aggregate into a single resolution.

    Parameters
    ----------
    targets
        Each operator-written target string. Whitespace is stripped
        for classification but the original string is preserved in the
        per-target :class:`TargetClassification` so the audit log
        mirrors what the operator typed.
    bouncer_overrides
        Optional iterable of bouncer names (``ibounce`` / ``kbouncer``
        / ``dbounce`` / ``gbounce``). When supplied, the resulting
        ``applied_to`` is the UNION of the resolver's output AND the
        overrides. Unclassifiable targets become "non-fatal" when the
        operator passed any overrides — the resolver assumes the
        override covers them.
    """
    overrides_set = _normalise_overrides(bouncer_overrides)
    classifications: list[TargetClassification] = []
    union: set[str] = set(overrides_set)
    unclassifiable: list[str] = []
    for t in targets:
        cls = classify_one(t)
        classifications.append(cls)
        if cls.applied_to:
            union.update(cls.applied_to)
        else:
            unclassifiable.append(cls.target)

    # If the operator passed an explicit override, treat unclassifiable
    # targets as "operator knows what they're doing" — the override is
    # the routing decision. We still surface the rationale in each
    # per-target classification.
    if overrides_set and unclassifiable:
        unclassifiable = []

    return ResolutionResult(
        classifications=tuple(classifications),
        applied_to=tuple(sorted(union)),
        unclassifiable_targets=tuple(unclassifiable),
    )


def classify_one(raw: str) -> TargetClassification:
    """Classify a single target string. Pure function — no I/O, no
    state. Used directly by the resolver + by the unit tests."""
    target = raw if isinstance(raw, str) else str(raw)
    stripped = target.strip()
    if not stripped:
        return TargetClassification(
            target=target,
            applied_to=(),
            rationale="empty target string",
        )

    lowered = stripped.lower()

    # 1. ARN-shape → ibounce.
    if lowered.startswith(_AWS_ARN_PREFIXES):
        prefix = next(p for p in _AWS_ARN_PREFIXES if lowered.startswith(p))
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_IBOUNCE,),
            rationale=f"ARN partition `{prefix}` -> ibounce",
        )

    # 2. `secret:` shorthand → ibounce.
    if lowered.startswith(_SECRET_PREFIX):
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_IBOUNCE,),
            rationale="`secret:` shorthand -> ibounce (Secrets Manager)",
        )

    # 3. Explicit k8s shorthand prefixes.
    if lowered.startswith(_NAMESPACE_PREFIX):
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_KBOUNCER,),
            rationale="`namespace:` shorthand -> kbouncer",
        )
    if lowered.startswith(_CLUSTER_PREFIX):
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_KBOUNCER,),
            rationale="`cluster:` shorthand -> kbouncer",
        )

    # 4. dbounce shorthand prefix.
    if lowered.startswith(_RDS_PREFIX):
        # RDS endpoints typically also need the CONNECT proxied;
        # gbounce additionally lands so HTTP-egress (CLI tools) is
        # blocked too. Honest cross-protocol routing.
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_DBOUNCE, BOUNCER_GBOUNCE),
            rationale="`rds:` shorthand -> dbounce + gbounce (SQL + CONNECT)",
        )

    # 5. URL form → gbounce.
    if lowered.startswith(_HTTP_SCHEMES):
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_GBOUNCE,),
            rationale="URL scheme -> gbounce",
        )

    # 6. k8s GVR shape (group/version/resource).
    if _K8S_GVR_PATTERN.match(lowered):
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_KBOUNCER,),
            rationale="k8s `group/version/resource` shape -> kbouncer",
        )

    # 7. IP literal or CIDR → gbounce.
    cidr_routing = _classify_ip_or_cidr(stripped)
    if cidr_routing is not None:
        return cidr_routing

    # 8. Hostname / hostname-glob heuristics.
    if "." in stripped or _looks_like_hostname(stripped):
        return _classify_hostname(stripped)

    # 9. Bare label that fits k8s naming → kbouncer.
    if _K8S_LABEL_PATTERN.match(lowered):
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_KBOUNCER,),
            rationale="bare k8s-label shape -> kbouncer (namespace-like)",
        )

    # 10. Unclassifiable.
    return TargetClassification(
        target=target,
        applied_to=(),
        rationale=(
            "no shape matched; pass --bouncer NAME to override "
            "(see DYNAMIC-DENY-RULES.md `Cross-protocol target resolver`)"
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_overrides(
    overrides: typing.Iterable[str] | None,
) -> tuple[str, ...]:
    """Normalise + dedupe the operator's ``--bouncer`` overrides.
    Rejects unknown names; the click ``choice`` constraint already
    catches typos at parse time, but the MCP-tool path is dict-based
    and benefits from the second pass.
    """
    if not overrides:
        return ()
    seen: list[str] = []
    seen_set: set[str] = set()
    for raw in overrides:
        if not raw:
            continue
        s = raw.strip()
        if s in VALID_BOUNCERS and s not in seen_set:
            seen.append(s)
            seen_set.add(s)
    return tuple(seen)


def _classify_ip_or_cidr(target: str) -> TargetClassification | None:
    """Return a classification when ``target`` looks like an IP literal
    or CIDR; ``None`` otherwise. Bare hostnames flow on to the
    hostname heuristic."""
    # CIDR form contains a slash.
    candidate = target
    try:
        if "/" in candidate:
            ipaddress.ip_network(candidate, strict=False)
        else:
            ipaddress.ip_address(candidate)
    except (ValueError, TypeError):
        return None
    return TargetClassification(
        target=target,
        applied_to=(BOUNCER_GBOUNCE,),
        rationale="IP literal or CIDR -> gbounce",
    )


def _looks_like_hostname(s: str) -> bool:
    """Cheap hostname-shape sniff for strings without dots — anything
    that has glob wildcards (`*` / `?`) but is clearly hostname-shaped
    (no slashes, no spaces, no shorthand prefix) qualifies."""
    if not s:
        return False
    if "/" in s or " " in s:
        return False
    if ":" in s:
        return False
    return any(ch in s for ch in ("*", "?"))


def _classify_hostname(target: str) -> TargetClassification:
    """Hostname / hostname-glob classification. Multi-bouncer-friendly
    — DB-shaped hostnames land on dbounce + gbounce."""
    lowered = target.lower()

    # Strip a leading wildcard segment for the substring sniff so
    # `*.rds.amazonaws.com` still matches the `rds.amazonaws.com` hint.
    sniff = lowered.lstrip("*.")

    is_rds = ".rds.amazonaws.com" in sniff or sniff.endswith(".rds.amazonaws.com")
    is_db_shape = (
        is_rds
        or any(hint in sniff for hint in _DB_HOSTNAME_HINTS)
        or "-db" in sniff
        or sniff.startswith("db-")
        or sniff.endswith("-db")
    )

    if is_db_shape:
        return TargetClassification(
            target=target,
            applied_to=(BOUNCER_DBOUNCE, BOUNCER_GBOUNCE),
            rationale=(
                "hostname matches DB shape "
                f"({'RDS endpoint' if is_rds else 'db-name pattern'}) "
                "-> dbounce + gbounce"
            ),
        )
    return TargetClassification(
        target=target,
        applied_to=(BOUNCER_GBOUNCE,),
        rationale="hostname -> gbounce (HTTP egress)",
    )


__all__ = [
    "BOUNCER_DBOUNCE",
    "BOUNCER_GBOUNCE",
    "BOUNCER_IBOUNCE",
    "BOUNCER_KBOUNCER",
    "ResolutionResult",
    "TargetClassification",
    "VALID_BOUNCERS",
    "classify_one",
    "resolve_targets",
]
