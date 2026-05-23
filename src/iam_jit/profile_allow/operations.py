# #345 / §A25 — Profile-allow operations (add + introspect).
"""Shared backend for ``iam-jit profile allow`` CLI + the
``bounce_profile_allow`` MCP tool.

Mirrors the structural shape of :mod:`iam_jit.dynamic_denies.operations`
so the cross-product UX stays parity per
``[[cross-product-agent-parity]]``.

The single entry point is :func:`add_profile_allow_rule` which:

  1. Validates inputs (target / action / reason / profile presence;
     refuses ``*`` as a target per the design memo's "force operator
     specificity" requirement).
  2. Reads the current profile YAML.
  3. Refuses to mutate org-distributed profiles (matches
     :func:`iam_jit.bouncer.profiles.upsert_profile`).
  4. Decides whether to auto-apply (operator + opt-in for agent) or
     queue for approval (agent + default-off).
  5. Appends a new ``ProfileAllowRule`` to the profile's
     ``allow_rules`` tuple with provenance metadata embedded in the
     ``note`` field.
  6. Persists via :func:`iam_jit.bouncer.profiles.upsert_profile`.
  7. Fans out a profile-reload POST to each affected bouncer.

Per ``[[ibounce-honest-positioning]]``: agent-self-grant attempts are
ALWAYS recorded (even when held for approval) so the operator can
see the request later via ``iam-jit profile allow --list-pending``
(future surface; the queue file exists today as the persistence
layer).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import pathlib
import typing

from .fanout import (
    DEFAULT_PROFILE_RELOAD_URLS,
    ProfileReloadResult,
    fanout_profile_reload,
)


class ProfileAllowError(RuntimeError):
    """Structured operations-layer error. Carries a ``code`` so the CLI
    can map to an exit status + the MCP tool picks the right structured
    payload."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: dict[str, typing.Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


# ---------------------------------------------------------------------------
# Pending-approval queue (agent self-grants without --allow-agent-self-grant
# get queued here instead of auto-applied)
# ---------------------------------------------------------------------------

PENDING_APPROVALS_PATH_ENV = "IAM_JIT_PROFILE_ALLOW_PENDING_PATH"
"""Override path for the agent-pending-approval queue. Default lives in
``~/.iam-jit/bouncer/profile-allow-pending.jsonl``."""

_DEFAULT_PENDING_REL = pathlib.Path(".iam-jit") / "bouncer" / "profile-allow-pending.jsonl"


def resolve_pending_path(explicit: str | None = None) -> pathlib.Path:
    """Resolve the pending-approvals queue path."""
    if explicit:
        return pathlib.Path(explicit)
    env = os.environ.get(PENDING_APPROVALS_PATH_ENV)
    if env:
        return pathlib.Path(env)
    return pathlib.Path.home() / _DEFAULT_PENDING_REL


# ---------------------------------------------------------------------------
# Source-vs-actor classification
# ---------------------------------------------------------------------------

# Sources that are "agents" for the agent-self-grant gate. ``mcp`` is the
# canonical agent surface (Claude / Codex / Cursor reach the operations
# layer via the MCP server). ``cli`` is treated as an operator unless
# the actor identity signals otherwise.
_AGENT_SOURCES: frozenset[str] = frozenset({"mcp"})


def _is_agent_request(source: str) -> bool:
    return source in _AGENT_SOURCES


# ---------------------------------------------------------------------------
# Auto-apply gate
# ---------------------------------------------------------------------------

ALLOW_AGENT_SELF_GRANT_ENV = "IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT"
"""Bouncer-startup env var the operator sets to opt in to agent-driven
allows. Default OFF — agent attempts to add to allow_rules without
this flag set are queued for operator confirmation."""


def _agent_self_grant_enabled() -> bool:
    raw = os.environ.get(ALLOW_AGENT_SELF_GRANT_ENV, "").strip().lower()
    return raw in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Duration parsing (delegates to dynamic_denies.store.parse_duration for
# wire-shape consistency)
# ---------------------------------------------------------------------------


def _parse_duration_to_expiry(
    duration: str | None,
) -> tuple[str | None, str | None]:
    """Parse a duration string into (duration_str, expires_at_iso).

    ``None`` / ``""`` / ``"permanent"`` -> ``(None, None)`` (permanent).
    Other strings round-trip through dynamic_denies parsing.
    """
    if not duration:
        return None, None
    s = duration.strip()
    if not s or s == "permanent":
        return None, None
    from ..dynamic_denies.store import parse_duration

    td = parse_duration(s)
    if td is None:
        return s, None
    now = _dt.datetime.now(_dt.timezone.utc)
    expiry = (now + td).replace(microsecond=0)
    return s, expiry.isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Provenance-tagged note construction
# ---------------------------------------------------------------------------

EASY_ALLOW_ORIGIN_TAG = "[easy_allow]"
"""Substring marker the note field carries so the audit trail can
distinguish operator-installed allows from generator-installed allows.
Documented in the deny-visibility surface so the suggested_fix can call
back to the original easy_allow command if a deny matches an existing
easy_allow rule (rare; happens when the rule shape is wrong)."""


def _build_provenance_note(
    *,
    reason: str,
    actor: str,
    source: str,
    duration: str | None,
    expires_at: str | None,
) -> str:
    """Build the ProfileAllowRule.note string. Format:

        ``[easy_allow] <reason> -- by=<actor> via=<source>``
        ``[easy_allow] <reason> -- by=<actor> via=<source> expires=<iso>``
    """
    base = f"{EASY_ALLOW_ORIGIN_TAG} {reason} -- by={actor} via={source}"
    if expires_at:
        return f"{base} expires={expires_at}"
    if duration:
        return f"{base} duration={duration}"
    return base


# ---------------------------------------------------------------------------
# Target / action validation
# ---------------------------------------------------------------------------


def _validate_target_action(
    target: str,
    actions: typing.Sequence[str],
) -> None:
    """Per the design memo: refuse ``*`` as a target (force operator
    specificity; same shape as the dynamic-deny resolver). Refuse
    empty actions list. Refuse actions without a ``:`` separator (the
    ibounce rule engine only speaks ``service:Action``)."""
    if not isinstance(target, str) or not target.strip():
        raise ProfileAllowError(
            "--target is required",
            code="missing_target",
        )
    if target.strip() == "*":
        raise ProfileAllowError(
            "--target '*' is refused; profile allows must be specific. "
            "Use a glob (e.g. arn:aws:s3:::staging-cache-*) or a resource "
            "ARN. Per [[creates-never-mutates]] the easy-allow surface is "
            "deliberately narrower than 'allow everything'.",
            code="target_too_broad",
        )
    if not actions:
        raise ProfileAllowError(
            "--action is required (one or more service:Action strings)",
            code="missing_action",
        )
    for a in actions:
        if not isinstance(a, str) or ":" not in a or not a.strip():
            raise ProfileAllowError(
                f"action {a!r} must be a 'service:Action' string "
                "(e.g. s3:GetObject)",
                code="bad_action",
            )


# ---------------------------------------------------------------------------
# Org-distributed profile gate
# ---------------------------------------------------------------------------


def _refuse_org_distributed(profile_obj: typing.Any) -> None:
    """Mirror :func:`iam_jit.bouncer.profiles.upsert_profile`'s
    refusal: a profile sourced from an org URL is read-only at the
    personal CLI surface; users must define a local override profile
    to add allows.
    """
    src = getattr(profile_obj, "source", "local") or "local"
    if src != "local":
        raise ProfileAllowError(
            f"profile {profile_obj.name!r} is org-distributed "
            f"(source={src!r}) and read-only at the easy-allow surface. "
            f"Create a local profile with `iam-jit profile install` or "
            f"copy the profile to a new local name and `profile allow` "
            f"that.",
            code="org_distributed",
            details={
                "profile_name": profile_obj.name,
                "source": src,
            },
        )


# ---------------------------------------------------------------------------
# Pending-approval queue writer
# ---------------------------------------------------------------------------


def _enqueue_pending(
    *,
    target: str,
    actions: list[str],
    reason: str,
    duration: str | None,
    expires_at: str | None,
    profile_name: str,
    actor: str,
    source: str,
    queue_path: pathlib.Path | None = None,
    kind: str = "profile_allow",
    extra: dict[str, typing.Any] | None = None,
) -> dict[str, typing.Any]:
    """Append one pending-approval entry to the JSONL queue. Returns
    the entry dict so the caller can echo a ticket id back to the
    agent.

    ``kind`` defaults to ``"profile_allow"`` (the historical shape:
    propose adding ``actions`` on ``target`` to the profile). The
    improve-profile pipeline (#451 fix) also enqueues
    ``kind="scope_change"`` entries for scope-only diffs (e.g.
    ``only_account_ids: added 999988887777``); those entries carry
    ``extra`` payload describing the scope field + value(s).

    Per [[ibounce-honest-positioning]] both kinds land in the SAME
    JSONL file so the operator has ONE place to review every pending
    change — preserving the explanation message that says "inspect
    ~/.iam-jit/bouncer/profile-allow-pending.jsonl"."""
    qp = queue_path or resolve_pending_path()
    qp.parent.mkdir(parents=True, exist_ok=True)
    entry: dict[str, typing.Any] = {
        "id": _new_pending_id(),
        "requested_at": _now_iso(),
        "kind": kind,
        "target": target,
        "actions": list(actions),
        "reason": reason,
        "duration": duration,
        "expires_at": expires_at,
        "profile_name": profile_name,
        "actor": actor,
        "source": source,
        "status": "pending",
    }
    if extra:
        entry["extra"] = dict(extra)
    # Append, never rewrite — the file is a forensic record.
    with qp.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    try:
        qp.chmod(0o600)
    except OSError:
        pass
    return entry


def _new_pending_id() -> str:
    """Generate a fresh ``pa_<ULID>`` id. Reuses the dynamic-denies
    ULID generator so the wire shape is parity-aligned."""
    from ..dynamic_denies.store import new_rule_id

    raw = new_rule_id()
    # new_rule_id() returns ``dd_<ULID>``; swap the prefix.
    return "pa_" + raw[len("dd_"):]


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Add operation
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class AllowAddResult:
    """Structured outcome the CLI + MCP layers render."""

    status: str  # "applied" | "pending_approval"
    profile_name: str
    profile_path: str | None
    actions: list[str]
    target: str
    reason: str
    duration: str | None
    expires_at: str | None
    actor: str
    source: str
    fanout: list[dict[str, typing.Any]]
    pending_entry: dict[str, typing.Any] | None
    rule_count_after: int

    def as_dict(self) -> dict[str, typing.Any]:
        return dataclasses.asdict(self)


def add_profile_allow_rule(
    *,
    target: str,
    action: str | typing.Sequence[str],
    reason: str,
    duration: str | None = None,
    profile_name: str | None = None,
    source: str = "cli",
    actor: str | None = None,
    profiles_path: str | pathlib.Path | None = None,
    bouncer_url_overrides: typing.Mapping[str, str] | None = None,
    skip_fanout: bool = False,
    queue_path: pathlib.Path | None = None,
    allow_agent_self_grant: bool | None = None,
) -> AllowAddResult:
    """Append a profile allow rule (or queue it for approval).

    Parameters
    ----------
    target
        Target pattern (ARN glob, resource ARN). ``*`` is refused.
    action
        Either a single ``"service:Action"`` string or a list of them.
    reason
        Operator/agent-supplied explanation; surfaces in the
        ``note`` field + the admin-action audit event.
    duration
        Go-style duration (``"3h"``, ``"7d"``) or ``"permanent"`` /
        ``None`` (default). When non-permanent, the rule's note carries
        an ``expires=<iso>`` segment; the proxy hot-reload should drop
        the rule when the timestamp passes (FUTURE: today the duration
        is advisory metadata — operators remove expired rules via
        ``profile`` YAML edit. Phase 2 wires the expiry sweeper into
        the profile watcher).
    profile_name
        Profile to mutate. ``None`` -> the active profile. Active
        profile is resolved via :func:`iam_jit.bouncer.profiles.resolve_active_profile`.
    source
        ``"cli"`` / ``"mcp"`` / ``"api"``. MCP requests are subject to
        the agent-self-grant gate.
    actor
        Identity recorded in the note + audit event. ``None`` ->
        resolves via :func:`iam_jit.dynamic_denies.store.resolve_operator`.
    profiles_path
        Override the profiles.yaml location (tests inject here).
    bouncer_url_overrides
        Override bouncer mgmt URLs for the fan-out.
    skip_fanout
        Test hook — skip the reload POSTs.
    queue_path
        Override the pending-approvals JSONL path.
    allow_agent_self_grant
        Explicit override of the env-var gate. ``True`` -> always
        auto-apply MCP requests; ``False`` -> always queue; ``None``
        -> consult :func:`_agent_self_grant_enabled` (env-var).

    Returns
    -------
    AllowAddResult
        ``status="applied"`` when the rule was written + fan-out
        completed; ``status="pending_approval"`` when the agent's
        request was queued.
    """
    from ..bouncer.profiles import (
        Profile,
        ProfileAllowRule,
        load_profiles,
        resolve_active_profile,
        upsert_profile,
    )
    from ..dynamic_denies.store import resolve_operator

    actions_list: list[str]
    if isinstance(action, str):
        actions_list = [action]
    else:
        actions_list = [str(a) for a in action]
    _validate_target_action(target, actions_list)

    if not reason or not reason.strip():
        raise ProfileAllowError(
            "--reason is required (surfaces in note + audit event)",
            code="missing_reason",
        )

    resolved_actor = (actor or resolve_operator()).strip() or "local-operator"

    duration_str, expires_at = _parse_duration_to_expiry(duration)

    # Load profiles to resolve target name + check source.
    profiles = load_profiles(path=profiles_path)
    if profile_name:
        if profile_name not in profiles:
            raise ProfileAllowError(
                f"profile {profile_name!r} not found; available: "
                f"{sorted(profiles.keys())}",
                code="profile_not_found",
            )
        target_profile = profiles[profile_name]
    else:
        target_profile = resolve_active_profile(profiles=profiles)

    _refuse_org_distributed(target_profile)

    # Agent-self-grant gate (per design memo: agents cannot silently
    # self-grant unless operator opted in).
    self_grant_enabled = (
        allow_agent_self_grant
        if allow_agent_self_grant is not None
        else _agent_self_grant_enabled()
    )
    if _is_agent_request(source) and not self_grant_enabled:
        # Queue + return without mutating the profile.
        entry = _enqueue_pending(
            target=target,
            actions=actions_list,
            reason=reason.strip(),
            duration=duration_str,
            expires_at=expires_at,
            profile_name=target_profile.name,
            actor=resolved_actor,
            source=source,
            queue_path=queue_path,
        )
        return AllowAddResult(
            status="pending_approval",
            profile_name=target_profile.name,
            profile_path=None,
            actions=actions_list,
            target=target,
            reason=reason.strip(),
            duration=duration_str,
            expires_at=expires_at,
            actor=resolved_actor,
            source=source,
            fanout=[],
            pending_entry=entry,
            rule_count_after=len(target_profile.allow_rules),
        )

    # Apply path: append new ProfileAllowRule entries (one per action).
    note = _build_provenance_note(
        reason=reason.strip(),
        actor=resolved_actor,
        source=source,
        duration=duration_str,
        expires_at=expires_at,
    )

    new_rules: list[ProfileAllowRule] = list(target_profile.allow_rules)
    for act in actions_list:
        new_rules.append(ProfileAllowRule(
            pattern=act,
            arn_scope=target,
            region_scope=None,
            note=note,
        ))

    # Construct an additive Profile (dataclass is frozen — replace via
    # dataclasses.replace). All other fields preserved by-construction.
    updated = dataclasses.replace(target_profile, allow_rules=tuple(new_rules))
    profile_path = upsert_profile(updated, path=profiles_path)

    fanout_results: list[ProfileReloadResult] = []
    if not skip_fanout:
        # We fan out to every default bouncer URL — only ibounce
        # currently consumes the profile.yaml shape, but the parity
        # surface gives kbounce/dbounce/gbounce a no-op endpoint to
        # tick when they ship Phase 2.
        fanout_results = fanout_profile_reload(
            list(DEFAULT_PROFILE_RELOAD_URLS.keys()),
            overrides=bouncer_url_overrides,
        )

    return AllowAddResult(
        status="applied",
        profile_name=target_profile.name,
        profile_path=str(profile_path),
        actions=actions_list,
        target=target,
        reason=reason.strip(),
        duration=duration_str,
        expires_at=expires_at,
        actor=resolved_actor,
        source=source,
        fanout=[_serialise_reload(r) for r in fanout_results],
        pending_entry=None,
        rule_count_after=len(new_rules),
    )


def _serialise_reload(r: ProfileReloadResult) -> dict[str, typing.Any]:
    return {
        "bouncer": r.bouncer,
        "url": r.url,
        "reloaded": r.reloaded,
        "status_code": r.status_code,
        "error": r.error,
    }


# ---------------------------------------------------------------------------
# Pending-queue read accessors (for the FUTURE `--list-pending` /
# operator-approval surface; lands as Phase 2)
# ---------------------------------------------------------------------------


def list_pending(
    *,
    queue_path: pathlib.Path | None = None,
) -> list[dict[str, typing.Any]]:
    """Read every pending-approval entry from the JSONL queue. Returns
    an empty list when the file is absent. Stub-level today (Phase 1
    ships the writer; operator review surface lands in Phase 2)."""
    qp = queue_path or resolve_pending_path()
    if not qp.exists():
        return []
    out: list[dict[str, typing.Any]] = []
    with qp.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def enqueue_pending_scope_change(
    *,
    field: str,
    op: str,
    value: str,
    reason: str,
    profile_name: str,
    actor: str,
    source: str,
    queue_path: pathlib.Path | None = None,
) -> dict[str, typing.Any]:
    """Append one ``kind="scope_change"`` pending entry to the JSONL
    queue. Public surface for #451 fix — the improve-profile pipeline
    routes scope-only diffs (e.g. ``only_account_ids: added X``) through
    here so the JSONL file IS created + ``pending_entry_ids`` IS
    populated per ``[[ibounce-honest-positioning]]``.

    Parameters
    ----------
    field
        Scope field name (e.g. ``"only_account_ids"``, ``"only_regions"``).
    op
        One of ``"added"`` / ``"removed"`` (matches the human-readable
        bullet shape emitted by ``_compute_diff``).
    value
        The scope value being added/removed.
    """
    return _enqueue_pending(
        target=f"scope:{field}",
        actions=[f"{op} {value}"],
        reason=reason,
        duration=None,
        expires_at=None,
        profile_name=profile_name,
        actor=actor,
        source=source,
        queue_path=queue_path,
        kind="scope_change",
        extra={"scope_field": field, "scope_op": op, "scope_value": value},
    )


__all__ = [
    "ALLOW_AGENT_SELF_GRANT_ENV",
    "AllowAddResult",
    "EASY_ALLOW_ORIGIN_TAG",
    "PENDING_APPROVALS_PATH_ENV",
    "ProfileAllowError",
    "add_profile_allow_rule",
    "enqueue_pending_scope_change",
    "list_pending",
    "resolve_pending_path",
]
