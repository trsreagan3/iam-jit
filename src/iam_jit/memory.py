"""Approved-request memory.

A small, opt-in datastore of approved-and-active requests that the
intake LLM reads as "similar past approvals". The model uses these as
shape templates so repeat patterns produce tighter policies without
the user re-typing the same narrowing context every time.

Design choices and their reasons:

  - **Recorded ON APPROVAL, not on submission.** Pending or rejected
    requests are not a signal of "what good looks like"; only approvals
    are. We record the post-approval state as the canonical "this shape
    was reviewed and accepted".

  - **Sanitized snapshots, not raw policies.** We keep the description,
    services, access_type, account_id, a coarse "resource pattern"
    (e.g. `arn:aws:s3:::*` vs. `arn:aws:s3:::specific-name`), and the
    request name. We DROP concrete ARN values that might leak project
    names, customer IDs, or other org-sensitive content into the LLM
    prompt of an unrelated future request. The reviewer's exact policy
    is still in the audit log; the memory layer is just shapes.

  - **Top-K similarity, not full corpus.** When the intake module asks
    for context, we return at most ~5 entries most similar to the
    current request — by services + access_type + account, scored
    cheaply (Jaccard on services + exact-match on the rest). No
    embeddings, no vector DB; the corpus stays small enough that this
    works.

  - **Bounded growth.** Cap the file at N entries; oldest fall off.
    Default 500. Production deployments can resize via env.

  - **Off by default.** Set `IAM_JIT_MEMORY_FILE` to enable. We don't
    want this turning on silently — it's a privacy-meaningful change
    for a workspace.

The memory file is a YAML list of MemoryEntry records. Easy to inspect,
easy to delete, easy to commit (or .gitignore) at the admin's choice.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from typing import Any

from ruamel.yaml import YAML

_yaml = YAML(typ="safe")
_LOCK = threading.Lock()


@dataclass(frozen=True)
class MemoryEntry:
    """One approved request, sanitized for use as a context shape."""

    request_id: str
    name: str
    description: str
    account_id: str
    services: tuple[str, ...]
    access_type: str
    resource_shapes: tuple[str, ...]
    """ARN patterns with the user-specific identifier replaced by `<resource>`.

    e.g. `arn:aws:s3:::omise-config-staging/*` becomes
    `arn:aws:s3:::<resource>/*`. The shape is what's useful for future
    inference; the specific name is what's privacy-meaningful and
    therefore dropped."""
    duration_hours: int
    approved_at: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["services"] = list(d["services"])
        d["resource_shapes"] = list(d["resource_shapes"])
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MemoryEntry":
        return cls(
            request_id=str(d["request_id"]),
            name=str(d.get("name") or ""),
            description=str(d.get("description") or ""),
            account_id=str(d.get("account_id") or ""),
            services=tuple(d.get("services") or ()),
            access_type=str(d.get("access_type") or "read-only"),
            resource_shapes=tuple(d.get("resource_shapes") or ()),
            duration_hours=int(d.get("duration_hours") or 24),
            approved_at=str(d.get("approved_at") or ""),
        )


# ---- Sanitization ----


_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:([^:]+):([^:]*):([^:]*):(.+)$"
)


def _resource_shape(arn: str) -> str:
    """Replace the user-specific identifier in an ARN with `<resource>`.

    Preserves the service prefix, region, account, and any trailing
    path-suffix shape (e.g. `/*`). Wildcards pass through.

    Examples:
      arn:aws:s3:::my-bucket          -> arn:aws:s3:::<resource>
      arn:aws:s3:::my-bucket/*        -> arn:aws:s3:::<resource>/*
      arn:aws:lambda:us-east-1:1:function:my-fn -> arn:aws:lambda:us-east-1:<account>:function:<resource>
      *                               -> *
    """
    if arn == "*" or not arn.startswith("arn:aws"):
        return arn
    m = _ARN_RE.match(arn)
    if not m:
        return arn
    service, region, account, resource = m.group(1, 2, 3, 4)
    # Preserve `/*` suffix, sub-resource separators (e.g. `:function:name`).
    suffix = ""
    # Preserve empty-segment ARN formats like S3's `arn:aws:s3:::bucket`.
    # When region or account were empty in the input, keep them empty
    # in the shape — substituting `*`/`<account>` would produce invalid
    # ARNs for those services.
    region_out = region if region else ""
    account_out = account if account else ""
    if account and account.isdigit() and len(account) == 12:
        account_out = account
    elif account:
        account_out = "<account>"

    if "/" in resource:
        head, _, tail = resource.partition("/")
        if tail == "*":
            suffix = "/*"
        elif head and tail:
            tail_out = "*" if "*" in tail else "<sub>"
            return f"arn:aws:{service}:{region_out}:{account_out}:<resource>/{tail_out}"
    elif ":" in resource:
        head, _, tail = resource.partition(":")
        if tail:
            return f"arn:aws:{service}:{region_out}:{account_out}:{head}:<resource>"
    return f"arn:aws:{service}:{region_out}:{account_out}:<resource>{suffix}"


def _acct(account: str) -> str:
    return account if (account.isdigit() and len(account) == 12) else "<account>"


def _services_in_policy(policy: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in policy.get("Statement") or []:
        actions = s.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if isinstance(a, str) and ":" in a:
                svc = a.split(":", 1)[0]
                if svc not in seen:
                    seen.add(svc)
                    out.append(svc)
    return out


def _resource_shapes(policy: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in policy.get("Statement") or []:
        r = s.get("Resource")
        items = r if isinstance(r, list) else [r] if r else []
        for arn in items:
            if isinstance(arn, str):
                shape = _resource_shape(arn)
                if shape not in seen:
                    seen.add(shape)
                    out.append(shape)
    return out


def sanitize(request: dict[str, Any]) -> MemoryEntry:
    """Build a MemoryEntry from a request, dropping anything sensitive."""
    metadata = request.get("metadata") or {}
    spec = request.get("spec") or {}
    accounts = spec.get("accounts") or []
    account_id = (accounts[0].get("account_id") if accounts else "") or ""
    policy = spec.get("policy") or {}
    return MemoryEntry(
        request_id=str(metadata.get("id") or ""),
        name=str(metadata.get("name") or ""),
        description=str(spec.get("description") or "")[:200],
        account_id=account_id,
        services=tuple(_services_in_policy(policy)),
        access_type=str(spec.get("access_type") or "read-only"),
        resource_shapes=tuple(_resource_shapes(policy)),
        duration_hours=int((spec.get("duration") or {}).get("duration_hours") or 24),
        approved_at=_dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# ---- Storage ----


_DEFAULT_MAX_ENTRIES = 500


class MemoryStore:
    """File-backed bounded list of MemoryEntry records."""

    def __init__(self, path: str, *, max_entries: int = _DEFAULT_MAX_ENTRIES) -> None:
        self.path = path
        self.max_entries = max_entries

    def _read(self) -> list[MemoryEntry]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path) as fh:
                data = _yaml.load(fh)
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        out: list[MemoryEntry] = []
        for d in data:
            if isinstance(d, dict):
                try:
                    out.append(MemoryEntry.from_dict(d))
                except Exception:
                    continue
        return out

    def _write(self, entries: list[MemoryEntry]) -> None:
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(tmp, "w") as fh:
            _yaml.dump([e.to_dict() for e in entries], fh)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def all(self) -> list[MemoryEntry]:
        with _LOCK:
            return self._read()

    def append(self, entry: MemoryEntry) -> None:
        with _LOCK:
            entries = self._read()
            # Dedupe: if we already have this request_id, replace.
            entries = [e for e in entries if e.request_id != entry.request_id]
            entries.append(entry)
            if len(entries) > self.max_entries:
                entries = entries[-self.max_entries :]
            self._write(entries)


def is_enabled() -> bool:
    """Check whether the memory feature is enabled.

    Three off-switches, all honored:
      - **No LLM**: this feature only feeds the conversational intake
        prompt. With NoAI mode, nothing reads the memory, so recording
        is dead weight. We gate on the LLM being live.
      - `IAM_JIT_MEMORY_DISABLED=1` (or true/yes) — explicit kill-switch
        that overrides everything else. Use this to disable in
        production without changing other config.
      - `IAM_JIT_MEMORY_FILE` unset — the feature stays off by default
        when no path is configured.

    Off-by-default is intentional: this feature changes the LLM prompt
    visibly and is privacy-meaningful for a workspace, so admins should
    have to opt in explicitly.
    """
    if (os.environ.get("IAM_JIT_MEMORY_DISABLED") or "").lower() in {"1", "true", "yes"}:
        return False
    if not os.environ.get("IAM_JIT_MEMORY_FILE"):
        return False
    # Memory only feeds the intake LLM prompt; if LLM is off, skip.
    try:
        from . import review

        return review.is_review_enabled()
    except Exception:
        return False


def get_store() -> MemoryStore | None:
    """Return the configured store, or None when memory is disabled.

    Footprint: a single YAML file capped at 500 entries by default
    (~150 KB max). No database, no vector store, no embeddings. Reads
    are O(N) but at this scale that's negligible.
    """
    if not is_enabled():
        return None
    path = os.environ.get("IAM_JIT_MEMORY_FILE")
    if not path:
        return None
    max_entries = int(os.environ.get("IAM_JIT_MEMORY_MAX_ENTRIES") or _DEFAULT_MAX_ENTRIES)
    return MemoryStore(path, max_entries=max_entries)


# ---- Recall (similarity) ----


def _jaccard(a: tuple[str, ...], b: tuple[str, ...]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / max(len(sa | sb), 1)


def find_similar(
    entries: list[MemoryEntry],
    *,
    services: list[str],
    access_type: str,
    account_id: str,
    limit: int = 5,
) -> list[MemoryEntry]:
    """Return up to `limit` past entries most similar to the query.

    Score = Jaccard(services) + 0.5 * (account match) + 0.25 * (access
    type match). Coarse on purpose; embeddings are overkill at this
    scale. Stable sort so ties keep most-recent order.
    """
    scored: list[tuple[float, MemoryEntry]] = []
    q_services = tuple(services)
    for e in entries:
        score = _jaccard(q_services, e.services)
        if account_id and e.account_id == account_id:
            score += 0.5
        if access_type and e.access_type == access_type:
            score += 0.25
        if score > 0:
            scored.append((score, e))
    scored.sort(key=lambda x: (x[0], x[1].approved_at), reverse=True)
    return [e for _, e in scored[:limit]]


def render_for_prompt(entries: list[MemoryEntry]) -> str:
    """Format entries for splicing into the LLM system prompt.

    Empty list → empty string. Otherwise a labeled block similar to
    the org-context block, so the model can use it as grounding for
    "what shapes have been approved before"."""
    if not entries:
        return ""
    lines = [
        "\n\nPAST APPROVED SHAPES (recorded after human review — use as a",
        "guide for what reviewers tend to accept; do NOT copy specific",
        "resource names — they were sanitized out for privacy):",
        "<<<MEMORY>>>",
    ]
    for e in entries:
        lines.append(
            f"- [{e.access_type}] services={list(e.services)} "
            f"account={e.account_id or '<unknown>'} "
            f"duration={e.duration_hours}h "
            f"resources={list(e.resource_shapes)} "
            f"description: {e.description[:140]!r}"
        )
    lines.append("<<<END_MEMORY>>>\n")
    return "\n".join(lines)
