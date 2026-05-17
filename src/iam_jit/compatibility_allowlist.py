"""Admin-managed compatibility allowlist (Slice 2 of #166).

Per [[iam-jit-inapplicable-cases]]: Slice 1 ships the curated
known-incompatible catalog (k8s IRSA, EC2 IP, Lambda exec, etc.).
Slice 2 adds an ADMIN-controlled per-account override layer so
organizations can declare:
- "for account 111... + workload k8s_pod, ALWAYS use existing role
  arn:aws:iam::111...:role/shared-ml-role"
- "for account 222..., iam-jit is OUT OF SCOPE (compliance env);
  escalate to human"
- "for account 333... + workload agent_local_dev, prefer the
  bouncer over issuing new roles"

This wires the `USE_BOUNCER` and `CANNOT_HELP` verdicts that Slice 1
reserved.

Per [[agent-friendly-not-bypassable]] Lens B: every allowlist
mutation is audit-logged via the bouncer's `config_events` table
(same chain). Admin CLI mutations + agent-visible reads;
mutation-via-MCP-tool is intentionally NOT exposed (agents can't
grant themselves access).

Per [[recommender-context-boundary]]: the allowlist is admin-supplied
config — iam-jit doesn't infer overrides from source code or AWS
state. Admin declares; checker consults.

Storage backends mirror `AccountStore`'s shape:
- `InMemoryAllowlistStore` (tests, transient)
- `FileAllowlistStore` (YAML on local disk, default for self-host)
- DynamoDB backend can land in Slice 3 if customers ask

Matching: rules are evaluated in INSERTION ORDER (first-match-wins).
A rule with `account_id=None` is a wildcard ("applies to any
account"); same for `workload`. Admin orders rules from specific
to general.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import pathlib
import re
import threading
import uuid
from typing import Any, Protocol

from .compatibility import (
    Compatibility,
    CompatibilityIntent,
    CompatibilityResult,
    WorkloadType,
    _validate_existing_role_hint,
)


_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


class AllowlistError(Exception):
    """Base for allowlist-store errors."""


class RuleNotFound(AllowlistError):
    pass


class InvalidRule(AllowlistError):
    """Raised when an admin tries to add a malformed rule (bad
    account ID, USE_EXISTING without role_arn, etc.). Per WB24
    MED-24-02 pattern: validate at insert so bad data never reaches
    the checker."""


@dataclasses.dataclass(frozen=True)
class AllowlistRule:
    """One admin-supplied override.

    `account_id` and `workload` are MATCHING criteria; either can
    be None to mean "any." `verdict` + `existing_role_arn` + `reason`
    + `next_action_hint` are the OUTPUT applied when the rule matches.

    Rules are immutable; admin updates a rule by removing + re-adding
    (each mutation captured separately in the audit chain).
    """

    rule_id: str  # opaque; assigned by store.add()
    account_id: str | None
    workload: WorkloadType | None
    verdict: Compatibility
    existing_role_arn: str | None
    reason: str
    next_action_hint: str | None
    created_at: str
    created_by: str

    def matches(self, intent: CompatibilityIntent) -> bool:
        """True iff this rule applies to the intent."""
        if self.account_id is not None and self.account_id != intent.target_account_id:
            return False
        if self.workload is not None and self.workload != intent.workload:
            return False
        return True

    def to_result(self) -> CompatibilityResult:
        """Build the CompatibilityResult this rule produces."""
        return CompatibilityResult(
            verdict=self.verdict,
            reasoning=(
                f"Admin allowlist rule {self.rule_id!r} matched: {self.reason}"
            ),
            existing_role_arn=self.existing_role_arn,
            matched_pattern=f"allowlist:{self.rule_id}",
            next_action_hint=self.next_action_hint,
            bouncer_recommended=(
                self.verdict == Compatibility.USE_BOUNCER
                or (self.verdict == Compatibility.USE_EXISTING
                    and self.existing_role_arn is not None)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "account_id": self.account_id,
            "workload": self.workload.value if self.workload else None,
            "verdict": self.verdict.value,
            "existing_role_arn": self.existing_role_arn,
            "reason": self.reason,
            "next_action_hint": self.next_action_hint,
            "created_at": self.created_at,
            "created_by": self.created_by,
        }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_account_id(account_id: str | None) -> str | None:
    """None passes through (wildcard); strings must be 12 digits."""
    if account_id is None:
        return None
    stripped = account_id.strip()
    if not stripped:
        return None
    if not _ACCOUNT_ID_RE.match(stripped):
        raise InvalidRule(
            f"account_id must be exactly 12 digits or None; got {account_id!r}"
        )
    return stripped


def _validate_workload(workload: WorkloadType | str | None) -> WorkloadType | None:
    if workload is None:
        return None
    if isinstance(workload, WorkloadType):
        return workload
    try:
        return WorkloadType(workload)
    except ValueError as e:
        raise InvalidRule(str(e)) from e


def _validate_verdict_and_arn(
    verdict: Compatibility | str,
    existing_role_arn: str | None,
) -> tuple[Compatibility, str | None]:
    """Cross-validate verdict + existing_role_arn:
    - USE_EXISTING REQUIRES an ARN
    - Other verdicts should NOT carry an ARN (would be confusing)
    """
    if isinstance(verdict, str):
        try:
            verdict_enum = Compatibility(verdict)
        except ValueError as e:
            raise InvalidRule(str(e)) from e
    else:
        verdict_enum = verdict

    if verdict_enum == Compatibility.USE_EXISTING:
        if not existing_role_arn:
            raise InvalidRule(
                "verdict=use_existing requires existing_role_arn"
            )
        cleaned, invalid = _validate_existing_role_hint(existing_role_arn)
        if invalid or cleaned is None:
            raise InvalidRule(
                f"existing_role_arn {existing_role_arn!r} is not a valid IAM role ARN"
            )
        return verdict_enum, cleaned

    if existing_role_arn:
        # Defensive: don't silently drop an ARN the admin supplied;
        # surface that the arn doesn't make sense for this verdict.
        raise InvalidRule(
            f"existing_role_arn only valid with verdict=use_existing "
            f"(got verdict={verdict_enum.value!r})"
        )
    return verdict_enum, None


# ---------------------------------------------------------------------------
# Store protocol + implementations
# ---------------------------------------------------------------------------


class AllowlistStore(Protocol):
    """The operations the checker + CLI + MCP layer need."""

    def list(self) -> list[AllowlistRule]: ...

    def get(self, rule_id: str) -> AllowlistRule: ...

    def add(self, rule: AllowlistRule) -> AllowlistRule: ...

    def remove(self, rule_id: str) -> AllowlistRule: ...


def _isoformat_z(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_rule(
    *,
    account_id: str | None,
    workload: WorkloadType | str | None,
    verdict: Compatibility | str,
    existing_role_arn: str | None = None,
    reason: str,
    next_action_hint: str | None = None,
    created_by: str,
    rule_id: str | None = None,
    created_at: str | None = None,
) -> AllowlistRule:
    """Validating constructor — admins and the CLI use this. Generates
    a UUID rule_id if not provided. Raises InvalidRule on bad input.
    """
    if not reason or not reason.strip():
        raise InvalidRule("reason is required and must be non-empty")
    cleaned_account = _validate_account_id(account_id)
    cleaned_workload = _validate_workload(workload)
    cleaned_verdict, cleaned_arn = _validate_verdict_and_arn(
        verdict, existing_role_arn
    )
    return AllowlistRule(
        rule_id=rule_id or uuid.uuid4().hex[:12],
        account_id=cleaned_account,
        workload=cleaned_workload,
        verdict=cleaned_verdict,
        existing_role_arn=cleaned_arn,
        reason=reason.strip(),
        next_action_hint=(next_action_hint.strip() if next_action_hint else None),
        created_at=created_at or _isoformat_z(_dt.datetime.now(_dt.UTC)),
        created_by=created_by,
    )


class InMemoryAllowlistStore:
    """In-memory store; for tests + transient use."""

    def __init__(self) -> None:
        self._rules: list[AllowlistRule] = []
        self._lock = threading.Lock()

    def list(self) -> list[AllowlistRule]:
        with self._lock:
            return list(self._rules)

    def get(self, rule_id: str) -> AllowlistRule:
        with self._lock:
            for r in self._rules:
                if r.rule_id == rule_id:
                    return r
        raise RuleNotFound(f"no rule with id {rule_id!r}")

    def add(self, rule: AllowlistRule) -> AllowlistRule:
        with self._lock:
            # rule_id uniqueness check
            if any(r.rule_id == rule.rule_id for r in self._rules):
                raise InvalidRule(f"duplicate rule_id {rule.rule_id!r}")
            self._rules.append(rule)
        return rule

    def remove(self, rule_id: str) -> AllowlistRule:
        with self._lock:
            for i, r in enumerate(self._rules):
                if r.rule_id == rule_id:
                    return self._rules.pop(i)
        raise RuleNotFound(f"no rule with id {rule_id!r}")


class FileAllowlistStore:
    """YAML-on-disk store. Mirrors `accounts_store.FileAccountStore`'s
    shape. Default for self-host deployments.

    File format (one rule per list entry):

        version: 1
        rules:
          - rule_id: abc123
            account_id: '111111111111'
            workload: k8s_pod
            verdict: use_existing
            existing_role_arn: arn:aws:iam::111111111111:role/shared-ml
            reason: shared ML cluster has fixed role
            next_action_hint: Use the shared ML role.
            created_at: 2026-05-17T15:00:00Z
            created_by: admin@example.com
    """

    def __init__(self, path: pathlib.Path | str) -> None:
        self.path = pathlib.Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _read_all(self) -> list[AllowlistRule]:
        if not self.path.exists():
            return []
        import yaml  # lazy import

        with self.path.open("r") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return []
        rules_data = data.get("rules") or []
        out: list[AllowlistRule] = []
        for raw in rules_data:
            if not isinstance(raw, dict):
                continue
            try:
                rule = build_rule(
                    rule_id=raw.get("rule_id"),
                    account_id=raw.get("account_id"),
                    workload=raw.get("workload"),
                    verdict=raw.get("verdict") or "proceed",
                    existing_role_arn=raw.get("existing_role_arn"),
                    reason=raw.get("reason") or "(no reason recorded)",
                    next_action_hint=raw.get("next_action_hint"),
                    created_by=raw.get("created_by") or "unknown",
                    created_at=raw.get("created_at"),
                )
            except InvalidRule:
                # Skip malformed rows; don't crash the whole listing.
                # (Mirrors WB23 MED-23-01 pattern.)
                continue
            out.append(rule)
        return out

    def _write_all(self, rules: list[AllowlistRule]) -> None:
        import yaml

        payload = {
            "version": 1,
            "rules": [r.to_dict() for r in rules],
        }
        # Atomic write via temp + rename so a crash mid-write doesn't
        # leave a half-file.
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w") as f:
            yaml.safe_dump(payload, f, default_flow_style=False, sort_keys=False)
        tmp.replace(self.path)

    def list(self) -> list[AllowlistRule]:
        with self._lock:
            return self._read_all()

    def get(self, rule_id: str) -> AllowlistRule:
        for r in self.list():
            if r.rule_id == rule_id:
                return r
        raise RuleNotFound(f"no rule with id {rule_id!r}")

    def add(self, rule: AllowlistRule) -> AllowlistRule:
        with self._lock:
            existing = self._read_all()
            if any(r.rule_id == rule.rule_id for r in existing):
                raise InvalidRule(f"duplicate rule_id {rule.rule_id!r}")
            existing.append(rule)
            self._write_all(existing)
        return rule

    def remove(self, rule_id: str) -> AllowlistRule:
        with self._lock:
            existing = self._read_all()
            for i, r in enumerate(existing):
                if r.rule_id == rule_id:
                    removed = existing.pop(i)
                    self._write_all(existing)
                    return removed
        raise RuleNotFound(f"no rule with id {rule_id!r}")


# ---------------------------------------------------------------------------
# Matching against an intent
# ---------------------------------------------------------------------------


def match_intent(
    intent: CompatibilityIntent, store: AllowlistStore
) -> AllowlistRule | None:
    """Return the FIRST rule whose criteria match the intent, or None
    if no rule matches.

    First-match-wins: admins are expected to order rules from specific
    to general (e.g. account-specific rule before account-wildcard).
    Tied to LOW-24-03's discipline.
    """
    for rule in store.list():
        if rule.matches(intent):
            return rule
    return None


# ---------------------------------------------------------------------------
# Default-store factory (env-driven, mirrors _build_request_store_from_env)
# ---------------------------------------------------------------------------


def default_allowlist_path() -> pathlib.Path:
    """`~/.iam-jit/compatibility_allowlist.yaml` unless
    `IAM_JIT_ALLOWLIST_PATH` overrides."""
    import os

    override = os.environ.get("IAM_JIT_ALLOWLIST_PATH")
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".iam-jit" / "compatibility_allowlist.yaml"


def build_default_store() -> AllowlistStore:
    """Env-driven default. Mirrors `_build_request_store_from_env`.
    For now only the filesystem backend; DynamoDB / S3 can land in
    Slice 3 if production deployments need them."""
    return FileAllowlistStore(default_allowlist_path())
