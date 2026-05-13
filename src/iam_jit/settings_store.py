"""Admin-editable runtime settings.

Single source for "things the operator can change without a
redeploy." Today: auto-approve threshold, per-user quota,
service / account blocklists. Tomorrow: more.

Architecture:
  - `Settings` dataclass is the immutable snapshot.
  - `SettingsStore` Protocol: `get()` / `put()`. DDB and in-memory
    variants. The DDB variant stores one row keyed `pk=settings`
    in the existing CidrsTable's table family (or a dedicated
    table; see __init__).
  - `get_default_store()` builds the right variant from env vars.
  - Admins update via POST /api/v1/admin/auto-approve/settings.
    Reads are cached for ~10s to avoid hammering DDB on every
    submission.

Why a settings store (vs env vars only):
  Env-var-only settings can't be changed without a redeploy.
  Auto-approve thresholds are exactly the kind of knob an
  operator wants to tighten during an incident ("disable auto-
  approve right now") or loosen after a misfire ("re-enable now
  that we've reviewed the chain"). DDB-backed settings give an
  in-band on/off switch.
"""

from __future__ import annotations

import dataclasses
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Floors:
    """Deploy-time hard limits on runtime settings.

    Read from Lambda env vars set by the SAM template. Admins can
    tighten settings (lower threshold, more strict blocklists) but
    the API refuses any PATCH that would loosen below these floors.

    The platform team that owns deploys owns the floors; the
    in-system admins own day-to-day tightening. This split is the
    iam-jit equivalent of AWS SCPs vs IAM identity policies.
    """

    max_auto_approve_risk_below: int = 5
    """Admin can NEVER set auto_approve_risk_below > this."""

    required_service_blocklist: tuple[str, ...] = (
        "iam", "organizations", "sts", "kms", "secretsmanager",
    )
    """Every entry MUST be in never_auto_approve_services."""

    required_account_blocklist: tuple[str, ...] = ()
    """Every entry MUST be in never_auto_approve_accounts."""

    max_auto_approve_quota_per_hour: int = 10
    """Admin can NEVER set auto_approve_quota_per_hour > this."""

    @classmethod
    def from_env(cls) -> "Floors":
        """Build from SAM-template-set env vars. Falls back to
        the dataclass defaults when an env var is unset (which
        means a dev deploy or a pre-floor-feature deploy)."""
        def _csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
            raw = (os.environ.get(name) or "").strip()
            if not raw:
                return default
            return tuple(s.strip() for s in raw.split(",") if s.strip())

        def _int(name: str, default: int) -> int:
            raw = (os.environ.get(name) or "").strip()
            try:
                return int(raw) if raw else default
            except ValueError:
                return default

        return cls(
            max_auto_approve_risk_below=_int(
                "IAM_JIT_MAX_AUTO_APPROVE_RISK_BELOW", 5
            ),
            required_service_blocklist=_csv(
                "IAM_JIT_REQUIRED_SERVICE_BLOCKLIST",
                ("iam", "organizations", "sts", "kms", "secretsmanager"),
            ),
            required_account_blocklist=_csv(
                "IAM_JIT_REQUIRED_ACCOUNT_BLOCKLIST", (),
            ),
            max_auto_approve_quota_per_hour=_int(
                "IAM_JIT_MAX_AUTO_APPROVE_QUOTA", 10
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_auto_approve_risk_below": self.max_auto_approve_risk_below,
            "required_service_blocklist": list(self.required_service_blocklist),
            "required_account_blocklist": list(self.required_account_blocklist),
            "max_auto_approve_quota_per_hour": self.max_auto_approve_quota_per_hour,
        }


def validate_against_floors(settings: "Settings", floors: Floors) -> list[str]:
    """Return a list of human-readable error messages for any
    floor violation. Empty list = settings are within floors.
    Used by the admin PATCH validator before persisting."""
    errors: list[str] = []
    if (
        settings.auto_approve_risk_below is not None
        and settings.auto_approve_risk_below > floors.max_auto_approve_risk_below
    ):
        errors.append(
            f"auto_approve_risk_below={settings.auto_approve_risk_below} "
            f"exceeds floor of {floors.max_auto_approve_risk_below}. "
            f"Platform team set this ceiling at deploy time via "
            f"MaxAutoApproveRiskBelow."
        )
    if (
        settings.auto_approve_quota_per_hour
        > floors.max_auto_approve_quota_per_hour
    ):
        errors.append(
            f"auto_approve_quota_per_hour="
            f"{settings.auto_approve_quota_per_hour} "
            f"exceeds floor of "
            f"{floors.max_auto_approve_quota_per_hour}. "
            f"Platform team set this ceiling at deploy time via "
            f"MaxAutoApproveQuotaPerHour."
        )
    missing_services = (
        set(floors.required_service_blocklist)
        - set(settings.never_auto_approve_services)
    )
    if missing_services:
        errors.append(
            f"never_auto_approve_services must include "
            f"{sorted(missing_services)} (locked by deploy via "
            f"RequiredServiceBlocklist). Add them back; you can keep "
            f"any additional entries you've added."
        )
    missing_accounts = (
        set(floors.required_account_blocklist)
        - set(settings.never_auto_approve_accounts)
    )
    if missing_accounts:
        errors.append(
            f"never_auto_approve_accounts must include "
            f"{sorted(missing_accounts)} (locked by deploy via "
            f"RequiredAccountBlocklist). These are typically your "
            f"prod account IDs; the deploy time choice is intentional."
        )
    return errors


@dataclass(frozen=True)
class PresetToggle:
    """One pre-defined rule the admin can enable/disable at runtime.

    The conditions are PRE-DEFINED — admins can flip the toggle on
    or off but cannot edit the condition fields. New conditions
    require a redeploy with an updated `AutoApproveTogglesJson`
    SAM parameter (or a future "platform team" admin endpoint).
    This split is the toggle-system equivalent of the
    settings-vs-floors model: admin tightens; platform team
    decides what tightening is available.

    Conditions match against the request's structured fields. The
    matchable shape today:

      - `account_id`: string  (matches if any account in the request
                               has this id)
      - `access_type`: "read-only" | "read-write" | "*"
      - `service`: string  (matches if any action's service is this)

    Actions:
      - `force_review_if` — when condition matches, route to human
        review regardless of score. Used for "no prod auto-approve"
        and "no IAM auto-approve" patterns.
      - `auto_approve_if` — when condition matches, bypass the
        normal score gate and auto-approve (FLOORS still apply —
        an account in the required_account_blocklist still blocks).
        Used for "all dev requests auto-approve" pattern. RISKIER
        than force_review_if; require operator confirmation in UI.

    Admins can ONLY toggle `enabled`. The id / name / condition /
    action are fixed at deploy.
    """

    id: str
    name: str
    description: str
    enabled: bool
    condition: dict[str, Any] = field(default_factory=dict)
    action: str = "force_review_if"

    def matches(self, request: dict[str, Any]) -> bool:
        """True iff the toggle's condition matches the request."""
        spec = request.get("spec") or {}

        if "account_id" in self.condition:
            target_id = self.condition["account_id"]
            accounts = spec.get("accounts") or []
            if not any(
                isinstance(a, dict) and a.get("account_id") == target_id
                for a in accounts
            ):
                return False

        if "access_type" in self.condition:
            target_at = self.condition["access_type"]
            if target_at != "*" and (spec.get("access_type") or "") != target_at:
                return False

        if "service" in self.condition:
            target_svc = self.condition["service"]
            policy = spec.get("policy") or {}
            found = False
            for stmt in policy.get("Statement") or []:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action") or []
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if isinstance(action, str) and action.startswith(f"{target_svc}:"):
                        found = True
                        break
                if found:
                    break
            if not found:
                return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "condition": dict(self.condition),
            "action": self.action,
        }


@dataclass(frozen=True)
class Settings:
    """Runtime configuration the admin can change without redeploy.

    All fields have sensible defaults so an unset settings store
    behaves like "auto-approve is OFF" — the conservative posture.
    """

    # Auto-approve fires when a request's risk score is STRICTLY
    # LESS THAN this value. None = auto-approve disabled. The choice
    # of "less than" (not "≤") makes the threshold legible: setting
    # threshold=4 auto-approves scores 1,2,3 and routes 4+ to
    # humans, matching the calibration table in docs/USE-CASES.md.
    auto_approve_risk_below: int | None = None

    # Sliding-window cap on per-user auto-approvals. Defends the
    # composability attack (chained low-risk requests). The (N+1)th
    # auto-approval-eligible request from the same user within the
    # window forces human review even if the score qualifies.
    auto_approve_quota_per_hour: int = 5

    # Services that NEVER auto-approve, regardless of score.
    # Sensible defaults that operators rarely want changed.
    never_auto_approve_services: tuple[str, ...] = (
        "iam",
        "organizations",
        "sts",
        "kms",
        "secretsmanager",
    )

    # Account IDs that NEVER auto-approve. Most useful with the
    # "prod accounts here" pattern: list every prod-tagged account
    # so even a low-score read against them goes to a human.
    never_auto_approve_accounts: tuple[str, ...] = ()

    # Admin-curated risk context. Extends the deterministic scorer
    # with org-specific knowledge that doesn't justify a code change.
    # Two typed fields today (more in roadmap):
    #
    #   additional_sensitive_services: services the org treats as
    #     sensitive even though policy_sentry doesn't classify them
    #     that way. Example: ["athena", "redshift-data"] for an
    #     analytics-heavy org where read-via-query is high-impact.
    #     Scorer treats these like default _SENSITIVE_SERVICES.
    #
    #   additional_high_impact_actions: specific actions that floor
    #     at score 5 even on a specific resource. Example:
    #     ["dynamodb:UpdateItem"] for a team that ships
    #     business-critical writes through one Lambda.
    #
    # See docs/TUNING-RISK.md for the full process: commit-vs-UI,
    # examples, calibration approach.
    additional_sensitive_services: tuple[str, ...] = ()
    additional_high_impact_actions: tuple[str, ...] = ()

    # Pre-defined toggles the admin can enable/disable. Each toggle's
    # condition and action are fixed at deploy via the
    # AutoApproveTogglesJson SAM parameter (or by direct PATCH from
    # a platform-team-only future endpoint). Admins flip `enabled`
    # only; they cannot reshape the rules. Toggle evaluation runs
    # BEFORE the score / quota gates: `force_review_if` short-
    # circuits to deny; `auto_approve_if` short-circuits to allow
    # (still subject to floors). Order is deterministic by toggle id.
    preset_toggles: tuple[PresetToggle, ...] = ()

    # Org-wide max on the duration of any role grant. None = no
    # cap. When set, submission of a request with
    # duration_hours > max_role_duration_hours is REFUSED at the
    # API layer with HTTP 400. Use this to express "no role should
    # last longer than 2 months" without code changes — set
    # max_role_duration_hours=1440 (= 60 days × 24h).
    max_role_duration_hours: int | None = None

    # Free-form notes from the admin explaining what they configured
    # and why. Returned on /api/v1/admin/auto-approve/settings so the
    # next admin can see the rationale without digging through audit.
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "auto_approve_risk_below": self.auto_approve_risk_below,
            "auto_approve_quota_per_hour": self.auto_approve_quota_per_hour,
            "never_auto_approve_services": list(self.never_auto_approve_services),
            "never_auto_approve_accounts": list(self.never_auto_approve_accounts),
            "additional_sensitive_services": list(self.additional_sensitive_services),
            "additional_high_impact_actions": list(self.additional_high_impact_actions),
            "preset_toggles": [t.to_dict() for t in self.preset_toggles],
            "max_role_duration_hours": self.max_role_duration_hours,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Settings":
        toggles_raw = data.get("preset_toggles") or []
        toggles = tuple(
            PresetToggle(
                id=t["id"],
                name=t.get("name", t["id"]),
                description=t.get("description", ""),
                enabled=bool(t.get("enabled", False)),
                condition=dict(t.get("condition") or {}),
                action=t.get("action") or "force_review_if",
            )
            for t in toggles_raw
            if isinstance(t, dict) and t.get("id")
        )
        return cls(
            auto_approve_risk_below=data.get("auto_approve_risk_below"),
            auto_approve_quota_per_hour=int(
                data.get("auto_approve_quota_per_hour") or 5
            ),
            never_auto_approve_services=tuple(
                data.get("never_auto_approve_services") or ()
            ),
            never_auto_approve_accounts=tuple(
                data.get("never_auto_approve_accounts") or ()
            ),
            additional_sensitive_services=tuple(
                data.get("additional_sensitive_services") or ()
            ),
            additional_high_impact_actions=tuple(
                data.get("additional_high_impact_actions") or ()
            ),
            preset_toggles=toggles,
            max_role_duration_hours=data.get("max_role_duration_hours"),
            notes=str(data.get("notes") or ""),
        )

    @property
    def auto_approve_enabled(self) -> bool:
        return (
            self.auto_approve_risk_below is not None
            and self.auto_approve_risk_below > 0
        )


class SettingsStore(Protocol):
    def get(self) -> Settings: ...
    def put(self, settings: Settings) -> None: ...


class InMemorySettingsStore:
    """Test / dev variant. Resets on Lambda cold-start; not
    suitable for production. Initialized with the default Settings."""

    def __init__(self, initial: Settings | None = None) -> None:
        self._settings = initial or Settings()

    def get(self) -> Settings:
        return self._settings

    def put(self, settings: Settings) -> None:
        self._settings = settings


class DynamoDBSettingsStore:
    """Persistent variant keyed `pk=auto-approve` in the named DDB
    table. Reads are cached for `cache_ttl_seconds` to bound the
    per-request DDB load — auto-approve evaluation runs on every
    submission, and operators change settings rarely. Stale-read
    risk: an admin disabling auto-approve takes up to
    `cache_ttl_seconds` to propagate to other Lambda containers.
    Acceptable; emergency "disable auto-approve" can be done by
    setting `IAM_JIT_AUTO_APPROVE_FORCE_OFF=1` (the env var bypasses
    the settings store entirely).
    """

    def __init__(self, table_name: str, cache_ttl_seconds: int = 10) -> None:
        self._table_name = table_name
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cached: Settings | None = None
        self._cached_at: float = 0.0
        self._client = None  # lazy import boto3

    def _get_client(self) -> Any:
        if self._client is None:
            import boto3
            self._client = boto3.client("dynamodb")
        return self._client

    def get(self) -> Settings:
        now = time.time()
        if self._cached is not None and now - self._cached_at < self._cache_ttl_seconds:
            return self._cached
        try:
            client = self._get_client()
            resp = client.get_item(
                TableName=self._table_name,
                Key={"pk": {"S": "auto-approve"}},
                ConsistentRead=False,
            )
            item = resp.get("Item")
            if item is None:
                settings = Settings()
            else:
                raw = item.get("payload", {}).get("S", "{}")
                settings = Settings.from_dict(json.loads(raw))
        except Exception:
            # DDB hiccup → fail closed (defaults = auto-approve disabled).
            settings = Settings()
        self._cached = settings
        self._cached_at = now
        return settings

    def put(self, settings: Settings) -> None:
        client = self._get_client()
        client.put_item(
            TableName=self._table_name,
            Item={
                "pk": {"S": "auto-approve"},
                "payload": {"S": json.dumps(settings.to_dict())},
                "updated_at": {"S": str(int(time.time()))},
            },
        )
        self._cached = settings
        self._cached_at = time.time()


_GLOBAL: SettingsStore | None = None


def get_default_store() -> SettingsStore:
    """Build the store from env on first use.

    Production: `IAM_JIT_SETTINGS_TABLE` env var → DDB-backed.
    Without it: in-memory (test mode).

    Emergency override: `IAM_JIT_AUTO_APPROVE_FORCE_OFF=1` makes
    `get()` always return Settings(auto_approve_risk_below=None)
    regardless of DDB content. Use this as a panic switch.
    """
    global _GLOBAL
    if _GLOBAL is None:
        table = os.environ.get("IAM_JIT_SETTINGS_TABLE", "").strip()
        if table:
            _GLOBAL = DynamoDBSettingsStore(table_name=table)
        else:
            _GLOBAL = InMemorySettingsStore()
    if os.environ.get("IAM_JIT_AUTO_APPROVE_FORCE_OFF") == "1":
        return _ForceOffStore(_GLOBAL)
    return _GLOBAL


def reset_default_store_for_tests() -> None:
    global _GLOBAL
    _GLOBAL = None


class _ForceOffStore:
    """Wraps another store; overrides `get()` to disable auto-approve.
    The env-var panic switch — operators can flip it without an admin
    user, useful during incident response."""

    def __init__(self, inner: SettingsStore) -> None:
        self._inner = inner

    def get(self) -> Settings:
        return dataclasses.replace(
            self._inner.get(),
            auto_approve_risk_below=None,
            notes=(self._inner.get().notes or "") + " [forced-off via env]",
        )

    def put(self, settings: Settings) -> None:
        self._inner.put(settings)
