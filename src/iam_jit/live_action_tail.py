"""Live action tail — read CloudTrail events for a JIT-issued role's
active session window.

Per [[live-action-tail-pro-tier]]: admins want a "what is this grant
doing right now?" view. This module is the OSS scaffolding: it
defines the data model (`LiveActionEvent`), the source abstraction
(`LiveActionTailSource`), an in-memory stub source for tests + manual
instrumentation, and a "null" source as the default (returns empty
with a note explaining how to wire a real source).

The concrete `CloudTrailLookupSource` (boto3 `cloudtrail:LookupEvents`)
lives in `live_action_tail_cloudtrail.py` so this module stays
dep-free for tests + import paths that don't need boto3.

Per [[creates-never-mutates]]: the tail only READS CloudTrail; it
never modifies any IAM resource. Per [[no-hosted-saas]]: the
customer's own self-hosted iam-jit instance queries CloudTrail in
the customer's own account using the customer's own credentials.
No iam-jit-the-company involvement at runtime.

Per [[pro-self-host-llm-choice]] reasoning: this pull-based source
is FREE in OSS (customer pays AWS query cost; iam-jit is just
"call lookup_events + format"). The Enterprise plugin (post-launch,
proprietary) adds the things iam-jit-the-company actually
infrastructures: EventBridge real-time subscription (push), web-UI
streaming, Slack streaming, multi-account aggregation, anomaly
detection, retention beyond raw CloudTrail.

Scope guardrails:
- This module does NOT poll continuously. Each `fetch_events()` call
  is a snapshot; callers decide cadence. (The Enterprise plugin
  layers true streaming on top via EventBridge.)
- This module does NOT persist anything; the source is the ground
  truth (CloudTrail).
"""

from __future__ import annotations

import abc
import dataclasses
import datetime as _dt
from typing import Any


@dataclasses.dataclass(frozen=True)
class LiveActionEvent:
    """One CloudTrail event scoped to a JIT-issued role's session.

    Fields are the subset of CloudTrail event JSON that iam-jit
    needs for an audit-quality "what did this grant do" view. Raw
    event detail is intentionally NOT captured — admins who need
    the full record should query CloudTrail directly.
    """

    event_time: str  # ISO-8601 UTC
    event_name: str  # e.g. "GetObject", "PutObject"
    event_source: str  # e.g. "s3.amazonaws.com"
    aws_region: str  # e.g. "us-east-1"
    request_id: str | None = None  # AWS request ID for cross-reference
    error_code: str | None = None  # populated when the call failed
    error_message: str | None = None
    resources: tuple[str, ...] = ()  # ARN strings touched
    source_ip: str | None = None
    user_agent: str | None = None
    # IAM role NAME from sessionContext.sessionIssuer.userName — this
    # is the value that matches the iam-jit-issued role's `role_name`
    # one-to-one. CRIT-22-01 closure: do NOT confuse this with the
    # role SESSION name (the per-assume `RoleSessionName` the end-user
    # picks freely — CloudTrail records that as `Username`, we cannot
    # predict it, and it must NOT be used as a filter).
    role_name: str | None = None
    # The end-user-chosen RoleSessionName, derived from the assumed-role
    # ARN's last segment. Surfaced as audit-display context only; never
    # used to filter (we don't know what the user picked, and they can
    # pick anything legal under the role's trust policy).
    role_session_name: str | None = None

    @property
    def action(self) -> str:
        """Canonical action label `service:Name`, derived from
        event_source + event_name (e.g. `s3:GetObject`)."""
        # event_source is "<service>.amazonaws.com" — extract service prefix
        svc = self.event_source.split(".")[0] if self.event_source else ""
        return f"{svc}:{self.event_name}" if svc and self.event_name else ""

    @property
    def succeeded(self) -> bool:
        return self.error_code is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_time": self.event_time,
            "event_name": self.event_name,
            "event_source": self.event_source,
            "action": self.action,
            "aws_region": self.aws_region,
            "request_id": self.request_id,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "resources": list(self.resources),
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "role_name": self.role_name,
            "role_session_name": self.role_session_name,
            "succeeded": self.succeeded,
        }


@dataclasses.dataclass(frozen=True)
class TailResult:
    """The return shape of `LiveActionTailSource.fetch_events`.

    Per WB22 MED-22-03 + LOW-22-03 closures: a bare `list[LiveActionEvent]`
    return can't distinguish "no activity" from "source failed". Wrapping
    in a result lets callers branch on `ok` and surface `error` honestly
    (UI banner, CLI non-zero exit, MCP error field).
    """

    events: tuple[LiveActionEvent, ...] = ()
    ok: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "ok": self.ok,
            "error": self.error,
        }


@dataclasses.dataclass(frozen=True)
class TailQuery:
    """Inputs that scope a `fetch_events` call to one grant's session.

    All fields are required except `since` / `until` (default to
    grant's full session window).
    """

    role_name: str
    session_name: str
    account_id: str
    since: str | None = None  # ISO-8601 UTC; default = grant's issued-at
    until: str | None = None  # ISO-8601 UTC; default = now or expires_at
    aws_region: str | None = None  # if set, narrow to one region
    max_events: int = 100
    only_errors: bool = False


class LiveActionTailSource(abc.ABC):
    """Abstract source for live-action events. Concrete impls:

    - `NullLiveActionTailSource` (default in OSS)
    - `InMemoryLiveActionTailSource` (tests + manual instrumentation)
    - `CloudTrailLookupSource` (boto3 — see `live_action_tail_cloudtrail.py`)
    - `EventBridgeSubscriptionSource` (Enterprise plugin, post-launch)
    """

    @abc.abstractmethod
    def fetch_events(self, query: TailQuery) -> TailResult:
        """Return events matching `query` in time-descending order,
        wrapped in a `TailResult` so callers can distinguish "no
        events" (`ok=True, events=[]`) from "source failed"
        (`ok=False, error="..."`). Concrete impls must respect
        `query.max_events` as a hard cap and `query.only_errors` as
        a server-side filter where possible (else apply client-side
        via `filter_events`).
        """

    def describe(self) -> str:
        """Human-readable name for this source — surfaced in CLI / MCP
        responses so users know what they're reading."""
        return type(self).__name__


class NullLiveActionTailSource(LiveActionTailSource):
    """Default source: returns no events with an explanatory note.

    Ships as the OSS default so the MCP tool / CLI command never
    crash on a fresh install — they just say "configure a source".
    Enterprise plugin swaps in `EventBridgeSubscriptionSource`;
    self-host admins can swap in `CloudTrailLookupSource` via the
    `live_action_tail_source` config knob.
    """

    def fetch_events(self, query: TailQuery) -> TailResult:
        return TailResult(events=(), ok=True)

    def describe(self) -> str:
        return (
            "null (no live-action source configured; see docs/LIVE-ACTION-TAIL.md "
            "to wire CloudTrail lookup or the Enterprise EventBridge plugin)"
        )


class InMemoryLiveActionTailSource(LiveActionTailSource):
    """Concrete source backed by an injected list of events.

    Useful for: tests, local-only dev where the customer manually
    instruments their workflow, and (notably) demos / comic-strip
    scenarios — see [[comic-strip-demo-format]] — where pre-recorded
    event sequences play back deterministically.

    Filter semantics: events are matched on `role_name` (the value of
    `sessionContext.sessionIssuer.userName` in the original CloudTrail
    record). CRIT-22-01 closure: do NOT filter on `role_session_name`
    — that's the end-user-chosen RoleSessionName and we don't know
    what they'll pick, so we'd silently drop their real activity.
    """

    def __init__(self, events: list[LiveActionEvent] | None = None) -> None:
        self._events: list[LiveActionEvent] = list(events or [])

    def add(self, event: LiveActionEvent) -> None:
        self._events.append(event)

    def fetch_events(self, query: TailQuery) -> TailResult:
        matched = [
            e for e in self._events
            if (e.role_name is None or e.role_name == query.role_name)
            and (query.aws_region is None or e.aws_region == query.aws_region)
        ]
        matched = filter_events(
            matched,
            since=query.since,
            until=query.until,
            only_errors=query.only_errors,
        )
        # CloudTrail orders descending by time; mirror that.
        matched.sort(key=lambda e: e.event_time, reverse=True)
        capped = matched[: max(0, query.max_events)]
        return TailResult(events=tuple(capped), ok=True)

    def describe(self) -> str:
        return f"in-memory ({len(self._events)} pre-loaded events)"


# ---------------------------------------------------------------------------
# Formatting + filtering helpers
# ---------------------------------------------------------------------------


def format_event_summary(event: LiveActionEvent) -> str:
    """One-line human summary, suitable for CLI / Slack / web stream.

    Format: `HH:MM:SSZ [✓|✗] service:Action (region) → resource[, ...]`
    Failure is marked with `✗ ERRCODE`; success with `✓`. Resources
    are truncated to first 2 + count.
    """
    # Time: hh:mm:ssZ
    try:
        ts = _dt.datetime.fromisoformat(event.event_time.replace("Z", "+00:00"))
        time_str = ts.strftime("%H:%M:%SZ")
    except (ValueError, AttributeError):
        time_str = event.event_time or "??:??:??Z"

    status = "OK" if event.succeeded else f"FAIL[{event.error_code}]"
    action = event.action or f"{event.event_source}:{event.event_name}"
    region = event.aws_region or "?"

    if event.resources:
        if len(event.resources) <= 2:
            res_str = " -> " + ", ".join(event.resources)
        else:
            res_str = f" -> {event.resources[0]} (+ {len(event.resources) - 1} more)"
    else:
        res_str = ""

    return f"{time_str} {status} {action} ({region}){res_str}"


def filter_events(
    events: list[LiveActionEvent],
    *,
    since: str | None = None,
    until: str | None = None,
    only_errors: bool = False,
    action_prefix: str | None = None,
) -> list[LiveActionEvent]:
    """Client-side filter; safe to apply after server-side fetch as
    a belt-and-suspenders check. Empty filters are no-ops."""
    out = events
    if since:
        out = [e for e in out if e.event_time >= since]
    if until:
        out = [e for e in out if e.event_time <= until]
    if only_errors:
        out = [e for e in out if not e.succeeded]
    if action_prefix:
        out = [e for e in out if e.action.startswith(action_prefix)]
    return out


# ---------------------------------------------------------------------------
# Grant extraction — pull tail-query inputs out of a stored request
# ---------------------------------------------------------------------------


def extract_tail_inputs_from_grant(request: dict[str, Any]) -> TailQuery | None:
    """Given a stored request dict, build a TailQuery from its
    `status.provisioned` block. Returns None if the request has not
    been provisioned (i.e. there's no grant to tail).

    The provisioned block is populated by `lifecycle.mark_provisioned`
    from a `ProvisioningResult` (see `provision.py`). Required fields
    for tailing: `role_name`, `session_name`, `account_id`.
    """
    if not isinstance(request, dict):
        return None
    status = request.get("status") or {}
    provisioned = status.get("provisioned") or {}
    if not isinstance(provisioned, dict):
        return None
    role_name = provisioned.get("role_name")
    session_name = provisioned.get("session_name")
    account_id = provisioned.get("account_id")
    if not (role_name and session_name and account_id):
        return None
    return TailQuery(
        role_name=str(role_name),
        session_name=str(session_name),
        account_id=str(account_id),
        # `since` defaults to provisioned-at if available; CloudTrail
        # will further bound to its own 90-day retention.
        since=_extract_provisioned_at(request, provisioned),
        until=provisioned.get("expires_at"),
    )


def _extract_provisioned_at(request: dict[str, Any], provisioned: dict[str, Any]) -> str | None:
    """Best-effort extract of when the grant was issued, to bound the
    CloudTrail query window. Tags carry provisioned-at; history may too.
    """
    tags = provisioned.get("tags") or {}
    if isinstance(tags, dict):
        pat = tags.get("provisioned-at") or tags.get("iam-jit:provisioned-at")
        if pat:
            return str(pat)
    # Fallback: search status history for the mark_provisioned event
    history = (request.get("status") or {}).get("history") or []
    for event in history:
        if not isinstance(event, dict):
            continue
        if event.get("kind") == "active" or event.get("to_state") == "active":
            ts = event.get("at") or event.get("timestamp")
            if ts:
                return str(ts)
    return None


# ---------------------------------------------------------------------------
# Source registry (single configurable runtime source)
# ---------------------------------------------------------------------------


def record_tail_read_in_history(
    store: Any,
    request: dict[str, Any],
    *,
    grant_id: str,
    query: TailQuery,
    result_ok: bool,
    event_count: int,
    actor: str,
) -> None:
    """Append a tail-read event to the grant's status.history so the
    audit chain doesn't have a hole. WB22 HIGH-22-01 closure.

    Best-effort: callers should wrap in try/except; this helper does
    NOT raise on store-write failure (the read already succeeded;
    we don't want to mask the result behind a write error).
    """
    import datetime as _dt

    status = request.setdefault("status", {})
    history = status.setdefault("history", [])
    if not isinstance(history, list):
        return
    history.append({
        "kind": "tail_read",
        "at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actor": actor,
        "since": query.since,
        "until": query.until,
        "aws_region": query.aws_region,
        "only_errors": query.only_errors,
        "max_events": query.max_events,
        "result_ok": result_ok,
        "event_count": event_count,
    })
    try:
        store.put(grant_id, request)
    except Exception:
        # Don't mask a successful read behind an audit-log persistence
        # failure. The read happened; the operator's logs will still
        # contain it; this is best-effort.
        pass


_active_source: LiveActionTailSource | None = None


def get_default_source() -> LiveActionTailSource:
    """Return the configured source; lazily initializes to
    `NullLiveActionTailSource` if nothing has been set."""
    global _active_source
    if _active_source is None:
        _active_source = NullLiveActionTailSource()
    return _active_source


def set_default_source(source: LiveActionTailSource | None) -> None:
    """Install a runtime source. Pass None to reset to the null source.
    Used by:
    - the Enterprise plugin's bootstrap to register EventBridge
    - the CloudTrail self-host bootstrap to register the boto3 source
    - tests, to inject `InMemoryLiveActionTailSource` deterministically
    """
    global _active_source
    _active_source = source
