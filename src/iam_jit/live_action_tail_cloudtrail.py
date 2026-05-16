"""Boto3-backed `LiveActionTailSource` using CloudTrail
`LookupEvents`.

Per [[live-action-tail-pro-tier]] + [[no-hosted-saas]]: the
customer's own self-hosted iam-jit deployment queries CloudTrail in
their own account using their own AWS credentials. iam-jit-the-
company never sees these credentials or events. This module is the
default self-host implementation; the Enterprise plugin adds an
EventBridge subscription source on top for true streaming.

Per [[pro-self-host-llm-choice]] reasoning: this source is FREE in
OSS — customer pays AWS for the lookup_events query
(~$2.00 per 100k events returned). iam-jit is just "call the API +
format results". No iam-jit-billable component.

Permission requirement (document for self-host admins): the
iam-jit-runner principal needs `cloudtrail:LookupEvents` on the
account hosting the JIT-issued role. That's read-only; no IAM
modification required.

Known caveats (documented for the OSS user, not bugs to fix):
- CloudTrail `LookupEvents` has eventual consistency — events can
  take up to ~15 min to appear after the API call happens. For true
  real-time, use the Enterprise EventBridge plugin.
- CloudTrail retains lookup history for 90 days; older events
  require CloudTrail Lake or a configured trail querying S3.
- `LookupEvents` is rate-limited to 2 TPS per account/region. Heavy
  tailing should target one region or use the Enterprise streaming
  plugin which doesn't share this limit.
"""

from __future__ import annotations

import datetime as _dt
import logging
from typing import Any

from .live_action_tail import (
    LiveActionEvent,
    LiveActionTailSource,
    TailQuery,
    filter_events,
)

logger = logging.getLogger(__name__)


class CloudTrailLookupSource(LiveActionTailSource):
    """Concrete `LiveActionTailSource` that queries CloudTrail's
    `LookupEvents` API.

    Filter strategy: CloudTrail supports `LookupAttributes` with
    `Username` matching the assumed-role session name (see
    `provision.py`'s `iam-jit-provision-{request_id}` pattern).
    That's the surgical filter — we don't have to scan every event
    in the account.
    """

    # Hard cap on per-fetch results to keep accidental cost-spikes
    # bounded; agents / UIs that need more must paginate explicitly.
    HARD_MAX_EVENTS = 1000

    def __init__(
        self,
        *,
        boto3_session_factory: Any | None = None,
        default_region: str = "us-east-1",
    ) -> None:
        """`boto3_session_factory` is a callable returning a `boto3.Session`
        — injectable for tests / dual-credential setups. If None, uses
        the ambient `boto3.Session()`.

        `default_region` is used when the `TailQuery` doesn't specify
        one. CloudTrail is regional, so the iam-jit operator should
        usually pin this to the region where the JIT role is exercised.
        """
        self._session_factory = boto3_session_factory
        self._default_region = default_region

    def describe(self) -> str:
        return (
            f"cloudtrail:LookupEvents (region={self._default_region}, "
            f"lag~15min, retention=90d)"
        )

    def _session(self) -> Any:
        if self._session_factory is not None:
            return self._session_factory()
        import boto3

        return boto3.Session()

    def _client(self, region: str) -> Any:
        return self._session().client("cloudtrail", region_name=region)

    def fetch_events(self, query: TailQuery) -> list[LiveActionEvent]:
        region = query.aws_region or self._default_region
        max_events = min(query.max_events, self.HARD_MAX_EVENTS)
        if max_events <= 0:
            return []

        try:
            client = self._client(region)
        except Exception as e:
            # boto3 import error / no credentials / no region — fail
            # soft: surface as an empty result + a logged warning so
            # callers can show the user a "couldn't reach CloudTrail"
            # banner without crashing the whole MCP / CLI flow.
            logger.warning("cloudtrail client init failed: %s", e)
            return []

        params: dict[str, Any] = {
            "LookupAttributes": [
                {"AttributeKey": "Username", "AttributeValue": query.session_name}
            ],
            "MaxResults": min(50, max_events),  # API max is 50 per call
        }
        if query.since:
            params["StartTime"] = _parse_iso8601(query.since)
        if query.until:
            params["EndTime"] = _parse_iso8601(query.until)

        collected: list[LiveActionEvent] = []
        next_token: str | None = None
        # Bound the pagination loop to a sensible cap so a runaway
        # session window can't iterate forever.
        max_pages = max(1, (max_events + 49) // 50)
        for _ in range(max_pages):
            if next_token is not None:
                params["NextToken"] = next_token
            try:
                resp = client.lookup_events(**params)
            except Exception as e:
                logger.warning(
                    "cloudtrail lookup_events failed (session=%s, region=%s): %s",
                    query.session_name,
                    region,
                    e,
                )
                break
            for raw in resp.get("Events", []) or []:
                ev = _parse_cloudtrail_event(raw, fallback_region=region)
                if ev is not None:
                    collected.append(ev)
                if len(collected) >= max_events:
                    break
            if len(collected) >= max_events:
                break
            next_token = resp.get("NextToken")
            if not next_token:
                break

        # Client-side belt-and-suspenders filter (only_errors etc.)
        return filter_events(collected, only_errors=query.only_errors)[:max_events]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_iso8601(s: str) -> _dt.datetime:
    """Parse an ISO-8601 UTC string for boto3. Accepts the iam-jit
    canonical form `YYYY-MM-DDTHH:MM:SSZ` and full ISO variants."""
    return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _parse_cloudtrail_event(raw: dict[str, Any], *, fallback_region: str) -> LiveActionEvent | None:
    """Map a CloudTrail `LookupEvents` event entry → `LiveActionEvent`.

    Returns None for entries that can't be parsed (rather than
    raising) so a single malformed record doesn't break a whole
    fetch. The structure CloudTrail returns is documented at
    https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
    """
    import json

    if not isinstance(raw, dict):
        return None

    event_name = str(raw.get("EventName") or "")
    event_source = str(raw.get("EventSource") or "")

    # EventTime is a datetime (boto3 deserializes timestamps); normalize to ISO-Z.
    et = raw.get("EventTime")
    if isinstance(et, _dt.datetime):
        event_time = et.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        event_time = str(et) if et else ""

    # Detail blob lives in a JSON string inside `CloudTrailEvent` —
    # safer than walking the top-level Resources because CloudTrail
    # only populates Resources for a subset of services.
    detail_str = raw.get("CloudTrailEvent") or "{}"
    try:
        detail = json.loads(detail_str) if isinstance(detail_str, str) else {}
    except (ValueError, TypeError):
        detail = {}

    aws_region = str(detail.get("awsRegion") or fallback_region)
    request_id = detail.get("requestID") or detail.get("requestId")
    error_code = detail.get("errorCode")
    error_message = detail.get("errorMessage")
    source_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")

    # Resources list — CloudTrail puts these at the top level of `raw`,
    # not in the detail blob. Each entry is {ResourceType, ResourceName}.
    resources: list[str] = []
    for r in raw.get("Resources") or []:
        if isinstance(r, dict):
            name = r.get("ResourceName") or r.get("ResourceArn") or ""
            if name:
                resources.append(str(name))

    # Session-name extraction from userIdentity.sessionContext.sessionIssuer.userName
    session_name = None
    user_identity = detail.get("userIdentity") or {}
    if isinstance(user_identity, dict):
        sc = user_identity.get("sessionContext") or {}
        if isinstance(sc, dict):
            si = sc.get("sessionIssuer") or {}
            if isinstance(si, dict):
                session_name = si.get("userName")

    return LiveActionEvent(
        event_time=event_time,
        event_name=event_name,
        event_source=event_source,
        aws_region=aws_region,
        request_id=str(request_id) if request_id else None,
        error_code=str(error_code) if error_code else None,
        error_message=str(error_message) if error_message else None,
        resources=tuple(resources),
        source_ip=str(source_ip) if source_ip else None,
        user_agent=str(user_agent) if user_agent else None,
        session_name=str(session_name) if session_name else None,
    )
