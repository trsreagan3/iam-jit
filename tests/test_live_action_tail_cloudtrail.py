"""Tests for the boto3-backed CloudTrail LookupEvents source.

The CloudTrail API is mocked via a hand-rolled fake session +
client so the tests don't require moto / network access. The
parsing helper is tested directly with realistic CloudTrail
LookupEvents response payloads.
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

from iam_jit.live_action_tail import TailQuery, TailResult
from iam_jit.live_action_tail_cloudtrail import (
    CloudTrailLookupSource,
    _parse_cloudtrail_event,
    _parse_iso8601,
)


# ---------------------------------------------------------------------------
# _parse_iso8601
# ---------------------------------------------------------------------------


def test_parse_iso8601_handles_z_suffix() -> None:
    out = _parse_iso8601("2026-05-17T14:00:00Z")
    assert out.tzinfo is not None
    assert out.year == 2026


def test_parse_iso8601_handles_explicit_offset() -> None:
    out = _parse_iso8601("2026-05-17T14:00:00+00:00")
    assert out.tzinfo is not None


# ---------------------------------------------------------------------------
# _parse_cloudtrail_event
# ---------------------------------------------------------------------------


def _ct_event(
    *,
    event_name: str = "GetObject",
    event_source: str = "s3.amazonaws.com",
    event_time: _dt.datetime | None = None,
    error_code: str | None = None,
    role_name: str = "iam-jit-grant-1",
    role_session_name: str = "alice-laptop",
    resources: list[dict] | None = None,
    aws_region: str = "us-east-1",
    account_id: str = "111111111111",
) -> dict:
    """Build a realistic CloudTrail event entry. WB22 CRIT-22-01:
    sessionIssuer.userName is the ROLE NAME (e.g. iam-jit-grant-1);
    the assumed-role ARN's last segment is the user-chosen
    RoleSessionName (e.g. alice-laptop)."""
    detail = {
        "awsRegion": aws_region,
        "requestID": "abc-123",
        "sourceIPAddress": "1.2.3.4",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": f"AROAEXAMPLE:{role_session_name}",
            "arn": f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{role_session_name}",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "userName": role_name,  # the IAM role name
                    "arn": f"arn:aws:iam::{account_id}:role/{role_name}",
                }
            },
        },
    }
    if error_code:
        detail["errorCode"] = error_code
        detail["errorMessage"] = f"{error_code}: simulated"
    return {
        "EventName": event_name,
        "EventSource": event_source,
        "EventTime": event_time or _dt.datetime(2026, 5, 17, 14, 23, 18, tzinfo=_dt.UTC),
        "Resources": resources or [
            {"ResourceType": "AWS::S3::Object", "ResourceName": "arn:aws:s3:::b/k"}
        ],
        "CloudTrailEvent": json.dumps(detail),
    }


def test_parse_cloudtrail_event_happy_path() -> None:
    ev = _parse_cloudtrail_event(_ct_event(), fallback_region="us-west-2")
    assert ev is not None
    assert ev.event_name == "GetObject"
    assert ev.event_source == "s3.amazonaws.com"
    assert ev.action == "s3:GetObject"
    assert ev.aws_region == "us-east-1"
    assert ev.request_id == "abc-123"
    # WB22 CRIT-22-01: role_name comes from sessionIssuer.userName;
    # role_session_name comes from the assumed-role ARN's tail.
    assert ev.role_name == "iam-jit-grant-1"
    assert ev.role_session_name == "alice-laptop"
    assert ev.resources == ("arn:aws:s3:::b/k",)
    assert ev.succeeded


def test_parse_cloudtrail_event_role_session_name_from_principalid_fallback() -> None:
    """If the assumed-role ARN isn't present, fall back to splitting
    principalId on ':' to recover the role-session-name."""
    raw = _ct_event()
    detail = json.loads(raw["CloudTrailEvent"])
    # Drop the arn, keep principalId
    detail["userIdentity"].pop("arn", None)
    raw["CloudTrailEvent"] = json.dumps(detail)
    ev = _parse_cloudtrail_event(raw, fallback_region="us-east-1")
    assert ev is not None
    assert ev.role_session_name == "alice-laptop"


def test_parse_cloudtrail_event_failure_path() -> None:
    ev = _parse_cloudtrail_event(
        _ct_event(error_code="AccessDenied"), fallback_region="us-east-1"
    )
    assert ev is not None
    assert ev.error_code == "AccessDenied"
    assert ev.error_message is not None
    assert ev.succeeded is False


def test_parse_cloudtrail_event_uses_fallback_region_when_detail_missing() -> None:
    raw = _ct_event()
    # Strip the region from the detail
    detail = json.loads(raw["CloudTrailEvent"])
    detail.pop("awsRegion", None)
    raw["CloudTrailEvent"] = json.dumps(detail)
    ev = _parse_cloudtrail_event(raw, fallback_region="eu-west-1")
    assert ev is not None
    assert ev.aws_region == "eu-west-1"


def test_parse_cloudtrail_event_malformed_detail_blob() -> None:
    raw = _ct_event()
    raw["CloudTrailEvent"] = "{not-valid-json"
    ev = _parse_cloudtrail_event(raw, fallback_region="us-east-1")
    assert ev is not None
    # Falls back gracefully — event_name still present from top-level
    assert ev.event_name == "GetObject"
    # No detail blob means no role identity etc.
    assert ev.role_name is None
    assert ev.role_session_name is None


def test_parse_cloudtrail_event_non_dict_returns_none() -> None:
    assert _parse_cloudtrail_event("not-a-dict", fallback_region="us-east-1") is None  # type: ignore[arg-type]


def test_parse_cloudtrail_event_handles_multiple_resources() -> None:
    raw = _ct_event(resources=[
        {"ResourceType": "AWS::S3::Object", "ResourceName": "arn:aws:s3:::b/k1"},
        {"ResourceType": "AWS::S3::Object", "ResourceName": "arn:aws:s3:::b/k2"},
    ])
    ev = _parse_cloudtrail_event(raw, fallback_region="us-east-1")
    assert ev is not None
    assert ev.resources == ("arn:aws:s3:::b/k1", "arn:aws:s3:::b/k2")


# ---------------------------------------------------------------------------
# CloudTrailLookupSource — hand-rolled fake session
# ---------------------------------------------------------------------------


class _FakeCloudTrailClient:
    def __init__(self, *, pages: list[dict] | None = None) -> None:
        self.pages = list(pages or [])
        self.calls: list[dict] = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        if not self.pages:
            return {"Events": []}
        return self.pages.pop(0)


class _FakeSession:
    def __init__(self, client: _FakeCloudTrailClient) -> None:
        self._client = client
        self.client_args: list[tuple] = []

    def client(self, name: str, region_name: str | None = None):
        self.client_args.append((name, region_name))
        return self._client


def _query(**overrides) -> TailQuery:
    defaults = {
        "role_name": "iam-jit-grant-1",
        "session_name": "iam-jit-provision-grant-1",
        "account_id": "111111111111",
    }
    defaults.update(overrides)
    return TailQuery(**defaults)


def test_fetch_events_returns_tail_result_ok() -> None:
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [_ct_event(event_name="GetObject")]}
    ])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
        default_region="us-east-1",
    )
    result = src.fetch_events(_query())
    assert isinstance(result, TailResult)
    assert result.ok is True
    assert result.error is None
    assert len(result.events) == 1
    assert result.events[0].event_name == "GetObject"


def test_fetch_events_does_not_use_username_lookup_attribute() -> None:
    """WB22 CRIT-22-01 regression: NEVER use Username as the
    LookupAttribute — for assumed-role events that's the end-user-
    chosen RoleSessionName, which we don't know."""
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [_ct_event(event_name="GetObject")]}
    ])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    src.fetch_events(_query())
    call = fake_client.calls[0]
    # No Username (or any other identity-filter) LookupAttributes —
    # we filter client-side by role_name now.
    attrs = call.get("LookupAttributes", [])
    for attr in attrs:
        assert attr.get("AttributeKey") != "Username", (
            "WB22 CRIT-22-01: Username filter is incorrect; "
            "matches end-user-chosen session name we don't know"
        )


def test_fetch_events_filters_client_side_by_role_name() -> None:
    """Events from other roles in the same time window must be
    dropped client-side."""
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [
            _ct_event(event_name="A", role_name="iam-jit-grant-1"),
            _ct_event(event_name="B", role_name="iam-jit-grant-2"),  # different grant
            _ct_event(event_name="C", role_name="iam-jit-grant-1"),
        ]}
    ])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    result = src.fetch_events(_query())
    names = [e.event_name for e in result.events]
    assert "A" in names
    assert "C" in names
    assert "B" not in names


def test_fetch_events_includes_events_with_missing_role_name() -> None:
    """If sessionIssuer is missing entirely (e.g. console events,
    root-account caller), include the event so caller can see the
    noise rather than silently filter useful data."""
    raw_no_session = _ct_event(event_name="weird")
    detail = json.loads(raw_no_session["CloudTrailEvent"])
    detail["userIdentity"].pop("sessionContext", None)
    raw_no_session["CloudTrailEvent"] = json.dumps(detail)
    fake_client = _FakeCloudTrailClient(pages=[{"Events": [raw_no_session]}])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    result = src.fetch_events(_query())
    assert len(result.events) == 1


def test_fetch_events_paginates() -> None:
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [_ct_event(event_name=f"E{i}") for i in range(50)], "NextToken": "p2"},
        {"Events": [_ct_event(event_name=f"E{50+i}") for i in range(30)]},
    ])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    result = src.fetch_events(_query(max_events=80))
    assert len(result.events) == 80


def test_fetch_events_respects_hard_max() -> None:
    """HARD_MAX_EVENTS caps requested max regardless of query."""
    # Build a lot of pages, each with 50 events and a NextToken so the
    # source would paginate forever if hard-cap broke.
    pages = []
    for p in range(50):
        page = {"Events": [_ct_event(event_name=f"E{p}-{i}") for i in range(50)]}
        if p < 49:
            page["NextToken"] = f"p{p+1}"
        pages.append(page)
    fake_client = _FakeCloudTrailClient(pages=pages)
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    result = src.fetch_events(_query(max_events=100_000))
    assert len(result.events) <= CloudTrailLookupSource.HARD_MAX_EVENTS


def test_fetch_events_returns_error_on_client_init_failure() -> None:
    """WB22 MED-22-03 closure: surface client-init failure honestly."""
    def failing_factory():
        raise RuntimeError("no credentials")

    src = CloudTrailLookupSource(boto3_session_factory=failing_factory)
    result = src.fetch_events(_query())
    assert result.ok is False
    assert result.events == ()
    assert "could not initialize" in result.error


def test_fetch_events_returns_error_on_lookup_failure() -> None:
    """WB22 MED-22-03 closure: surface lookup failure honestly."""
    class FailingClient(_FakeCloudTrailClient):
        def lookup_events(self, **kwargs):
            raise RuntimeError("rate limit")

    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(FailingClient()),
    )
    result = src.fetch_events(_query())
    assert result.ok is False
    assert "LookupEvents failed" in result.error


def test_fetch_events_terminates_on_empty_page_limit() -> None:
    """WB22 LOW-22-01 closure: bail after EMPTY_PAGE_LIMIT consecutive
    empty pages with NextToken."""
    pages = [
        {"Events": [], "NextToken": f"p{i}"}
        for i in range(10)
    ]
    fake_client = _FakeCloudTrailClient(pages=pages)
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    src.fetch_events(_query())
    # Should have stopped after the empty-page limit, not exhausted
    # all 10 pages.
    assert len(fake_client.calls) <= CloudTrailLookupSource.EMPTY_PAGE_LIMIT


def test_fetch_events_max_zero_returns_empty_without_call() -> None:
    fake_client = _FakeCloudTrailClient()
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    result = src.fetch_events(_query(max_events=0))
    assert result.ok is True
    assert result.events == ()
    assert fake_client.calls == []  # no API call when max_events <= 0


def test_fetch_events_applies_only_errors_filter() -> None:
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [
            _ct_event(event_name="ok"),
            _ct_event(event_name="fail", error_code="AccessDenied"),
        ]}
    ])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    result = src.fetch_events(_query(only_errors=True))
    assert len(result.events) == 1
    assert result.events[0].event_name == "fail"


def test_fetch_events_uses_region_from_query_over_default() -> None:
    fake_client = _FakeCloudTrailClient(pages=[{"Events": []}])
    fake_session = _FakeSession(fake_client)
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: fake_session,
        default_region="us-east-1",
    )
    src.fetch_events(_query(aws_region="eu-west-1"))
    assert fake_session.client_args == [("cloudtrail", "eu-west-1")]


def test_fetch_events_includes_time_window_when_provided() -> None:
    fake_client = _FakeCloudTrailClient(pages=[{"Events": []}])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    q = TailQuery(
        role_name="iam-jit-grant-1",
        session_name="iam-jit-provision-grant-1",
        account_id="111111111111",
        since="2026-05-17T14:00:00Z",
        until="2026-05-17T15:00:00Z",
    )
    src.fetch_events(q)
    call = fake_client.calls[0]
    assert "StartTime" in call
    assert "EndTime" in call


def test_describe_mentions_lag_and_event_history_specifically() -> None:
    """WB22 MED-22-02 closure: describe() must say 'Event-history'
    (the 90d API window), not just 'retention' which conflates with
    the customer's trail's S3 retention."""
    src = CloudTrailLookupSource(default_region="us-east-1")
    desc = src.describe()
    assert "cloudtrail" in desc.lower()
    assert "lag" in desc.lower()
    assert "event-history" in desc.lower()
    assert "90d" in desc
