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

from iam_jit.live_action_tail import TailQuery
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
    session_name: str = "iam-jit-provision-req-1",
    resources: list[dict] | None = None,
    aws_region: str = "us-east-1",
) -> dict:
    detail = {
        "awsRegion": aws_region,
        "requestID": "abc-123",
        "sourceIPAddress": "1.2.3.4",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {
            "type": "AssumedRole",
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "userName": session_name}
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
    assert ev.session_name == "iam-jit-provision-req-1"
    assert ev.resources == ("arn:aws:s3:::b/k",)
    assert ev.succeeded


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
    # No detail blob means no error code etc.
    assert ev.session_name is None


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


def _query() -> TailQuery:
    return TailQuery(
        role_name="iam-jit-req-1",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
    )


def test_fetch_events_returns_parsed_events() -> None:
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [_ct_event(event_name="GetObject")]}
    ])
    fake_session = _FakeSession(fake_client)
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: fake_session,
        default_region="us-east-1",
    )
    events = src.fetch_events(_query())
    assert len(events) == 1
    assert events[0].event_name == "GetObject"
    # Called CloudTrail with the session-name LookupAttributes filter
    call = fake_client.calls[0]
    assert call["LookupAttributes"] == [
        {"AttributeKey": "Username", "AttributeValue": "iam-jit-provision-req-1"}
    ]


def test_fetch_events_paginates() -> None:
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [_ct_event(event_name=f"E{i}") for i in range(50)], "NextToken": "p2"},
        {"Events": [_ct_event(event_name=f"E{50+i}") for i in range(30)]},
    ])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    q = TailQuery(
        role_name="r",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        max_events=80,
    )
    events = src.fetch_events(q)
    assert len(events) == 80


def test_fetch_events_respects_hard_max() -> None:
    """HARD_MAX_EVENTS caps requested max regardless of query."""
    fake_client = _FakeCloudTrailClient(pages=[
        {"Events": [_ct_event(event_name=f"E{i}") for i in range(50)], "NextToken": "p2"},
    ] + [
        {"Events": [_ct_event(event_name=f"E{50+50*p+i}") for i in range(50)], "NextToken": f"p{p+3}"}
        for p in range(25)
    ])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    q = TailQuery(
        role_name="r",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        max_events=100_000,  # absurdly large
    )
    events = src.fetch_events(q)
    assert len(events) <= CloudTrailLookupSource.HARD_MAX_EVENTS


def test_fetch_events_returns_empty_on_client_init_failure() -> None:
    def failing_factory():
        raise RuntimeError("no credentials")

    src = CloudTrailLookupSource(boto3_session_factory=failing_factory)
    assert src.fetch_events(_query()) == []


def test_fetch_events_returns_empty_on_lookup_failure() -> None:
    class FailingClient(_FakeCloudTrailClient):
        def lookup_events(self, **kwargs):
            raise RuntimeError("rate limit")

    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(FailingClient()),
    )
    assert src.fetch_events(_query()) == []


def test_fetch_events_max_zero_returns_empty_without_call() -> None:
    fake_client = _FakeCloudTrailClient()
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    q = TailQuery(
        role_name="r",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        max_events=0,
    )
    assert src.fetch_events(q) == []
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
    q = TailQuery(
        role_name="r",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        only_errors=True,
    )
    events = src.fetch_events(q)
    assert len(events) == 1
    assert events[0].event_name == "fail"


def test_fetch_events_uses_region_from_query_over_default() -> None:
    fake_client = _FakeCloudTrailClient(pages=[{"Events": []}])
    fake_session = _FakeSession(fake_client)
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: fake_session,
        default_region="us-east-1",
    )
    q = TailQuery(
        role_name="r",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        aws_region="eu-west-1",
    )
    src.fetch_events(q)
    assert fake_session.client_args == [("cloudtrail", "eu-west-1")]


def test_fetch_events_includes_time_window_when_provided() -> None:
    fake_client = _FakeCloudTrailClient(pages=[{"Events": []}])
    src = CloudTrailLookupSource(
        boto3_session_factory=lambda: _FakeSession(fake_client),
    )
    q = TailQuery(
        role_name="r",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        since="2026-05-17T14:00:00Z",
        until="2026-05-17T15:00:00Z",
    )
    src.fetch_events(q)
    call = fake_client.calls[0]
    assert "StartTime" in call
    assert "EndTime" in call


def test_describe_mentions_lag_and_retention() -> None:
    src = CloudTrailLookupSource(default_region="us-east-1")
    desc = src.describe()
    assert "cloudtrail" in desc.lower()
    assert "lag" in desc.lower()
    assert "90d" in desc
