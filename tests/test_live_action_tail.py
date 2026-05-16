"""Tests for the live-action-tail OSS scaffolding (#157).

Per [[live-action-tail-pro-tier]]: the OSS foundation defines the
data model, source abstraction, formatters, in-memory stub source,
and the CloudTrail boto3 source. The Enterprise plugin (post-launch)
layers EventBridge streaming + web UI + multi-account aggregation
on top.
"""

from __future__ import annotations

import pytest

from iam_jit.live_action_tail import (
    InMemoryLiveActionTailSource,
    LiveActionEvent,
    NullLiveActionTailSource,
    TailQuery,
    extract_tail_inputs_from_grant,
    filter_events,
    format_event_summary,
    get_default_source,
    set_default_source,
)


# ---------------------------------------------------------------------------
# LiveActionEvent data model
# ---------------------------------------------------------------------------


def _ev(**overrides) -> LiveActionEvent:
    defaults: dict = {
        "event_time": "2026-05-17T14:23:18Z",
        "event_name": "GetObject",
        "event_source": "s3.amazonaws.com",
        "aws_region": "us-east-1",
        "session_name": "iam-jit-provision-req-1",
    }
    defaults.update(overrides)
    return LiveActionEvent(**defaults)


def test_event_action_combines_service_and_name() -> None:
    assert _ev().action == "s3:GetObject"


def test_event_action_handles_missing_source() -> None:
    assert _ev(event_source="").action == ""


def test_event_succeeded_default_true() -> None:
    assert _ev().succeeded is True


def test_event_succeeded_false_when_error_code_set() -> None:
    assert _ev(error_code="AccessDenied").succeeded is False


def test_event_to_dict_round_trip() -> None:
    d = _ev(error_code="AccessDenied", resources=("arn:aws:s3:::b/k",)).to_dict()
    assert d["action"] == "s3:GetObject"
    assert d["succeeded"] is False
    assert d["resources"] == ["arn:aws:s3:::b/k"]


# ---------------------------------------------------------------------------
# NullLiveActionTailSource (default OSS source)
# ---------------------------------------------------------------------------


def _query() -> TailQuery:
    return TailQuery(
        role_name="iam-jit-req-1",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
    )


def test_null_source_returns_empty() -> None:
    assert NullLiveActionTailSource().fetch_events(_query()) == []


def test_null_source_describe_mentions_unconfigured() -> None:
    assert "no live-action source configured" in NullLiveActionTailSource().describe()


# ---------------------------------------------------------------------------
# InMemoryLiveActionTailSource
# ---------------------------------------------------------------------------


def test_in_memory_source_filters_by_session() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(session_name="iam-jit-provision-req-1", event_time="2026-05-17T14:00:00Z"),
        _ev(session_name="iam-jit-provision-req-2", event_time="2026-05-17T14:05:00Z"),
    ])
    out = src.fetch_events(_query())
    assert len(out) == 1
    assert out[0].session_name == "iam-jit-provision-req-1"


def test_in_memory_source_filters_by_region() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(aws_region="us-east-1"),
        _ev(aws_region="eu-west-1"),
    ])
    q = TailQuery(
        role_name="iam-jit-req-1",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        aws_region="us-east-1",
    )
    out = src.fetch_events(q)
    assert all(e.aws_region == "us-east-1" for e in out)


def test_in_memory_source_sorts_descending_by_time() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_time="2026-05-17T14:00:00Z", event_name="A"),
        _ev(event_time="2026-05-17T14:10:00Z", event_name="B"),
        _ev(event_time="2026-05-17T14:05:00Z", event_name="C"),
    ])
    out = src.fetch_events(_query())
    assert [e.event_name for e in out] == ["B", "C", "A"]


def test_in_memory_source_respects_max_events() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_time=f"2026-05-17T14:0{i}:00Z", event_name=f"E{i}")
        for i in range(5)
    ])
    q = TailQuery(
        role_name="iam-jit-req-1",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        max_events=2,
    )
    assert len(src.fetch_events(q)) == 2


def test_in_memory_source_max_events_zero_returns_empty() -> None:
    src = InMemoryLiveActionTailSource(events=[_ev()])
    q = TailQuery(
        role_name="iam-jit-req-1",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        max_events=0,
    )
    assert src.fetch_events(q) == []


def test_in_memory_source_only_errors_filters() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_name="ok"),
        _ev(event_name="fail", error_code="AccessDenied"),
    ])
    q = TailQuery(
        role_name="iam-jit-req-1",
        session_name="iam-jit-provision-req-1",
        account_id="111111111111",
        only_errors=True,
    )
    out = src.fetch_events(q)
    assert len(out) == 1
    assert out[0].event_name == "fail"


def test_in_memory_source_session_none_matches_any() -> None:
    """An event with session_name=None is treated as match-any session
    (useful for manually instrumented test events)."""
    src = InMemoryLiveActionTailSource(events=[_ev(session_name=None)])
    assert len(src.fetch_events(_query())) == 1


# ---------------------------------------------------------------------------
# format_event_summary
# ---------------------------------------------------------------------------


def test_format_event_summary_ok() -> None:
    out = format_event_summary(_ev())
    assert "14:23:18Z" in out
    assert "OK" in out
    assert "s3:GetObject" in out
    assert "us-east-1" in out


def test_format_event_summary_failure_shows_error_code() -> None:
    out = format_event_summary(_ev(error_code="AccessDenied"))
    assert "FAIL[AccessDenied]" in out


def test_format_event_summary_truncates_long_resource_list() -> None:
    out = format_event_summary(_ev(resources=("a", "b", "c", "d")))
    assert "+ 3 more" in out


def test_format_event_summary_handles_two_resources_inline() -> None:
    out = format_event_summary(_ev(resources=("a", "b")))
    assert "a, b" in out
    assert "more" not in out


def test_format_event_summary_handles_malformed_time() -> None:
    out = format_event_summary(_ev(event_time="not-a-time"))
    # Should not crash; fall back to literal
    assert "not-a-time" in out or "??:??:??Z" in out


# ---------------------------------------------------------------------------
# filter_events
# ---------------------------------------------------------------------------


def test_filter_events_no_filters_returns_input() -> None:
    e = [_ev(), _ev(event_name="x")]
    assert filter_events(e) == e


def test_filter_events_since_bound() -> None:
    a = _ev(event_time="2026-05-17T14:00:00Z")
    b = _ev(event_time="2026-05-17T15:00:00Z")
    assert filter_events([a, b], since="2026-05-17T14:30:00Z") == [b]


def test_filter_events_until_bound() -> None:
    a = _ev(event_time="2026-05-17T14:00:00Z")
    b = _ev(event_time="2026-05-17T15:00:00Z")
    assert filter_events([a, b], until="2026-05-17T14:30:00Z") == [a]


def test_filter_events_only_errors() -> None:
    a = _ev()
    b = _ev(error_code="X")
    assert filter_events([a, b], only_errors=True) == [b]


def test_filter_events_action_prefix() -> None:
    a = _ev()  # s3:GetObject
    b = _ev(event_name="GetObject", event_source="iam.amazonaws.com")
    out = filter_events([a, b], action_prefix="s3:")
    assert out == [a]


# ---------------------------------------------------------------------------
# extract_tail_inputs_from_grant
# ---------------------------------------------------------------------------


def _grant_request(provisioned: dict | None) -> dict:
    return {
        "metadata": {"id": "req-1"},
        "status": {"provisioned": provisioned} if provisioned is not None else {},
    }


def test_extract_returns_none_when_not_provisioned() -> None:
    assert extract_tail_inputs_from_grant(_grant_request(None)) is None


def test_extract_returns_none_when_missing_fields() -> None:
    assert extract_tail_inputs_from_grant(_grant_request({"role_name": "x"})) is None


def test_extract_returns_query_for_complete_grant() -> None:
    q = extract_tail_inputs_from_grant(_grant_request({
        "role_name": "iam-jit-req-1",
        "session_name": "iam-jit-provision-req-1",
        "account_id": "111111111111",
        "expires_at": "2026-05-17T20:00:00Z",
        "tags": {"provisioned-at": "2026-05-17T14:00:00Z"},
    }))
    assert q is not None
    assert q.role_name == "iam-jit-req-1"
    assert q.session_name == "iam-jit-provision-req-1"
    assert q.account_id == "111111111111"
    assert q.since == "2026-05-17T14:00:00Z"
    assert q.until == "2026-05-17T20:00:00Z"


def test_extract_falls_back_to_history_when_no_tag() -> None:
    req = _grant_request({
        "role_name": "iam-jit-req-1",
        "session_name": "iam-jit-provision-req-1",
        "account_id": "111111111111",
    })
    req["status"]["history"] = [
        {"to_state": "active", "at": "2026-05-17T13:30:00Z"}
    ]
    q = extract_tail_inputs_from_grant(req)
    assert q is not None
    assert q.since == "2026-05-17T13:30:00Z"


def test_extract_handles_non_dict_input() -> None:
    assert extract_tail_inputs_from_grant("not-a-dict") is None  # type: ignore[arg-type]
    assert extract_tail_inputs_from_grant(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------


def test_get_default_source_initializes_to_null() -> None:
    set_default_source(None)
    src = get_default_source()
    assert isinstance(src, NullLiveActionTailSource)


def test_set_default_source_swaps_in_a_real_source() -> None:
    stub = InMemoryLiveActionTailSource(events=[_ev()])
    set_default_source(stub)
    try:
        assert get_default_source() is stub
    finally:
        set_default_source(None)


@pytest.fixture(autouse=True)
def _reset_source_after_test():
    yield
    set_default_source(None)
