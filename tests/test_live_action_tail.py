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
    TailResult,
    extract_tail_inputs_from_grant,
    filter_events,
    format_event_summary,
    get_default_source,
    record_tail_read_in_history,
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
        # WB22 CRIT-22-01 closure: filter is on role_name (the IAM role
        # name from sessionIssuer.userName), NOT the per-assume
        # role-session-name.
        "role_name": "iam-jit-grant-1",
        "role_session_name": "alice-laptop",
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
    # WB22 CRIT-22-01: surface both role_name (filter target) and
    # role_session_name (audit context).
    assert d["role_name"] == "iam-jit-grant-1"
    assert d["role_session_name"] == "alice-laptop"
    assert "session_name" not in d  # renamed away from the misleading label


# ---------------------------------------------------------------------------
# NullLiveActionTailSource (default OSS source)
# ---------------------------------------------------------------------------


def _query(**overrides) -> TailQuery:
    defaults = {
        "role_name": "iam-jit-grant-1",
        "session_name": "iam-jit-provision-grant-1",
        "account_id": "111111111111",
    }
    defaults.update(overrides)
    return TailQuery(**defaults)


def test_null_source_returns_empty_ok_result() -> None:
    """WB22 TailResult shape: ok=True, events=()."""
    result = NullLiveActionTailSource().fetch_events(_query())
    assert isinstance(result, TailResult)
    assert result.ok is True
    assert result.events == ()
    assert result.error is None


def test_null_source_describe_mentions_unconfigured() -> None:
    assert "no live-action source configured" in NullLiveActionTailSource().describe()


# ---------------------------------------------------------------------------
# InMemoryLiveActionTailSource
# ---------------------------------------------------------------------------


def test_in_memory_source_filters_by_role_name_not_session_name() -> None:
    """WB22 CRIT-22-01 closure: filter is on role_name (the IAM role
    name from sessionIssuer.userName), NOT the user-chosen
    role_session_name."""
    src = InMemoryLiveActionTailSource(events=[
        _ev(role_name="iam-jit-grant-1", role_session_name="alice-laptop",
            event_time="2026-05-17T14:00:00Z"),
        _ev(role_name="iam-jit-grant-2", role_session_name="alice-laptop",
            event_time="2026-05-17T14:05:00Z"),
    ])
    out = src.fetch_events(_query()).events
    assert len(out) == 1
    assert out[0].role_name == "iam-jit-grant-1"


def test_in_memory_source_does_not_filter_by_role_session_name() -> None:
    """WB22 CRIT-22-01: end-user picks any RoleSessionName, so we must
    match regardless of what they pick. Same role_name + different
    role_session_names should all match."""
    src = InMemoryLiveActionTailSource(events=[
        _ev(role_name="iam-jit-grant-1", role_session_name="alice-laptop"),
        _ev(role_name="iam-jit-grant-1", role_session_name="alice-ci"),
        _ev(role_name="iam-jit-grant-1", role_session_name="random-suffix-xyz"),
    ])
    out = src.fetch_events(_query()).events
    assert len(out) == 3


def test_in_memory_source_filters_by_region() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(aws_region="us-east-1"),
        _ev(aws_region="eu-west-1"),
    ])
    out = src.fetch_events(_query(aws_region="us-east-1")).events
    assert all(e.aws_region == "us-east-1" for e in out)


def test_in_memory_source_sorts_descending_by_time() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_time="2026-05-17T14:00:00Z", event_name="A"),
        _ev(event_time="2026-05-17T14:10:00Z", event_name="B"),
        _ev(event_time="2026-05-17T14:05:00Z", event_name="C"),
    ])
    out = src.fetch_events(_query()).events
    assert [e.event_name for e in out] == ["B", "C", "A"]


def test_in_memory_source_respects_max_events() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_time=f"2026-05-17T14:0{i}:00Z", event_name=f"E{i}")
        for i in range(5)
    ])
    assert len(src.fetch_events(_query(max_events=2)).events) == 2


def test_in_memory_source_max_events_zero_returns_empty() -> None:
    src = InMemoryLiveActionTailSource(events=[_ev()])
    assert src.fetch_events(_query(max_events=0)).events == ()


def test_in_memory_source_only_errors_filters() -> None:
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_name="ok"),
        _ev(event_name="fail", error_code="AccessDenied"),
    ])
    out = src.fetch_events(_query(only_errors=True)).events
    assert len(out) == 1
    assert out[0].event_name == "fail"


def test_in_memory_source_role_name_none_matches_any() -> None:
    """An event with role_name=None is treated as match-any role
    (useful for manually instrumented test events)."""
    src = InMemoryLiveActionTailSource(events=[_ev(role_name=None)])
    assert len(src.fetch_events(_query()).events) == 1


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


# ---------------------------------------------------------------------------
# record_tail_read_in_history (WB22 HIGH-22-01 closure)
# ---------------------------------------------------------------------------


class _FakeStore:
    """In-memory dict store enough for tail-read audit tests."""

    def __init__(self) -> None:
        self.requests: dict[str, dict] = {}
        self.put_calls: list[tuple[str, dict]] = []

    def put(self, request_id: str, request: dict) -> None:
        self.put_calls.append((request_id, request))
        self.requests[request_id] = request


def _grant() -> dict:
    return {"metadata": {"id": "g1"}, "status": {"history": []}}


def test_record_tail_read_appends_history_entry() -> None:
    store = _FakeStore()
    grant = _grant()
    record_tail_read_in_history(
        store, grant,
        grant_id="g1",
        query=_query(),
        result_ok=True,
        event_count=7,
        actor="admin@example.com",
    )
    history = grant["status"]["history"]
    assert len(history) == 1
    entry = history[0]
    assert entry["kind"] == "tail_read"
    assert entry["actor"] == "admin@example.com"
    assert entry["event_count"] == 7
    assert entry["result_ok"] is True
    assert "at" in entry


def test_record_tail_read_persists_via_store_put() -> None:
    store = _FakeStore()
    grant = _grant()
    record_tail_read_in_history(
        store, grant,
        grant_id="g1", query=_query(), result_ok=True,
        event_count=0, actor="admin",
    )
    assert store.put_calls == [("g1", grant)]


def test_record_tail_read_handles_missing_history_list() -> None:
    """If status.history is missing entirely, helper initializes it."""
    store = _FakeStore()
    grant: dict = {"metadata": {"id": "g1"}}
    record_tail_read_in_history(
        store, grant,
        grant_id="g1", query=_query(), result_ok=True,
        event_count=0, actor="admin",
    )
    assert len(grant["status"]["history"]) == 1


def test_record_tail_read_failure_path_marked_in_audit() -> None:
    store = _FakeStore()
    grant = _grant()
    record_tail_read_in_history(
        store, grant,
        grant_id="g1", query=_query(), result_ok=False,
        event_count=0, actor="admin",
    )
    assert grant["status"]["history"][0]["result_ok"] is False


def test_record_tail_read_swallows_store_put_failure() -> None:
    """Store write failure must not raise — read already succeeded."""
    class FailingStore:
        def put(self, request_id, request):
            raise RuntimeError("ddb down")

    grant = _grant()
    # Must NOT raise:
    record_tail_read_in_history(
        FailingStore(), grant,
        grant_id="g1", query=_query(), result_ok=True,
        event_count=0, actor="admin",
    )
    # History still got the entry locally (caller can flush later)
    assert len(grant["status"]["history"]) == 1


@pytest.fixture(autouse=True)
def _reset_source_after_test():
    yield
    set_default_source(None)
