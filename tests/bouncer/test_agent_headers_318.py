"""#318 / §A16 — cross-bouncer X-Agent-* header parity for ibounce.

These tests cover the ibounce slice of cross-bouncer agent-attribution
parity: reading inbound `X-Agent-Name` + `X-Agent-Session-Id` headers,
validating them against the canonical Bounce-suite regexes, and
populating `unmapped.iam_jit.agent.{name, session_id, detected_from}`
on the OCSF audit event so `iam-jit audit query --filter
agent.session_id=X` returns ibounce events alongside gbounce ones.

Mirror tests live in kbouncer + dbounce + gbounce. Per
[[cross-product-agent-parity]] the four product test suites assert the
same canonical pattern. Per [[deliberate-feature-completion]] this
slice ships header reading + validation + counter + tests + doc
update together.
"""

from __future__ import annotations

import pytest

from iam_jit.bouncer.audit_export import (
    audit_event_from_decision,
    extract_agent_headers,
    is_valid_agent_name,
    is_valid_agent_session_id,
    reset_agent_headers_rejected_for_tests,
    reset_for_tests,
    total_agent_headers_rejected,
)
from iam_jit.bouncer.audit_export import agent_context as _agent_context


@pytest.fixture(autouse=True)
def _reset_state(tmp_path, monkeypatch):
    """Each test runs against a clean module-level slot + a fresh
    rejection counter so test ordering doesn't matter. The on-disk
    MCP-session state file is redirected under tmp_path so a leaked
    real MCP session can't poison a header-precedence assertion."""
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AGENT_SESSION_FILE",
        str(tmp_path / "active-mcp-session.json"),
    )
    reset_for_tests()
    reset_agent_headers_rejected_for_tests()
    yield
    reset_for_tests()
    reset_agent_headers_rejected_for_tests()


# ---------------------------------------------------------------------------
# Validator parity with gbounce
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,valid", [
    ("claude-code", True),
    ("cursor", True),
    ("openai-codex", True),
    ("devin", True),
    ("aider", True),
    ("a", True),
    ("gpt-4.1", True),
    ("my_agent.v2", True),
    ("a" * 64, True),
    ("a" * 65, False),
    ("", False),
    ("has spaces", False),
    ("dollar$sign", False),
    ("back`tick", False),
    ("semi;colon", False),
    ("pipe|symbol", False),
    ("path/sep", False),
    ("with\nnewline", False),
    ("quote'mark", False),
    ('double"quote', False),
])
def test_is_valid_agent_name_matches_gbounce_regex(name, valid):
    """Mirror of gbounce's `IsValidAgentName` regex [A-Za-z0-9._-]{1,64}.
    Cross-product validator parity is the load-bearing invariant — a
    name accepted by ibounce must be accepted by every other Bounce
    + a name rejected by ibounce must be rejected everywhere else."""
    assert is_valid_agent_name(name) is valid


@pytest.mark.parametrize("sid,valid", [
    # UUID v4 (most common today)
    ("01968d6a-9c12-4a4b-b6f8-3b8e4c0d1aef", True),
    # UUID v7 (time-ordered, recommended)
    ("01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef", True),
    # Bare alphanumeric
    ("abc123", True),
    ("a", True),
    ("a" * 128, True),
    # Boundaries + invalid
    ("a" * 129, False),
    ("", False),
    ("has spaces", False),
    ("with.dot", False),  # session_id is stricter than name — no dots
    ("dollar$", False),
    ("path/sep", False),
])
def test_is_valid_agent_session_id_matches_gbounce_regex(sid, valid):
    """Mirror of gbounce's `IsValidSessionID` regex [A-Za-z0-9_-]{1,128}."""
    assert is_valid_agent_session_id(sid) is valid


# ---------------------------------------------------------------------------
# extract_agent_headers — happy path + rejection counter
# ---------------------------------------------------------------------------


def test_extract_agent_headers_happy_path_both_present():
    """Both headers present + valid → both come back populated."""
    name, sid = extract_agent_headers({
        "X-Agent-Name": "claude-code",
        "X-Agent-Session-Id": "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
    })
    assert name == "claude-code"
    assert sid == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    # No rejections counted on the happy path.
    assert total_agent_headers_rejected() == 0


def test_extract_agent_headers_case_insensitive_lookup():
    """HTTP header lookup must be case-insensitive — clients commonly
    send `x-agent-name` lowercased."""
    name, sid = extract_agent_headers({
        "x-agent-name": "cursor",
        "x-agent-session-id": "abc123",
    })
    assert name == "cursor"
    assert sid == "abc123"


def test_extract_agent_headers_none_present_returns_none_pair():
    """Empty / missing headers → (None, None). Counter stays zero."""
    assert extract_agent_headers({}) == (None, None)
    assert extract_agent_headers(None) == (None, None)
    assert extract_agent_headers({"User-Agent": "boto3"}) == (None, None)
    assert total_agent_headers_rejected() == 0


def test_extract_agent_headers_invalid_name_rejected_and_counted():
    """Invalid X-Agent-Name → returned as None + counter bumps + the
    valid session_id still passes through. Mirrors gbounce's pattern:
    one bad header doesn't poison the other."""
    name, sid = extract_agent_headers({
        "X-Agent-Name": "bad agent; rm -rf /",  # spaces + shell chars
        "X-Agent-Session-Id": "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
    })
    assert name is None
    assert sid == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    assert total_agent_headers_rejected() == 1


def test_extract_agent_headers_invalid_session_id_rejected_and_counted():
    """Invalid X-Agent-Session-Id → returned as None + counter bumps."""
    name, sid = extract_agent_headers({
        "X-Agent-Name": "claude-code",
        "X-Agent-Session-Id": "not a session id with spaces",
    })
    assert name == "claude-code"
    assert sid is None
    assert total_agent_headers_rejected() == 1


def test_extract_agent_headers_both_invalid_double_count():
    """Both headers invalid → both rejected + counter bumps TWICE."""
    name, sid = extract_agent_headers({
        "X-Agent-Name": "$shell injection`",
        "X-Agent-Session-Id": "also; bad",
    })
    assert name is None
    assert sid is None
    assert total_agent_headers_rejected() == 2


# ---------------------------------------------------------------------------
# resolve_agent_block — header precedence
# ---------------------------------------------------------------------------


def test_resolve_agent_block_header_wins_over_user_agent():
    """Header detection always beats User-Agent fingerprinting per
    [[cross-product-agent-parity]]. An agent that explicitly declares
    itself via X-Agent-Name must surface as `detected_from=http_header`
    even when the User-Agent looks like boto3/etc."""
    block = _agent_context.resolve_agent_block(
        user_agent="Boto3/1.34.5 Python/3.12",
        header_agent_name="claude-code",
        header_agent_session_id="01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
    )
    assert block is not None
    assert block["name"] == "claude-code"
    assert block["session_id"] == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    assert block["detected_from"] == "http_header"


def test_resolve_agent_block_header_name_only_partial_detection():
    """Name valid + session_id absent → `detected_from=
    http_header_name_only` so SIEM filters can distinguish full from
    partial header attribution."""
    block = _agent_context.resolve_agent_block(
        header_agent_name="claude-code",
        header_agent_session_id=None,
    )
    assert block is not None
    assert block["name"] == "claude-code"
    assert block["session_id"] is None
    assert block["detected_from"] == "http_header_name_only"


def test_resolve_agent_block_no_headers_falls_back_to_user_agent():
    """No X-Agent-* headers → existing User-Agent detection path
    fires unchanged. Cross-product invariant: header is ADDITIVE; the
    pre-#318 detection chain stays intact when no header is supplied."""
    block = _agent_context.resolve_agent_block(
        user_agent="claude-code/1.2.3 (python-httpx)",
    )
    assert block is not None
    assert block["name"] == "claude-code"
    assert block["detected_from"] == "user_agent"
    # Session id is None — UA detection doesn't carry a session.
    assert block["session_id"] is None


def test_resolve_agent_block_session_id_only_minimal_anonymous_block():
    """An agent that sends ONLY X-Agent-Session-Id (no name, no UA, no
    MCP, no PID) still gets a minimal anonymous block carrying the
    session_id so cross-bouncer correlation works. Per
    [[cross-product-agent-parity]]: don't drop the session_id just
    because we don't know the agent's name."""
    block = _agent_context.resolve_agent_block(
        header_agent_name=None,
        header_agent_session_id="01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
    )
    assert block is not None
    assert block["name"] == "anonymous"
    assert block["session_id"] == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    assert block["detected_from"] == "unknown"


def test_resolve_agent_block_session_id_overlays_ua_block():
    """An agent that sends X-Agent-Session-Id alongside a recognised UA
    (no X-Agent-Name) → the session_id overlays the UA-detected block
    so cross-bouncer correlation works AND we still pick up the
    canonical name from the UA. Detection source stays user_agent —
    that's where the name came from."""
    block = _agent_context.resolve_agent_block(
        user_agent="Boto3/1.34.5 Python/3.12",
        header_agent_session_id="01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
    )
    assert block is not None
    assert block["name"] == "aws-sdk-python"
    assert block["session_id"] == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    assert block["detected_from"] == "user_agent"


# ---------------------------------------------------------------------------
# Integration with audit_event_from_decision
# ---------------------------------------------------------------------------


def test_audit_event_from_decision_populates_agent_block_from_header():
    """End-to-end: when proxy.py extracts the headers + threads them
    through, `audit_event_from_decision` produces an event with
    `unmapped.iam_jit.agent.{name, session_id, detected_from}` set so
    the SIEM-side `agent.session_id=X` filter resolves."""
    ev = audit_event_from_decision(
        decision_id=1,
        mode="transparent",
        profile=None,
        verdict="allow",
        reason="",
        service="s3",
        action="ListBuckets",
        arn=None,
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        header_agent_name="parity-test",
        header_agent_session_id="01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
    )
    agent = ev["unmapped"]["iam_jit"]["agent"]
    assert agent["name"] == "parity-test"
    assert agent["session_id"] == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    assert agent["detected_from"] == "http_header"


# ---------------------------------------------------------------------------
# §A16 cross-product test name parity
# ---------------------------------------------------------------------------
#
# These are alias names that mirror gbounce / kbounce / dbounce's
# canonical test method names so the cross-product test discovery
# (per [[cross-product-agent-parity]]) finds an equivalent assertion
# under each product's test directory.


def test_AgentHeaders_HappyPath():
    """#318 canonical: both headers present + valid → populated."""
    name, sid = extract_agent_headers({
        "X-Agent-Name": "parity-test",
        "X-Agent-Session-Id": "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
    })
    assert name == "parity-test"
    assert sid == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"


def test_AgentHeaders_NoHeaders_FallbackToUserAgent():
    """#318 canonical: no X-Agent-* headers → existing UA-based
    detection unchanged."""
    block = _agent_context.resolve_agent_block(
        user_agent="claude-code/1.2.3",
    )
    assert block is not None
    assert block["name"] == "claude-code"
    assert block["detected_from"] == "user_agent"


def test_AgentHeaders_InvalidName_Rejected():
    """#318 canonical: invalid characters → counter bumps + no field
    populated. Mirrors gbounce's TestProxy_InvalidAgentHeaders_Rejected."""
    before = total_agent_headers_rejected()
    name, _ = extract_agent_headers({
        "X-Agent-Name": "bad name with spaces",
    })
    assert name is None
    assert total_agent_headers_rejected() == before + 1


def test_AgentHeaders_NameOnly_PartialDetection():
    """#318 canonical: name valid + session_id absent →
    `detected_from=http_header_name_only`."""
    block = _agent_context.resolve_agent_block(
        header_agent_name="parity-test",
    )
    assert block is not None
    assert block["name"] == "parity-test"
    assert block["session_id"] is None
    assert block["detected_from"] == "http_header_name_only"


# ---------------------------------------------------------------------------
# #320 / §A18 — structured agent-header rejection breadcrumb
# ---------------------------------------------------------------------------


def test_320_extract_agent_headers_with_rejections_charset_failure():
    """Invalid name (charset) → rejection breadcrumb names the field +
    reason `invalid_name_charset` + length."""
    _agent_context.reset_agent_headers_rejected_for_tests()
    raw = "bad agent; rm -rf /"
    name, sid, rejections = (
        _agent_context.extract_agent_headers_with_rejections({
            "X-Agent-Name": raw,
        })
    )
    assert name is None
    assert sid is None
    assert len(rejections) == 1
    assert rejections[0]["field"] == "X-Agent-Name"
    assert rejections[0]["reason"] == "invalid_name_charset"
    assert rejections[0]["value_redacted_length"] == len(raw)
    # Raw value NEVER appears in the breadcrumb.
    assert raw not in str(rejections[0])


def test_320_extract_agent_headers_with_rejections_length_failure():
    """Over-length session_id (charset OK) → `invalid_session_id_length`."""
    _agent_context.reset_agent_headers_rejected_for_tests()
    over = "a" * 129  # 129 > 128 cap
    name, sid, rejections = (
        _agent_context.extract_agent_headers_with_rejections({
            "X-Agent-Session-Id": over,
        })
    )
    assert sid is None
    assert len(rejections) == 1
    assert rejections[0]["field"] == "X-Agent-Session-Id"
    assert rejections[0]["reason"] == "invalid_session_id_length"
    assert rejections[0]["value_redacted_length"] == 129


def test_320_extract_agent_headers_with_rejections_both_failed():
    """Both headers invalid → two breadcrumbs, each with its own reason."""
    _agent_context.reset_agent_headers_rejected_for_tests()
    _, _, rejections = (
        _agent_context.extract_agent_headers_with_rejections({
            "X-Agent-Name": "$shell injection`",
            "X-Agent-Session-Id": "also; bad spaces",
        })
    )
    assert len(rejections) == 2
    fields = {r["field"] for r in rejections}
    assert fields == {"X-Agent-Name", "X-Agent-Session-Id"}


def test_320_audit_event_carries_rejection_breadcrumb():
    """audit_event_from_decision plumbs `agent_header_rejections` into
    `unmapped.iam_jit.ext.agent_header_rejection`. Single dict shape
    when one header failed."""
    from iam_jit.bouncer.audit_export.event import audit_event_from_decision
    raw = "$bad`name"
    _, _, rejections = (
        _agent_context.extract_agent_headers_with_rejections({
            "X-Agent-Name": raw,
        })
    )
    ev = audit_event_from_decision(
        decision_id=1,
        mode="enforce",
        profile=None,
        verdict="allow",
        reason="",
        service="s3",
        action="GetObject",
        arn=None,
        region="us-east-1",
        host="s3.amazonaws.com",
        agent_header_rejections=rejections,
    )
    breadcrumb = ev["unmapped"]["iam_jit"]["ext"]["agent_header_rejection"]
    # Single-failure shape: dict (not list).
    assert isinstance(breadcrumb, dict)
    assert breadcrumb["field"] == "X-Agent-Name"
    assert breadcrumb["reason"] == "invalid_name_charset"
    assert breadcrumb["value_redacted_length"] == len(raw)
    # Raw value MUST NOT appear anywhere in the event JSON.
    import json
    assert raw not in json.dumps(ev)


def test_320_audit_event_carries_multiple_rejection_breadcrumbs():
    """Both headers invalid → `agent_header_rejection` is a LIST."""
    from iam_jit.bouncer.audit_export.event import audit_event_from_decision
    _, _, rejections = (
        _agent_context.extract_agent_headers_with_rejections({
            "X-Agent-Name": "bad name with spaces",
            "X-Agent-Session-Id": "also bad",
        })
    )
    ev = audit_event_from_decision(
        decision_id=1,
        mode="enforce",
        profile=None,
        verdict="allow",
        reason="",
        service="s3",
        action="GetObject",
        arn=None,
        region="us-east-1",
        host="s3.amazonaws.com",
        agent_header_rejections=rejections,
    )
    breadcrumb = ev["unmapped"]["iam_jit"]["ext"]["agent_header_rejection"]
    assert isinstance(breadcrumb, list)
    assert len(breadcrumb) == 2
