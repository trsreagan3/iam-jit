"""#266 — agent identity + persistent session ID in audit-export.

Per [[agent-identity-in-audit]] the OCSF event grows an
`unmapped.iam_jit.agent` block carrying:
  * `name` (canonical agent name: claude-code, cursor, ...)
  * `version` (best-effort, None when not extractable)
  * `session_id` (UUID v7 minted at MCP connect; None for non-MCP calls)
  * `detected_from` (mcp_clientinfo | user_agent | user_agent_raw |
                     process_tree | unknown)

These tests cover:
  - MCP clientInfo capture + propagation
  - User-Agent -> canonical-name mapping (known and unknown)
  - Process-tree fallback via mocked _ppid / _exe_name
  - Session ID uniqueness, lifecycle, and SESSION_ENDED bookend
  - OCSF event omits the agent block cleanly when no detection fires
  - Cross-product schema parity (agent block has same shape across
    ibounce/kbounce/dbounce since it's built from the shared
    agent_context module)
"""

from __future__ import annotations

import json

import pytest

from iam_jit.bouncer.audit_export import (
    audit_event_from_decision,
    begin_mcp_session,
    detect_from_process_tree,
    detect_from_user_agent,
    end_mcp_session,
    reset_for_tests,
    resolve_agent_block,
    session_ended_event,
)
from iam_jit.bouncer.audit_export import agent_context as _agent_context


@pytest.fixture(autouse=True)
def _reset_agent_context(tmp_path, monkeypatch):
    """Each test gets a clean module-level slot; the MCP session store
    is process-global by design (one stdio process = one session).

    Per #287: also redirect the on-disk session-state file under tmp_path
    so tests don't pollute the operator's real `~/.iam-jit/` and so the
    cross-process pickup path can be exercised deterministically.
    """
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AGENT_SESSION_FILE",
        str(tmp_path / "active-mcp-session.json"),
    )
    reset_for_tests()
    yield
    reset_for_tests()


# ---------------------------------------------------------------------------
# Feature 1 — MCP clientInfo capture
# ---------------------------------------------------------------------------


def test_begin_mcp_session_records_clientinfo_and_mints_session_id():
    session = begin_mcp_session({"name": "claude-code", "version": "1.2.3"})
    assert session.name == "claude-code"
    assert session.version == "1.2.3"
    assert session.detected_from == "mcp_clientinfo"
    # UUID v7 (or v4 fallback) — 36-char canonical form.
    assert len(session.session_id) == 36
    assert session.session_id.count("-") == 4


def test_begin_mcp_session_with_no_clientinfo_records_unknown():
    """Older MCP clients may not send clientInfo. We still mint a
    session ID so subsequent audit events can be correlated; the
    name lands as 'unknown' per [[scorer-is-ground-truth]] (we
    don't invent a name)."""
    session = begin_mcp_session(None)
    assert session.name == "unknown"
    assert session.version is None
    assert session.session_id
    assert session.detected_from == "mcp_clientinfo"


def test_active_agent_session_returns_current():
    assert _agent_context.active_agent_session() is None
    s = begin_mcp_session({"name": "cursor", "version": "0.45.0"})
    assert _agent_context.active_agent_session() == s


def test_reinitialize_replaces_session():
    """Per the memo: each MCP `initialize` mints a fresh session_id;
    reconnect = new session (state-loss signal)."""
    first = begin_mcp_session({"name": "claude-code", "version": "1.0"})
    second = begin_mcp_session({"name": "claude-code", "version": "1.1"})
    assert first.session_id != second.session_id
    assert _agent_context.active_agent_session() == second


def test_ocsf_event_includes_agent_block_when_mcp_session_active():
    """Once an MCP session is bound, every audit_event_from_decision
    call surfaces it under unmapped.iam_jit.agent."""
    session = begin_mcp_session({"name": "claude-code", "version": "1.5.0"})
    event = audit_event_from_decision(
        decision_id=1,
        mode="transparent",
        profile=None,
        verdict="allow",
        reason="ok",
        service="s3",
        action="GetObject",
        arn="arn:aws:s3:::data/file.json",
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
    )
    agent = event["unmapped"]["iam_jit"]["agent"]
    assert agent["name"] == "claude-code"
    assert agent["version"] == "1.5.0"
    assert agent["session_id"] == session.session_id
    assert agent["detected_from"] == "mcp_clientinfo"


# ---------------------------------------------------------------------------
# Feature 1 — User-Agent mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ua,expected_name",
    [
        ("claude-code/1.2.3 (darwin; arm64)", "claude-code"),
        ("Cursor/0.45 (macOS)", "cursor"),
        ("devin-runtime/2026.05", "devin"),
        ("codex-cli/0.9.0", "codex"),
        ("Boto3/1.34.5 Python/3.12 Linux/6.5", "aws-sdk-python"),
        ("aws-cli/2.15.0 Python/3.11.0 Linux", "aws-cli"),
        ("aws-sdk-js/3.0.0 nodejs/v20.0.0", "aws-sdk-js"),
    ],
)
def test_detect_from_user_agent_known_patterns(ua, expected_name):
    block = detect_from_user_agent(ua)
    assert block is not None
    assert block["name"] == expected_name
    assert block["detected_from"] == "user_agent"


def test_detect_from_user_agent_unknown_records_raw():
    """Unknown UAs surface raw under user_agent_raw — SIEM filters
    can still grep on the raw string per [[scorer-is-ground-truth]]."""
    block = detect_from_user_agent("WeirdCustomClient/0.0.1")
    assert block is not None
    assert block["name"] == "unknown"
    assert block["detected_from"] == "user_agent_raw"
    assert block["raw_ua"] == "WeirdCustomClient/0.0.1"


def test_detect_from_user_agent_none_returns_none():
    assert detect_from_user_agent(None) is None
    assert detect_from_user_agent("") is None


def test_detect_from_user_agent_extracts_version_when_present():
    block = detect_from_user_agent("claude-code/1.2.3 (darwin)")
    assert block["version"] == "1.2.3"


def test_detect_from_user_agent_raw_truncates_long_strings():
    """Pathological UAs (some SDKs concat OS/arch/runtime) are
    truncated at 256 chars so we don't ship unbounded data through
    the audit channel."""
    long_ua = "MysteryAgent/" + ("x" * 5000)
    block = detect_from_user_agent(long_ua)
    assert block["name"] == "unknown"
    assert len(block["raw_ua"]) <= 256


# ---------------------------------------------------------------------------
# Feature 1 — process-tree fallback (mocked, platform-agnostic)
# ---------------------------------------------------------------------------


def test_detect_from_process_tree_walks_to_known_agent(monkeypatch):
    """Walk from PID 1000 -> 999 -> 1 -> stop. Middle ancestor
    matches `claude-code` so we report a process_tree hit."""
    parents = {1000: 999, 999: 1, 1: 0}
    exes = {1000: "python", 999: "claude-code-helper", 1: "init"}

    monkeypatch.setattr(_agent_context, "_ppid", lambda pid: parents.get(pid))
    monkeypatch.setattr(_agent_context, "_exe_name", lambda pid: exes.get(pid))

    block = detect_from_process_tree(1000)
    assert block is not None
    assert block["name"] == "claude-code"
    assert block["detected_from"] == "process_tree"
    assert block["process_tree_info"]["matched_pid"] == 999
    assert block["process_tree_info"]["matched_exe"] == "claude-code-helper"


def test_detect_from_process_tree_no_match_returns_none(monkeypatch):
    parents = {500: 1, 1: 0}
    exes = {500: "python", 1: "init"}
    monkeypatch.setattr(_agent_context, "_ppid", lambda pid: parents.get(pid))
    monkeypatch.setattr(_agent_context, "_exe_name", lambda pid: exes.get(pid))
    assert detect_from_process_tree(500) is None


def test_detect_from_process_tree_pid_zero_short_circuits():
    assert detect_from_process_tree(0) is None
    assert detect_from_process_tree(None) is None


def test_detect_from_process_tree_handles_walker_errors(monkeypatch):
    """_ppid returning None at the start means we still get a chain
    of length 1 (the seed PID); no recognisable exe -> None."""
    monkeypatch.setattr(_agent_context, "_ppid", lambda pid: None)
    monkeypatch.setattr(_agent_context, "_exe_name", lambda pid: "python")
    assert detect_from_process_tree(1234) is None


# ---------------------------------------------------------------------------
# Feature 2 — persistent session ID lifecycle + uniqueness
# ---------------------------------------------------------------------------


def test_session_id_unique_across_sessions():
    ids = set()
    for i in range(50):
        s = begin_mcp_session({"name": "claude-code", "version": str(i)})
        ids.add(s.session_id)
        # Don't end them — we WANT to test that each mint is unique
        # even when overwriting the active slot.
    assert len(ids) == 50


def test_end_mcp_session_retires_and_returns_prior():
    s = begin_mcp_session({"name": "cursor", "version": "0.45"})
    prior = end_mcp_session()
    assert prior == s
    assert _agent_context.active_agent_session() is None
    # Idempotent: second end returns None.
    assert end_mcp_session() is None


def test_session_ended_event_structure():
    """SESSION_ENDED is an OCSF-shaped synthetic; one query field
    (`unmapped.iam_jit.event_type == "SESSION_ENDED"`) picks them
    out, mirroring AUDIT_DROPPED."""
    s = begin_mcp_session({"name": "claude-code", "version": "1.2.3"})
    event = session_ended_event(s)
    assert event["class_uid"] == 6003
    assert event["category_uid"] == 6
    assert event["severity"] == "Informational"
    assert event["unmapped"]["iam_jit"]["event_type"] == "SESSION_ENDED"
    agent = event["unmapped"]["iam_jit"]["agent"]
    assert agent["session_id"] == s.session_id
    assert agent["name"] == "claude-code"
    assert agent["version"] == "1.2.3"
    assert agent["detected_from"] == "mcp_clientinfo"


# ---------------------------------------------------------------------------
# OCSF event integration
# ---------------------------------------------------------------------------


def test_ocsf_event_omits_agent_block_when_no_detection_signal():
    """Raw boto3 from a script with no MCP and no User-Agent: the
    agent block is OMITTED (not synthesised) so downstream filters
    see "no agent identity" rather than "unknown agent identity"
    for this honest case."""
    event = audit_event_from_decision(
        decision_id=42,
        mode="transparent",
        profile=None,
        verdict="allow",
        reason="ok",
        service="ec2",
        action="DescribeInstances",
        arn=None,
        region="us-east-1",
        host="ec2.us-east-1.amazonaws.com",
    )
    assert "agent" not in event["unmapped"]["iam_jit"]


def test_ocsf_event_agent_block_from_user_agent_only():
    """Non-MCP call (raw boto3) with a recognisable User-Agent:
    agent block fires from the UA path with session_id=None."""
    event = audit_event_from_decision(
        decision_id=43,
        mode="cooperative",
        profile=None,
        verdict="allow",
        reason="ok",
        service="s3",
        action="GetObject",
        arn=None,
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        user_agent="Boto3/1.34.5 Python/3.12 Linux",
    )
    agent = event["unmapped"]["iam_jit"]["agent"]
    assert agent["name"] == "aws-sdk-python"
    assert agent["detected_from"] == "user_agent"
    assert agent["session_id"] is None


def test_ocsf_event_agent_block_unknown_user_agent():
    event = audit_event_from_decision(
        decision_id=44,
        mode="transparent",
        profile=None,
        verdict="allow",
        reason="ok",
        service="ec2",
        action="DescribeInstances",
        arn=None,
        region="us-east-1",
        host="ec2.us-east-1.amazonaws.com",
        user_agent="MyCustomTool/2.0",
    )
    agent = event["unmapped"]["iam_jit"]["agent"]
    assert agent["name"] == "unknown"
    assert agent["detected_from"] == "user_agent_raw"
    assert agent["raw_ua"] == "MyCustomTool/2.0"


def test_ocsf_event_mcp_clientinfo_wins_over_user_agent():
    """Priority order per memo: mcp_clientinfo > user_agent > process_tree.
    A divergent UA gets surfaced as a side-tag so reviewers can spot
    the agent-spawns-subprocess case."""
    begin_mcp_session({"name": "claude-code", "version": "1.5.0"})
    event = audit_event_from_decision(
        decision_id=45,
        mode="transparent",
        profile=None,
        verdict="allow",
        reason="ok",
        service="s3",
        action="GetObject",
        arn=None,
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        user_agent="Boto3/1.34.5 Python/3.12 Linux",
    )
    agent = event["unmapped"]["iam_jit"]["agent"]
    assert agent["name"] == "claude-code"
    assert agent["detected_from"] == "mcp_clientinfo"
    # The divergent UA surfaces as a side-tag.
    assert agent.get("user_agent_name") == "aws-sdk-python"


def test_ocsf_event_serialises_to_json():
    """The whole event (with agent block) must round-trip through
    json.dumps — webhook + JSONL log both serialise via stdlib json."""
    begin_mcp_session({"name": "claude-code", "version": "1.0"})
    event = audit_event_from_decision(
        decision_id=46,
        mode="transparent",
        profile=None,
        verdict="deny",
        reason="rule#1",
        service="iam",
        action="DeleteRole",
        arn="arn:aws:iam::123456789012:role/admin",
        region="us-east-1",
        host="iam.amazonaws.com",
        enforced=True,
    )
    blob = json.dumps(event)
    parsed = json.loads(blob)
    assert parsed["unmapped"]["iam_jit"]["agent"]["name"] == "claude-code"


# ---------------------------------------------------------------------------
# Cross-product schema parity
# ---------------------------------------------------------------------------


def test_agent_block_schema_parity_when_detected():
    """Per the memo's cross-product contract: when agent detection
    fires, the block ALWAYS has {name, version, session_id,
    detected_from}. The four keys are the cross-product contract;
    extra keys (process_tree_info, raw_ua, user_agent_name) are
    optional per-path."""
    required_keys = {"name", "version", "session_id", "detected_from"}

    # mcp_clientinfo path
    begin_mcp_session({"name": "claude-code", "version": "1.0"})
    block_mcp = resolve_agent_block()
    assert required_keys <= set(block_mcp.keys())
    reset_for_tests()

    # user_agent path
    block_ua = resolve_agent_block(user_agent="claude-code/1.0")
    assert required_keys <= set(block_ua.keys())

    # user_agent_raw path
    block_raw = resolve_agent_block(user_agent="SomethingNobodyKnows/1.0")
    assert required_keys <= set(block_raw.keys())


def test_resolve_agent_block_can_skip_process_tree(monkeypatch):
    """Per [[security-team-positioning-safety-not-surveillance]] the
    webhook caller may opt OUT of process-tree fingerprinting so
    sensitive parent-process data doesn't leak to remote collectors."""
    # Set up a process-tree match.
    parents = {1000: 999, 999: 1, 1: 0}
    exes = {1000: "python", 999: "cursor-helper", 1: "init"}
    monkeypatch.setattr(_agent_context, "_ppid", lambda pid: parents.get(pid))
    monkeypatch.setattr(_agent_context, "_exe_name", lambda pid: exes.get(pid))

    # With include_process_tree=True: the block fires.
    block_on = resolve_agent_block(peer_pid=1000, include_process_tree=True)
    assert block_on is not None
    assert block_on["detected_from"] == "process_tree"

    # With include_process_tree=False: no block (no MCP, no UA either).
    block_off = resolve_agent_block(peer_pid=1000, include_process_tree=False)
    assert block_off is None


# ---------------------------------------------------------------------------
# MCP server wiring (integration with _handle_request)
# ---------------------------------------------------------------------------


def test_mcp_initialize_binds_clientinfo_for_subsequent_events():
    """End-to-end: dispatch an MCP initialize via the server's
    handler + check that audit_event_from_decision picks up the
    bound clientInfo."""
    from iam_jit.mcp_server import _handle_request

    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "clientInfo": {"name": "claude-code", "version": "1.7.0"},
        },
    })
    assert resp is not None
    # Active session is now bound.
    active = _agent_context.active_agent_session()
    assert active is not None
    assert active.name == "claude-code"
    assert active.version == "1.7.0"
    # An audit event built from any subsequent decision carries it.
    event = audit_event_from_decision(
        decision_id=1, mode="cooperative", profile=None, verdict="allow",
        reason="ok", service="s3", action="ListBuckets", arn=None,
        region="us-east-1", host="s3.us-east-1.amazonaws.com",
    )
    assert event["unmapped"]["iam_jit"]["agent"]["name"] == "claude-code"
    assert event["unmapped"]["iam_jit"]["agent"]["session_id"] == active.session_id


def test_mcp_initialize_with_no_clientinfo_still_binds_session():
    """An MCP client that omits clientInfo still gets a session ID —
    we record the connection happened even if we don't know the
    client identity."""
    from iam_jit.mcp_server import _handle_request

    _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {},
    })
    active = _agent_context.active_agent_session()
    assert active is not None
    assert active.name == "unknown"
    assert active.session_id


# ---------------------------------------------------------------------------
# #287 — AWS-API path (cross-process) carries the MCP session_id
# ---------------------------------------------------------------------------


def test_aws_api_path_picks_up_session_id_from_disk_after_initialize():
    """Reproducer for the #287 dogfood-round-2 finding:

    Process A: MCP server gets `initialize` -> `begin_mcp_session`.
    Process B: AWS-API proxy builds an OCSF event via
               `audit_event_from_decision`.

    Pre-fix: process B's `_ACTIVE` slot was empty because the slot is
    module-global PER PROCESS, so the AWS-API path emitted
    `unmapped.iam_jit.agent.session_id == None` on every decision even
    when an MCP session was live elsewhere on the host.

    Post-fix: `begin_mcp_session` persists to a small on-disk state
    file; `resolve_agent_block` reads the file as a fallback when the
    in-process slot is empty. We simulate the cross-process case by
    clearing the in-process slot (without removing the file).
    """
    session = begin_mcp_session(
        {"name": "claude-code", "version": "1.7.0"},
    )
    # Simulate the "proxy is a separate process" reality: that process
    # never called begin_mcp_session, so its in-process slot is None.
    _agent_context._ACTIVE = None
    assert _agent_context.active_agent_session() is None

    # Disk fallback fires; AWS-API decision carries the session_id.
    event = audit_event_from_decision(
        decision_id=287,
        mode="transparent",
        profile=None,
        verdict="deny",
        reason="rule#1",
        service="s3",
        action="DeleteObject",
        arn="arn:aws:s3:::secret-bucket/key",
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        user_agent="Boto3/1.34.5 Python/3.12",
        enforced=True,
    )
    agent = event["unmapped"]["iam_jit"]["agent"]
    assert agent["session_id"] == session.session_id
    assert agent["name"] == "claude-code"
    assert agent["detected_from"] == "mcp_clientinfo"


def test_disk_session_pickup_ignores_stale_pid(tmp_path, monkeypatch):
    """If the MCP server crashed (didn't call end_mcp_session) the
    state file would point at a dead PID. We must NOT stamp a stale
    session_id onto fresh AWS-API decisions in that case."""
    state_path = tmp_path / "stale-mcp-session.json"
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AGENT_SESSION_FILE", str(state_path),
    )
    # Write a stale state file by hand: a PID that's almost certainly
    # not running (very high number; the kernel reserves PIDs from low
    # numbers up). If it happens to be live we accept that as a flake
    # of the host (extremely unlikely; PIDs are recycled but the upper
    # range is sparse).
    state_path.write_text(json.dumps({
        "session_id": "stale-uuid",
        "name": "claude-code",
        "version": "0.0",
        "detected_from": "mcp_clientinfo",
        "pid": 2_000_000,
    }))
    block = _agent_context.resolve_agent_block(
        user_agent="Boto3/1.34.5 Python/3.12",
    )
    # No MCP-session stamp: stale file was skipped; the UA path took
    # over and assigned an aws-sdk-python identity with session_id=None.
    assert block is not None
    assert block["name"] == "aws-sdk-python"
    assert block["session_id"] is None
    # And the stale file was cleaned up by the loader.
    assert not state_path.exists()


def test_end_mcp_session_removes_disk_state(tmp_path, monkeypatch):
    """After end_mcp_session the cross-process state file must be
    removed so the proxy stops attributing AWS calls to the just-ended
    agent session."""
    state_path = tmp_path / "ending-mcp-session.json"
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AGENT_SESSION_FILE", str(state_path),
    )
    begin_mcp_session({"name": "cursor", "version": "0.45.0"})
    assert state_path.exists()
    end_mcp_session()
    assert not state_path.exists()
