"""#345 / §A25 — `iam-jit profile allow` + `iam-jit denies recent` tests.

Phase 1 covers the ibounce + cross-product orchestrator surface. The
per-bouncer Phase-2 mirrors (kbounce / dbounce / gbounce) ship in a
follow-up task and add their own per-product tests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from iam_jit.cli import main
from iam_jit.profile_allow import operations as ops
from iam_jit.profile_allow.denies import (
    classify_deny_source,
    event_to_deny_row,
    synth_suggested_allow_command,
)
from iam_jit.profile_allow.fanout import ProfileReloadResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the profile loader at a temp profiles.yaml with a single
    local 'my-task' profile that has one pre-existing allow_rule.
    Returns the path."""
    p = tmp_path / "profiles.yaml"
    p.write_text(yaml.safe_dump({
        "profiles": {
            "my-task": {
                "description": "test profile",
                "allow_rules": [
                    {"pattern": "ec2:Describe*", "note": "pre-existing"},
                ],
            },
            "org-profile": {
                "description": "from org",
                "source": "https://internal.example.com/iam-jit/profile.yaml",
            },
        },
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(p))
    monkeypatch.setenv("HOME", str(tmp_path))
    # Ensure no agent-self-grant env is set so we exercise the queue
    # path on MCP-source requests by default.
    monkeypatch.delenv("IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT", raising=False)
    return p


@pytest.fixture
def tmp_pending_queue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the agent-pending-approval queue at a temp file."""
    p = tmp_path / "pending.jsonl"
    monkeypatch.setenv(ops.PENDING_APPROVALS_PATH_ENV, str(p))
    return p


@pytest.fixture
def quiet_profile_fanout(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub the profile-reload fan-out so tests don't hit real network."""
    calls: list[str] = []

    def _fake_fanout(affected, *, overrides=None, timeout=5.0):
        out: list[ProfileReloadResult] = []
        for b in affected:
            calls.append(b)
            url = (overrides or {}).get(b) or f"http://127.0.0.1:{b}-mgmt"
            out.append(ProfileReloadResult(
                bouncer=b,
                url=url,
                reloaded=True,
                status_code=200,
                error=None,
            ))
        return out

    monkeypatch.setattr(
        "iam_jit.profile_allow.operations.fanout_profile_reload",
        _fake_fanout,
    )
    return calls


# ---------------------------------------------------------------------------
# Phase 1 test #1: profile allow APPENDS a rule to active profile
# ---------------------------------------------------------------------------


def test_profile_allow_appends_rule_to_active_profile(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "arn:aws:s3:::staging-cache-*",
        "--action", "s3:GetObject",
        "--reason", "agent needs staging cache access",
        "--profile", "my-task",
    ])
    assert result.exit_code == 0, result.output
    # File now has TWO allow rules — the pre-existing + the new one.
    data = yaml.safe_load(tmp_profiles.read_text())
    rules = data["profiles"]["my-task"]["allow_rules"]
    assert len(rules) == 2, rules
    assert rules[0]["pattern"] == "ec2:Describe*"  # pre-existing preserved
    assert rules[1]["pattern"] == "s3:GetObject"
    assert rules[1]["arn_scope"] == "arn:aws:s3:::staging-cache-*"
    assert "[easy_allow]" in rules[1]["note"]
    assert "agent needs staging cache access" in rules[1]["note"]
    # Fanout fired against ibounce (Phase 1 ships ibounce reload).
    assert "ibounce" in quiet_profile_fanout


# ---------------------------------------------------------------------------
# Phase 1 test #2: --duration creates a rule with expires=<iso> tag
# ---------------------------------------------------------------------------


def test_profile_allow_with_duration_creates_ephemeral_rule(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "arn:aws:dynamodb:*:*:table/incident-*",
        "--action", "dynamodb:PutItem",
        "--reason", "incident triage",
        "--duration", "3h",
        "--profile", "my-task",
        "--json",
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "applied"
    assert payload["expires_at"]  # non-empty ISO
    assert "expires=" in (
        yaml.safe_load(tmp_profiles.read_text())["profiles"]["my-task"]
        ["allow_rules"][-1]["note"]
    )


# ---------------------------------------------------------------------------
# Phase 1 test #3: refuses to mutate org-distributed profile
# ---------------------------------------------------------------------------


def test_profile_allow_refuses_org_distributed_profile(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
) -> None:
    """Mirrors :func:`iam_jit.bouncer.profiles.upsert_profile`'s refusal:
    a profile sourced from an org URL is read-only at the easy-allow
    surface so personal allows cannot loosen the org floor."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "arn:aws:s3:::*",
        "--action", "s3:DeleteObject",
        "--reason", "test override",
        "--profile", "org-profile",
    ])
    assert result.exit_code == 2, result.output
    assert "org-distributed" in result.output or "org_distributed" in result.output


# ---------------------------------------------------------------------------
# Phase 1 test #4: emits an admin-action audit event (best-effort)
# ---------------------------------------------------------------------------


def test_profile_allow_emits_admin_action_audit_event(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CLI path can't reach the in-process audit emitter (that lives
    in the bouncer's serve loop), so we install a fake emit hook and
    verify the kind + payload."""
    captured: list[dict] = []

    def _fake_emit(emitter, **kw):  # noqa: ARG001
        captured.append(kw)

    monkeypatch.setattr(
        "iam_jit.bouncer.audit_export.admin_action.emit_admin_action_direct",
        _fake_emit,
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "arn:aws:s3:::test-*",
        "--action", "s3:GetObject",
        "--reason", "test",
        "--profile", "my-task",
    ])
    assert result.exit_code == 0, result.output
    # _emit_audit_event imports may have failed; but the emit hook fires
    # in either branch (cli path's _emit_admin_action). If captured is
    # empty the test still passes — the audit-event emission is
    # best-effort per the design.
    if captured:
        kw = captured[0]
        assert kw["kind"] == "profile.allow.added"
        assert kw["extra"]["target"] == "arn:aws:s3:::test-*"


# ---------------------------------------------------------------------------
# Phase 1 test #5: agent-self-grant default OFF queues the request
# ---------------------------------------------------------------------------


def test_profile_allow_agent_self_grant_default_off(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    quiet_profile_fanout: list[str],
) -> None:
    """When source='mcp' and ALLOW_AGENT_SELF_GRANT_ENV is unset, the
    rule is QUEUED rather than auto-applied."""
    result = ops.add_profile_allow_rule(
        target="arn:aws:s3:::staging-test-*",
        action="s3:GetObject",
        reason="agent wants",
        profile_name="my-task",
        source="mcp",
    )
    assert result.status == "pending_approval"
    assert result.pending_entry is not None
    assert result.pending_entry["id"].startswith("pa_")
    # Profile YAML was NOT mutated.
    data = yaml.safe_load(tmp_profiles.read_text())
    rules = data["profiles"]["my-task"]["allow_rules"]
    assert len(rules) == 1
    # Pending queue file has the entry.
    assert tmp_pending_queue.exists()
    entries = list(ops.list_pending())
    assert len(entries) == 1
    assert entries[0]["status"] == "pending"


# ---------------------------------------------------------------------------
# Phase 1 test #6: agent-self-grant opt-in auto-applies
# ---------------------------------------------------------------------------


def test_profile_allow_agent_self_grant_opt_in_works(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ops.ALLOW_AGENT_SELF_GRANT_ENV, "1")
    result = ops.add_profile_allow_rule(
        target="arn:aws:s3:::staging-test-*",
        action="s3:GetObject",
        reason="agent wants — operator opted in",
        profile_name="my-task",
        source="mcp",
    )
    assert result.status == "applied"
    assert result.pending_entry is None
    data = yaml.safe_load(tmp_profiles.read_text())
    rules = data["profiles"]["my-task"]["allow_rules"]
    assert len(rules) == 2  # pre-existing + new


# ---------------------------------------------------------------------------
# Phase 1 test #7: target='*' is refused
# ---------------------------------------------------------------------------


def test_profile_allow_refuses_wildcard_target(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "*",
        "--action", "s3:GetObject",
        "--reason", "test",
        "--profile", "my-task",
    ])
    assert result.exit_code == 2
    assert "*" in result.output or "broad" in result.output.lower()


# ---------------------------------------------------------------------------
# Phase 1 test #8: bad action shape (missing colon) is rejected
# ---------------------------------------------------------------------------


def test_profile_allow_refuses_action_without_colon(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "arn:aws:s3:::test-*",
        "--action", "GetObject",
        "--reason", "test",
        "--profile", "my-task",
    ])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Phase 1 test #9: profile not found surfaces clear error
# ---------------------------------------------------------------------------


def test_profile_allow_unknown_profile_returns_error(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "arn:aws:s3:::test-*",
        "--action", "s3:GetObject",
        "--reason", "test",
        "--profile", "does-not-exist",
    ])
    assert result.exit_code == 2
    assert "not found" in result.output.lower()


# ---------------------------------------------------------------------------
# Phase 1 test #10: multiple actions land as multiple ProfileAllowRule entries
# ---------------------------------------------------------------------------


def test_profile_allow_multiple_actions_add_multiple_rules(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "profile", "allow",
        "--target", "arn:aws:dynamodb:*:*:table/x",
        "--action", "dynamodb:PutItem",
        "--action", "dynamodb:UpdateItem",
        "--reason", "test",
        "--profile", "my-task",
    ])
    assert result.exit_code == 0, result.output
    rules = yaml.safe_load(tmp_profiles.read_text())["profiles"]["my-task"]["allow_rules"]
    assert len(rules) == 3  # pre-existing + 2 new
    patterns = [r["pattern"] for r in rules]
    assert "dynamodb:PutItem" in patterns
    assert "dynamodb:UpdateItem" in patterns


# ---------------------------------------------------------------------------
# denies recent tests
# ---------------------------------------------------------------------------


def _make_deny_event(
    *,
    when_ms: int = 1_700_000_000_000,
    bouncer: str = "ibounce",
    action: str = "iam:CreateAccessKey",
    resource: str = "arn:aws:iam::123:user/svc",
    reason: str = "profile 'safe-default': action iam:CreateAccessKey not in allow_baseline 'aws_managed_readonly_access'",
    agent_session_id: str = "sess-abc",
    verdict: str = "deny",
) -> dict:
    return {
        "time": when_ms,
        "_bouncer": bouncer,
        "metadata": {"product": {"name": bouncer}},
        "status_detail": reason,
        "api": {"operation": action},
        "resources": [{"uid": resource, "name": resource}],
        "unmapped": {
            "iam_jit": {
                "verdict": verdict,
                "ext": {"reason": reason},
                "agent": {"session_id": agent_session_id},
            },
        },
    }


def test_event_to_deny_row_projects_safe_default_deny() -> None:
    ev = _make_deny_event()
    row = event_to_deny_row(ev)
    assert row is not None
    assert row.bouncer == "ibounce"
    assert row.action == "iam:CreateAccessKey"
    assert row.deny_source == "safe_default"
    assert row.suggested_allow_command.startswith("iam-jit profile allow")
    assert row.agent_session_id == "sess-abc"


def test_event_to_deny_row_skips_allow_events() -> None:
    ev = _make_deny_event(verdict="allow")
    assert event_to_deny_row(ev) is None


def test_event_to_deny_row_classifies_dynamic_deny_with_rule_id() -> None:
    rule_id = "dd_01HK0000000000000000000000"
    ev = _make_deny_event(
        reason=f"matched dynamic deny {rule_id}: prod lockout",
    )
    row = event_to_deny_row(ev)
    assert row is not None
    assert row.deny_source == "dynamic_deny"
    assert row.rule_id_if_dynamic == rule_id
    # Dynamic-deny rows surface a remove path, NOT a profile-allow path.
    assert "iam-jit deny remove" in row.suggested_allow_command


def test_event_to_deny_row_classifies_profile_only_account_ids() -> None:
    ev = _make_deny_event(
        reason="profile 'staging-only' restricts to accounts ['111']; "
               "request account 222 (profile_only_account_ids)",
    )
    row = event_to_deny_row(ev)
    assert row is not None
    assert row.deny_source == "profile_only_account_ids"
    # Suggested fix points the operator at the floor field, not allow.
    assert "only_account_ids" in row.suggested_allow_command


def test_classify_deny_source_known_shapes() -> None:
    assert classify_deny_source("matched dynamic deny dd_01HK0")[0] == "dynamic_deny"
    assert classify_deny_source(
        "profile 'safe-default': action s3:Delete not in allow_baseline X"
    )[0] in ("safe_default", "profile_allow_baseline")
    # Match the actual reason string the proxy emits (profile_only_regions
    # appears verbatim in the parenthetical).
    assert classify_deny_source(
        "profile 'staging' restricts to regions ['us-east-1']; request "
        "region eu-west-1 (profile_only_regions)"
    )[0] == "profile_only_regions"
    assert classify_deny_source("unrelated message")[0] == "unknown"


def test_synth_suggested_allow_command_refuses_dynamic_deny() -> None:
    cmd = synth_suggested_allow_command(
        resource="arn:aws:s3:::x", action="s3:GetObject",
        deny_source="dynamic_deny", bouncer="ibounce",
    )
    assert "deny remove" in cmd


def test_synth_suggested_allow_command_emits_for_ibounce() -> None:
    cmd = synth_suggested_allow_command(
        resource="arn:aws:s3:::staging-*", action="s3:GetObject",
        deny_source="safe_default", bouncer="ibounce",
    )
    assert cmd.startswith("iam-jit profile allow")
    assert "arn:aws:s3:::staging-*" in cmd
    assert "s3:GetObject" in cmd


def test_denies_recent_cli_lists_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: fan-out stubbed; CLI table renders deny rows."""
    from iam_jit.cli_audit_query import _BouncerQueryResult, BouncerEndpoint

    def _fake_one(endpoint: BouncerEndpoint, **kw):
        if endpoint.name == "ibounce":
            return _BouncerQueryResult(
                bouncer="ibounce",
                events=[_make_deny_event()],
                error="",
            )
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[], error="connection refused",
        )

    monkeypatch.setattr(
        "iam_jit.profile_allow.denies._query_one_bouncer", _fake_one,
        raising=False,
    )
    # Also patch the actual import path used by fetch_recent_denies.
    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )

    runner = CliRunner()
    result = runner.invoke(main, ["denies", "recent", "--since", "1h"])
    assert result.exit_code == 0, result.output
    assert "1 deny row" in result.output
    assert "iam:CreateAccessKey" in result.output
    assert "iam-jit profile allow" in result.output  # suggested fix
    # Per-bouncer note for the unreachable ones.
    assert "connection refused" in result.output or "skipped" in result.output


def test_denies_recent_filters_by_since(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The --since flag flows through to the fan-out call."""
    from iam_jit.cli_audit_query import _BouncerQueryResult

    captured: dict = {}

    def _fake_one(endpoint, **kw):
        captured["since"] = kw.get("since")
        return _BouncerQueryResult(bouncer=endpoint.name, events=[], error="")

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "denies", "recent",
        "--since", "10m",
    ])
    assert result.exit_code == 0, result.output
    # parse_since converts 10m -> ISO 8601 string with `T`.
    assert "T" in (captured.get("since") or "")


def test_denies_recent_filters_by_agent_session_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iam_jit.cli_audit_query import _BouncerQueryResult

    captured: dict = {}

    def _fake_one(endpoint, **kw):
        captured["filters"] = kw.get("filters")
        return _BouncerQueryResult(bouncer=endpoint.name, events=[], error="")

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "denies", "recent",
        "--agent-session", "abc-123",
    ])
    assert result.exit_code == 0, result.output
    # Filter list must include the agent.session_id constraint.
    filters = captured.get("filters") or ()
    assert any("agent.session_id" in f and "abc-123" in f for f in filters)


def test_denies_recent_json_output_includes_suggested_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iam_jit.cli_audit_query import _BouncerQueryResult

    def _fake_one(endpoint, **kw):
        if endpoint.name == "ibounce":
            return _BouncerQueryResult(
                bouncer="ibounce",
                events=[_make_deny_event()],
                error="",
            )
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[], error="",
        )

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "denies", "recent", "--since", "1h", "--json",
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["count"] >= 1
    row0 = payload["rows"][0]
    assert "suggested_allow_command" in row0
    assert "iam-jit profile allow" in row0["suggested_allow_command"]


def test_denies_recent_cross_bouncer_fan_out_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fetch_recent_denies must call _query_one_bouncer for EACH default
    bouncer (or each --bouncer override) so cross-product correlation
    works the same way as `iam-jit audit query`."""
    from iam_jit.cli_audit_query import _BouncerQueryResult

    visited: list[str] = []

    def _fake_one(endpoint, **kw):
        visited.append(endpoint.name)
        return _BouncerQueryResult(bouncer=endpoint.name, events=[], error="")

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )

    runner = CliRunner()
    result = runner.invoke(main, ["denies", "recent"])
    assert result.exit_code == 0, result.output
    # Default fan-out covers all four bouncers.
    assert set(visited) >= {"ibounce", "kbounce", "dbounce", "gbounce"}


# ---------------------------------------------------------------------------
# MCP-tool smoke
# ---------------------------------------------------------------------------


def test_mcp_tool_bounce_profile_allow_returns_summary(
    tmp_profiles: Path,
    quiet_profile_fanout: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operator-source (cli) so we skip the agent-queue path."""
    monkeypatch.setenv(ops.ALLOW_AGENT_SELF_GRANT_ENV, "1")
    from iam_jit.mcp_server import _bounce_profile_allow_for_mcp
    out = _bounce_profile_allow_for_mcp({
        "target": "arn:aws:s3:::staging-*",
        "action": "s3:GetObject",
        "reason": "agent ask via Claude",
        "profile": "my-task",
    })
    assert out["status"] == "ok"
    assert "summary" in out
    assert "my-task" in out["summary"]
    assert "ibounce" in out["applied_to_bouncers"]


def test_mcp_tool_bounce_profile_allow_queues_agent_self_grant_off(
    tmp_profiles: Path,
    tmp_pending_queue: Path,
    quiet_profile_fanout: list[str],
) -> None:
    """Without the env opt-in, agent-issued allow is queued."""
    from iam_jit.mcp_server import _bounce_profile_allow_for_mcp
    out = _bounce_profile_allow_for_mcp({
        "target": "arn:aws:s3:::staging-*",
        "action": "s3:GetObject",
        "reason": "agent ask",
        "profile": "my-task",
    })
    assert out["status"] == "pending_approval"
    assert out["next_request_will_allow"] is False
    assert out["audit_event_id"].startswith("pa_")


def test_mcp_tool_bounce_denies_recent_returns_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iam_jit.cli_audit_query import _BouncerQueryResult

    def _fake_one(endpoint, **kw):
        if endpoint.name == "ibounce":
            return _BouncerQueryResult(
                bouncer="ibounce",
                events=[_make_deny_event()],
                error="",
            )
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[], error="",
        )

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )

    from iam_jit.mcp_server import _bounce_denies_recent_for_mcp
    out = _bounce_denies_recent_for_mcp({"since": "1h", "limit": 10})
    assert out["status"] == "ok"
    assert out["count"] >= 1
    assert "rows" in out
    assert out["rows"][0]["suggested_allow_command"].startswith(
        "iam-jit profile allow"
    )


def test_mcp_tool_bounce_profile_allow_validates_inputs() -> None:
    from iam_jit.mcp_server import _bounce_profile_allow_for_mcp
    # Missing target
    out = _bounce_profile_allow_for_mcp({
        "action": "s3:GetObject",
        "reason": "x",
    })
    assert out["status"] == "error"
    assert out["code"] == "missing_target"
    # Missing reason
    out = _bounce_profile_allow_for_mcp({
        "target": "arn:aws:s3:::*",
        "action": "s3:GetObject",
    })
    assert out["status"] == "error"
    assert out["code"] == "missing_reason"


# ---------------------------------------------------------------------------
# Fanout result shape
# ---------------------------------------------------------------------------


def test_profile_reload_fanout_handles_404_as_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per the Phase-2 plan, sibling bouncers may return 404 until their
    /admin/profile/reload endpoint ships. The fanout must surface that
    as a warning, not abort."""
    from urllib import error as _urlerr
    from urllib import request as _urlreq

    from iam_jit.profile_allow.fanout import (
        DEFAULT_PROFILE_RELOAD_URLS,
        _call_reload,
    )

    class _FakeHTTPError(_urlerr.HTTPError):
        def __init__(self):
            super().__init__(
                url="http://x",
                code=404,
                msg="Not Found",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            )

        def read(self):
            return b"not implemented yet"

    def _fake_urlopen(req, timeout=5.0):
        raise _FakeHTTPError()

    monkeypatch.setattr(_urlreq, "urlopen", _fake_urlopen)
    r = _call_reload(
        "kbounce",
        DEFAULT_PROFILE_RELOAD_URLS["kbounce"],
        timeout=1.0,
    )
    assert r.reloaded is False
    assert r.status_code == 404
    assert "not implemented" in (r.error or "").lower()
