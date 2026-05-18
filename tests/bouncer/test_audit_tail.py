"""Tests for #268 — `ibounce audit tail` filter / summary / export.

Covers the spec contract:
  * --follow prints new rows as they appear; exits on signal
  * --filter AND-combines multiple expressions
  * --filter regex form matches
  * --filter numeric >= / <= work
  * --filter on nested field path (unmapped.iam_jit.agent.name) works
  * --summary produces correct counts per default groupings
  * --export jsonl round-trips through `jq -c` (we use json.loads)
  * --export csv parses cleanly via standard csv library
  * --export ocsf-bundle validates against the OCSF schema as a
    Detection Finding (class 2004)
  * --filter + --export composes (export reflects filtered view)
  * --follow + --summary clashes — error with clear message
  * Empty audit log + --summary produces zero counts (not crash)
  * CSV default columns exclude PII-shaped fields; --csv-columns
    opt-in surfaces the stderr warning
"""

from __future__ import annotations

import csv as _csv
import json
import pathlib
import signal
import threading
import time

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export.event import audit_event_from_decision
from iam_jit.bouncer.audit_export.tail import (
    DECISION_EVENT_TYPE,
    DEFAULT_CSV_COLUMNS,
    Filter,
    FilterParseError,
    build_ocsf_bundle,
    event_matches,
    export_csv,
    export_jsonl,
    export_ocsf_bundle,
    follow_audit_file,
    get_path,
    iter_audit_file,
    parse_filter_expr,
    render_event_row,
    render_summary,
    resolve_csv_columns,
    summarize_events,
)
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _decision_event(
    *,
    decision_id: int = 1,
    verdict: str = "allow",
    service: str = "s3",
    action: str = "GetObject",
    principal: str = "alice@example.com",
    severity_id: int | None = None,
    agent_name: str | None = None,
    agent_session_id: str | None = None,
) -> dict:
    """Build a synthetic OCSF decision event. Mutates a few fields
    post-build to set agent_name / severity_id deterministically;
    the live builder reads these from runtime context."""
    ev = audit_event_from_decision(
        decision_id=decision_id,
        mode="transparent",
        profile="safe-default",
        verdict=verdict,
        reason="test",
        service=service,
        action=action,
        arn=None,
        region="us-east-1",
        host=f"{service}.us-east-1.amazonaws.com",
        enforced=False,
        principal=principal,
        request_id=f"req-{decision_id}",
        include_process_tree=False,
    )
    if severity_id is not None:
        ev["severity_id"] = severity_id
    if agent_name is not None:
        ev.setdefault("unmapped", {}).setdefault("iam_jit", {}).setdefault(
            "agent", {}
        )["name"] = agent_name
    if agent_session_id is not None:
        ev.setdefault("unmapped", {}).setdefault("iam_jit", {}).setdefault(
            "agent", {}
        )["session_id"] = agent_session_id
    return ev


def _heartbeat_event(severity_id: int = 1) -> dict:
    ev = _decision_event(decision_id=999)
    ev["severity_id"] = severity_id
    ev.setdefault("unmapped", {}).setdefault("iam_jit", {})["event_type"] = "HEARTBEAT"
    return ev


def _write_jsonl(path: pathlib.Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e))
            f.write("\n")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def audit_path(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "audit.jsonl"


# ---------------------------------------------------------------------------
# get_path dotted lookup
# ---------------------------------------------------------------------------


def test_get_path_handles_nested_dicts() -> None:
    ev = {"a": {"b": {"c": 42}}}
    assert get_path(ev, "a.b.c") == 42
    assert get_path(ev, "a.b") == {"c": 42}
    assert get_path(ev, "a.x") is None
    assert get_path(ev, "x") is None


def test_get_path_event_type_shortcut_defaults_to_decision() -> None:
    """An event with no `unmapped.iam_jit.event_type` is a plain
    decision; the shortcut resolves to DECISION so summary tables
    + filters work without a special case."""
    ev = _decision_event()
    assert get_path(ev, "event_type") == DECISION_EVENT_TYPE
    # Explicit event_type wins.
    ev2 = _heartbeat_event()
    assert get_path(ev2, "event_type") == "HEARTBEAT"


def test_get_path_verdict_shortcut() -> None:
    ev = _decision_event(verdict="deny")
    assert get_path(ev, "verdict") == "deny"


# ---------------------------------------------------------------------------
# Filter parsing
# ---------------------------------------------------------------------------


def test_parse_filter_string_equality() -> None:
    f = parse_filter_expr("actor.user.name=alice@example.com")
    assert f.field == "actor.user.name"
    assert f.op == "="
    assert f.raw_value == "alice@example.com"


def test_parse_filter_regex() -> None:
    f = parse_filter_expr("api.operation~^s3:")
    assert f.op == "~"
    assert f.raw_value == "^s3:"


def test_parse_filter_numeric_ge_le() -> None:
    f = parse_filter_expr("severity_id>=3")
    assert f.op == ">="
    assert f.raw_value == "3"
    f2 = parse_filter_expr("severity_id<=2")
    assert f2.op == "<="


def test_parse_filter_longest_operator_wins() -> None:
    """`>=` must NOT parse as `=` with a leading `>`."""
    f = parse_filter_expr("severity_id>=3")
    assert f.op == ">="
    assert f.field == "severity_id"


def test_parse_filter_raises_on_garbage() -> None:
    with pytest.raises(FilterParseError):
        parse_filter_expr("garbage_no_operator")
    with pytest.raises(FilterParseError):
        parse_filter_expr("")
    with pytest.raises(FilterParseError):
        parse_filter_expr("=value")
    with pytest.raises(FilterParseError):
        parse_filter_expr("field=")


# ---------------------------------------------------------------------------
# Filter matching
# ---------------------------------------------------------------------------


def test_filter_string_equality_matches() -> None:
    ev = _decision_event(principal="alice@example.com")
    f = parse_filter_expr("actor.user.name=alice@example.com")
    assert f.matches(ev)
    f2 = parse_filter_expr("actor.user.name=bob@example.com")
    assert not f2.matches(ev)


def test_filter_regex_matches() -> None:
    ev = _decision_event(service="s3", action="DeleteBucket")
    # Note: api.operation = "s3:DeleteBucket"
    f = parse_filter_expr("api.operation~^s3:Delete")
    assert f.matches(ev)
    f2 = parse_filter_expr("api.operation~ec2:")
    assert not f2.matches(ev)


def test_filter_numeric_ge_le() -> None:
    ev = _decision_event(severity_id=3)
    assert parse_filter_expr("severity_id>=3").matches(ev)
    assert parse_filter_expr("severity_id>=2").matches(ev)
    assert not parse_filter_expr("severity_id>=4").matches(ev)
    assert parse_filter_expr("severity_id<=3").matches(ev)
    assert not parse_filter_expr("severity_id<=2").matches(ev)


def test_filter_on_nested_field_path() -> None:
    """Per the spec's nested-path test: filter on
    unmapped.iam_jit.agent.name should work end-to-end."""
    ev = _decision_event(agent_name="claude-code")
    f = parse_filter_expr("unmapped.iam_jit.agent.name=claude-code")
    assert f.matches(ev)


def test_filter_and_combines_multiple_expressions() -> None:
    """Per the spec: multiple --filter expressions AND together."""
    ev_match = _decision_event(
        severity_id=3,
        agent_name="claude-code",
    )
    ev_partial = _decision_event(
        severity_id=3,
        agent_name="cursor",
    )
    filters = [
        parse_filter_expr("severity_id>=3"),
        parse_filter_expr("unmapped.iam_jit.agent.name=claude-code"),
    ]
    assert event_matches(ev_match, filters)
    assert not event_matches(ev_partial, filters)


def test_filter_missing_field_does_not_match() -> None:
    ev = _decision_event()  # no agent block
    f = parse_filter_expr("unmapped.iam_jit.agent.name=claude-code")
    assert not f.matches(ev)


def test_filter_invalid_regex_does_not_crash() -> None:
    """An operator-supplied regex that's syntactically invalid should
    not match anything and should not raise — re.error is caught."""
    f = Filter(field="api.operation", op="~", raw_value="(unclosed")
    ev = _decision_event()
    assert not f.matches(ev)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_summary_correct_counts_per_default_groupings() -> None:
    events = [
        _decision_event(decision_id=1, principal="alice@example.com",
                        action="GetObject", severity_id=1),
        _decision_event(decision_id=2, principal="alice@example.com",
                        action="GetObject", severity_id=1),
        _decision_event(decision_id=3, principal="bob@example.com",
                        action="PutObject", severity_id=3),
        _heartbeat_event(severity_id=1),
    ]
    out = summarize_events(events)
    by_heading = {h: dict(rows) for h, rows in out}
    # event_type: 3 decisions + 1 heartbeat
    assert by_heading["event_type counts"][DECISION_EVENT_TYPE] == 3
    assert by_heading["event_type counts"]["HEARTBEAT"] == 1
    # severity: 3 of 1, 1 of 3.
    assert by_heading["severity_id counts"]["1 (Informational)"] == 3
    assert by_heading["severity_id counts"]["3 (Medium)"] == 1
    # actor: 2 alice (decision events have her principal); heartbeat
    # uses _decision_event base too so 3 alice total. Bob: 1.
    assert by_heading["actor counts"]["alice@example.com"] == 3
    assert by_heading["actor counts"]["bob@example.com"] == 1
    # operations
    assert by_heading["operation counts"]["s3:GetObject"] >= 2
    assert by_heading["operation counts"]["s3:PutObject"] == 1


def test_summary_empty_audit_log_does_not_crash() -> None:
    """Per the spec: empty input -> summary headings present but
    bodies empty (not a crash)."""
    out = summarize_events([])
    assert len(out) > 0  # all groupings represented
    for _heading, rows in out:
        assert rows == []
    rendered = render_summary(out)
    assert "(no events)" in rendered


# ---------------------------------------------------------------------------
# Export — JSONL
# ---------------------------------------------------------------------------


def test_export_jsonl_roundtrip(tmp_path: pathlib.Path) -> None:
    """Per the spec: --export jsonl round-trips through jq -c. We use
    json.loads per line which is equivalent."""
    events = [_decision_event(decision_id=i) for i in range(3)]
    out = tmp_path / "out.jsonl"
    n = export_jsonl(iter(events), out)
    assert n == 3
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    # Each line is a valid OCSF event.
    for i, ev in enumerate(parsed):
        assert ev["class_uid"] == 6003
        assert ev["api"]["request"]["uid"] == str(i)


# ---------------------------------------------------------------------------
# Export — CSV
# ---------------------------------------------------------------------------


def test_export_csv_parses_cleanly(tmp_path: pathlib.Path) -> None:
    events = [
        _decision_event(decision_id=1, principal="alice@example.com"),
        _decision_event(decision_id=2, principal="bob@example.com",
                        agent_name="claude-code",
                        agent_session_id="sess-1"),
    ]
    out = tmp_path / "out.csv"
    n = export_csv(events, out)
    assert n == 2
    with out.open("r", encoding="utf-8", newline="") as f:
        reader = _csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["actor.user.name"] == "alice@example.com"
    assert rows[1]["unmapped.iam_jit.agent.name"] == "claude-code"
    assert rows[1]["unmapped.iam_jit.agent.session_id"] == "sess-1"


def test_csv_default_columns_exclude_pii() -> None:
    """PII guard: default CSV column set must not include `email`,
    `phone`, etc. by default."""
    for col in DEFAULT_CSV_COLUMNS:
        low = col.lower()
        for pii in ("email", "phone", "credential", "secret", "token"):
            assert pii not in low, (
                f"default CSV column {col!r} contains PII hint {pii!r}"
            )


def test_csv_columns_opt_in_pii_returns_warning() -> None:
    """--csv-columns with a PII-shaped field returns it in the
    warnings list so the CLI surfaces the opt-in choice on stderr."""
    cols, warnings = resolve_csv_columns(["time", "actor.user.email"])
    assert "actor.user.email" in cols
    assert "actor.user.email" in warnings
    # Default path returns no warnings.
    cols_d, w_d = resolve_csv_columns(None)
    assert w_d == []
    assert list(cols_d) == list(DEFAULT_CSV_COLUMNS)


def test_csv_columns_override(tmp_path: pathlib.Path) -> None:
    events = [_decision_event(decision_id=1)]
    out = tmp_path / "out.csv"
    export_csv(events, out, columns=["time", "api.operation"])
    with out.open("r", encoding="utf-8", newline="") as f:
        reader = _csv.DictReader(f)
        rows = list(reader)
    assert list(rows[0].keys()) == ["time", "api.operation"]


# ---------------------------------------------------------------------------
# Export — OCSF bundle
# ---------------------------------------------------------------------------


_OCSF_BUNDLE_REQUIRED: dict[str, type] = {
    "metadata": dict,
    "time": int,
    "class_uid": int,
    "class_name": str,
    "category_uid": int,
    "category_name": str,
    "activity_id": int,
    "activity_name": str,
    "type_uid": int,
    "type_name": str,
    "severity_id": int,
    "severity": str,
    "status_id": int,
    "status": str,
}


def _validate_detection_finding(bundle: dict) -> None:
    """Per the spec: --export ocsf-bundle validates against the OCSF
    schema as a Detection Finding (class 2004). Hand-rolled per the
    same pattern used in test_audit_export_log.py."""
    for field, expected_type in _OCSF_BUNDLE_REQUIRED.items():
        assert field in bundle, f"OCSF bundle missing required field {field!r}"
        assert isinstance(bundle[field], expected_type), (
            f"OCSF bundle field {field!r} should be "
            f"{expected_type.__name__}, got {type(bundle[field]).__name__}"
        )
    assert bundle["class_uid"] == 2004, "Detection Finding class_uid is 2004"
    assert bundle["category_uid"] == 2, "Findings category_uid is 2"
    # type_uid formula per OCSF base.
    assert bundle["type_uid"] == 2004 * 100 + bundle["activity_id"]
    assert bundle["metadata"]["version"] == "1.1.0"
    prod = bundle["metadata"]["product"]
    assert prod["name"] == "ibounce"
    assert prod["vendor_name"] == "iam-jit"
    # Finding-specific shape.
    assert "finding" in bundle
    assert isinstance(bundle["finding"], dict)
    assert "uid" in bundle["finding"]
    assert "evidence" in bundle["finding"]
    assert "events" in bundle["finding"]["evidence"]


def test_build_ocsf_bundle_validates_as_detection_finding() -> None:
    events = [
        _decision_event(decision_id=1),
        _decision_event(decision_id=2, severity_id=4),
    ]
    bundle = build_ocsf_bundle(events)
    _validate_detection_finding(bundle)
    # Max severity propagates.
    assert bundle["severity_id"] == 4
    assert bundle["severity"] == "High"
    # Events stay verbatim under the evidence path.
    assert len(bundle["finding"]["evidence"]["events"]) == 2


def test_build_ocsf_bundle_empty_events_default_severity() -> None:
    bundle = build_ocsf_bundle([])
    _validate_detection_finding(bundle)
    assert bundle["severity_id"] == 1
    assert bundle["severity"] == "Informational"
    assert bundle["finding"]["evidence"]["events"] == []


def test_export_ocsf_bundle_writes_file(tmp_path: pathlib.Path) -> None:
    events = [_decision_event(decision_id=1)]
    out = tmp_path / "bundle.json"
    n = export_ocsf_bundle(events, out)
    assert n == 1
    parsed = json.loads(out.read_text(encoding="utf-8"))
    _validate_detection_finding(parsed)


# ---------------------------------------------------------------------------
# iter / follow file
# ---------------------------------------------------------------------------


def test_iter_audit_file_returns_empty_when_missing(tmp_path: pathlib.Path) -> None:
    out = list(iter_audit_file(tmp_path / "no-such.jsonl"))
    assert out == []


def test_iter_audit_file_skips_corrupt_lines(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps({"k": 1}) + "\n"
        + "not-json\n"
        + json.dumps({"k": 2}) + "\n",
        encoding="utf-8",
    )
    out = list(iter_audit_file(path))
    assert [e["k"] for e in out] == [1, 2]


def test_follow_audit_file_picks_up_new_rows(tmp_path: pathlib.Path) -> None:
    """Per the spec: --follow prints new rows as they appear; exits
    on signal. Uses the stop_flag mechanism rather than a real signal
    so the test stays deterministic + portable."""
    path = tmp_path / "audit.jsonl"
    # Pre-create the file so follow attaches immediately.
    _write_jsonl(path, [{"baseline": True}])
    stop_flag = {"stop": False}
    collected: list[dict] = []

    def _run() -> None:
        for ev in follow_audit_file(
            path, poll_interval_s=0.05, stop_flag=stop_flag,
        ):
            collected.append(ev)
            if len(collected) >= 2:
                stop_flag["stop"] = True
                return

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    # Give the follower time to seek to EOF.
    time.sleep(0.2)
    # Append two new rows; the follower (which seeked to EOF on open)
    # should pick them up but NOT the baseline.
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"new": 1}) + "\n")
        f.write(json.dumps({"new": 2}) + "\n")
        f.flush()
    t.join(timeout=3.0)
    assert not t.is_alive(), "follower thread did not exit"
    assert len(collected) == 2
    assert {e.get("new") for e in collected} == {1, 2}


def test_follow_audit_file_exits_on_stop_flag(tmp_path: pathlib.Path) -> None:
    """Stop flag is the cooperative signal-handler entry-point."""
    path = tmp_path / "audit.jsonl"
    _write_jsonl(path, [{"baseline": True}])
    stop_flag = {"stop": False}

    def _run() -> None:
        for _ in follow_audit_file(
            path, poll_interval_s=0.05, stop_flag=stop_flag,
        ):
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    time.sleep(0.1)
    stop_flag["stop"] = True
    t.join(timeout=2.0)
    assert not t.is_alive(), "follower did not honour stop_flag"


# ---------------------------------------------------------------------------
# render_event_row
# ---------------------------------------------------------------------------


def test_render_event_row_includes_key_fields() -> None:
    ev = _decision_event(
        decision_id=1, principal="alice@example.com", verdict="deny",
    )
    row = render_event_row(ev)
    assert "alice@example.com" in row
    assert "s3:GetObject" in row
    assert "deny" in row
    assert "sev=1" in row


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


def test_cli_audit_tail_summary(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    events = [
        _decision_event(decision_id=1),
        _decision_event(decision_id=2),
        _heartbeat_event(),
    ]
    _write_jsonl(audit_path, events)
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path), "--summary",
    ])
    assert result.exit_code == 0, result.output
    assert "event_type counts:" in result.output
    assert DECISION_EVENT_TYPE in result.output
    assert "HEARTBEAT" in result.output
    assert "severity_id counts:" in result.output


def test_cli_audit_tail_summary_empty_log_no_crash(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    """Per the spec: empty audit log + --summary produces zero counts
    (not a crash)."""
    # File does not exist at all.
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path), "--summary",
    ])
    assert result.exit_code == 0, result.output
    assert "event_type counts:" in result.output
    assert "(no events)" in result.output


def test_cli_audit_tail_filter_combines(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    events = [
        _decision_event(decision_id=1, severity_id=1,
                        agent_name="claude-code"),
        _decision_event(decision_id=2, severity_id=4,
                        agent_name="claude-code"),
        _decision_event(decision_id=3, severity_id=4,
                        agent_name="cursor"),
    ]
    _write_jsonl(audit_path, events)
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--filter", "severity_id>=3",
        "--filter", "unmapped.iam_jit.agent.name=claude-code",
    ])
    assert result.exit_code == 0, result.output
    # Only decision_id=2 matches both filters.
    assert result.output.count("\n") == 1
    assert "s3:GetObject" in result.output


def test_cli_audit_tail_filter_then_export_jsonl(
    runner: CliRunner,
    audit_path: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    """Per the spec: --filter + --export composes — the export
    reflects the filtered view, not the entire log."""
    events = [
        _decision_event(decision_id=1, agent_name="claude-code"),
        _decision_event(decision_id=2, agent_name="cursor"),
        _decision_event(decision_id=3, agent_name="claude-code"),
    ]
    _write_jsonl(audit_path, events)
    out = tmp_path / "filtered.jsonl"
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--filter", "unmapped.iam_jit.agent.name=claude-code",
        "--export", "jsonl", "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    ids = [json.loads(line)["api"]["request"]["uid"] for line in lines]
    assert ids == ["1", "3"]


def test_cli_audit_tail_export_ocsf_bundle(
    runner: CliRunner,
    audit_path: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    events = [_decision_event(decision_id=i) for i in range(3)]
    _write_jsonl(audit_path, events)
    out = tmp_path / "bundle.json"
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--export", "ocsf-bundle", "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    parsed = json.loads(out.read_text(encoding="utf-8"))
    _validate_detection_finding(parsed)
    assert len(parsed["finding"]["evidence"]["events"]) == 3


def test_cli_audit_tail_export_csv_writes_default_columns(
    runner: CliRunner,
    audit_path: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    events = [_decision_event(decision_id=1)]
    _write_jsonl(audit_path, events)
    out = tmp_path / "out.csv"
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--export", "csv", "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    with out.open("r", encoding="utf-8", newline="") as f:
        reader = _csv.DictReader(f)
        rows = list(reader)
    assert rows[0]["actor.user.name"] == "alice@example.com"
    # PII columns absent by default.
    assert "actor.user.email" not in rows[0]


def test_cli_audit_tail_csv_pii_optin_warns(
    runner: CliRunner,
    audit_path: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    events = [_decision_event(decision_id=1)]
    _write_jsonl(audit_path, events)
    out = tmp_path / "out.csv"
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--export", "csv", "--out", str(out),
        "--csv-columns", "time,actor.user.name,actor.user.email",
    ])
    assert result.exit_code == 0, result.output
    # Warning surfaces on stderr (Click CliRunner merges into output
    # by default; assert presence in either).
    combined = result.output
    assert "PII-shaped" in combined or "actor.user.email" in combined


def test_cli_audit_tail_follow_summary_clashes(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    """Per the spec: --follow + --summary clashes with a clear error."""
    _write_jsonl(audit_path, [])
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--follow", "--summary",
    ])
    assert result.exit_code != 0
    assert "--follow" in result.output
    assert "--summary" in result.output


def test_cli_audit_tail_export_requires_out(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    _write_jsonl(audit_path, [])
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--export", "jsonl",
    ])
    assert result.exit_code != 0
    assert "--out" in result.output


def test_cli_audit_tail_bad_filter_message(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    _write_jsonl(audit_path, [])
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
        "--filter", "no_operator_here",
    ])
    assert result.exit_code != 0
    assert "no_operator_here" in result.output


def test_cli_audit_tail_no_events_message(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    _write_jsonl(audit_path, [])
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path),
    ])
    assert result.exit_code == 0, result.output
    assert "no events" in result.output.lower()


# ---------------------------------------------------------------------------
# Neutral-vocabulary check per [[security-team-positioning-safety-not-
# surveillance]]: no forbidden words in NEW user-facing strings.
# ---------------------------------------------------------------------------


_FORBIDDEN = ("violation", "infraction", "unauthorized")


def test_no_forbidden_vocabulary_in_summary_output(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    """Per the spec: NO 'violation'/'infraction'/'unauthorized' in
    user-facing strings (verdict labels like 'allow'/'deny' are OK)."""
    events = [
        _decision_event(decision_id=1, verdict="deny"),
        _heartbeat_event(severity_id=4),
    ]
    _write_jsonl(audit_path, events)
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path), "--summary",
    ])
    lower = result.output.lower()
    for word in _FORBIDDEN:
        assert word not in lower, f"forbidden word {word!r} in CLI output"


def test_no_forbidden_vocabulary_in_help(runner: CliRunner) -> None:
    result = runner.invoke(main, ["audit", "tail", "--help"])
    lower = result.output.lower()
    for word in _FORBIDDEN:
        assert word not in lower, f"forbidden word {word!r} in CLI help"


# ---------------------------------------------------------------------------
# Optional: real-SIGINT follow exit (skipped on platforms where
# signals + threading make this flaky)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not hasattr(signal, "SIGINT"),
    reason="SIGINT not available on this platform",
)
def test_cli_audit_tail_follow_exits_on_sigint(
    runner: CliRunner,
    audit_path: pathlib.Path,
) -> None:
    """Per the spec: --follow exits on SIGINT. We invoke the CLI in
    an isolated CliRunner and deliver a KeyboardInterrupt via a
    background thread."""
    _write_jsonl(audit_path, [])

    def _interrupt_soon() -> None:
        time.sleep(0.3)
        import os as _os
        _os.kill(_os.getpid(), signal.SIGINT)

    t = threading.Thread(target=_interrupt_soon, daemon=True)
    t.start()
    result = runner.invoke(main, [
        "audit", "tail", "--path", str(audit_path), "--follow",
    ])
    # Either clean exit (0) or Click's signal exit code is acceptable —
    # the load-bearing assertion is that the command terminated.
    assert result.exit_code in (0, 1, 2, 130), (
        f"follow did not exit cleanly on SIGINT: code={result.exit_code} "
        f"output={result.output}"
    )
    t.join(timeout=1.0)
