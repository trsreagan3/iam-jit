"""Tests for #273 — `ibounce investigate` workflow.

Covers the spec contract:

  * Subcommand exits 0 + writes the two expected files.
  * --print-prompts lists the 10 prompts without writing files.
  * --time-range "24h" filters to recent events (verified by
    seeding events with varied timestamps).
  * Missing audit log → command succeeds, evidence file records
    "audit log present = false" so a Claude analyst sees the gap.
  * Output files have expected sizes (small for empty, larger for
    seeded).
  * No network calls — verified via a urlopen monkeypatch that
    raises if exercised (the embedded /healthz GET is allowed to
    fail; we just check we don't reach OUTBOUND hosts).
"""

from __future__ import annotations

import datetime as _dt
import json
import pathlib

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export.event import audit_event_from_decision
from iam_jit.bouncer.investigate import (
    INVESTIGATION_CONTEXT_FILENAME,
    INVESTIGATION_EVIDENCE_FILENAME,
    STARTER_PROMPTS,
    TimeRangeParseError,
    collect_events_for_window,
    parse_time_range,
    prepare_investigation,
    render_now_what_block,
    render_print_prompts_block,
    time_range_to_filter_expr,
)
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _event_at(ts: _dt.datetime, *, decision_id: int = 1) -> dict:
    """Build a synthetic OCSF decision event stamped at ``ts``.

    Mirrors the audit-tail test fixture so the two suites exercise
    the same wire shape.
    """
    ev = audit_event_from_decision(
        decision_id=decision_id,
        mode="transparent",
        profile="safe-default",
        verdict="allow",
        reason="test",
        service="s3",
        action="GetObject",
        arn=None,
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        enforced=False,
        principal="alice@example.com",
        request_id=f"req-{decision_id}",
        include_process_tree=False,
    )
    ev["time"] = int(ts.timestamp() * 1000)
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
# Time-range parsing
# ---------------------------------------------------------------------------


def test_parse_time_range_hours_days_weeks() -> None:
    assert parse_time_range("24h") == _dt.timedelta(hours=24)
    assert parse_time_range("7d") == _dt.timedelta(days=7)
    assert parse_time_range("4w") == _dt.timedelta(weeks=4)


def test_parse_time_range_uppercase_ok() -> None:
    assert parse_time_range("24H") == _dt.timedelta(hours=24)


def test_parse_time_range_rejects_garbage() -> None:
    with pytest.raises(TimeRangeParseError):
        parse_time_range("")
    with pytest.raises(TimeRangeParseError):
        parse_time_range("garbage")
    with pytest.raises(TimeRangeParseError):
        parse_time_range("24m")
    with pytest.raises(TimeRangeParseError):
        parse_time_range("0h")
    with pytest.raises(TimeRangeParseError):
        parse_time_range("-3d")


def test_time_range_to_filter_expr_emits_unix_ms() -> None:
    now = _dt.datetime(2026, 5, 18, 12, 0, 0, tzinfo=_dt.UTC)
    expr = time_range_to_filter_expr(_dt.timedelta(hours=24), now=now)
    assert expr.startswith("time>=")
    cutoff_ms = int(expr.split(">=", 1)[1])
    # 24h before noon 2026-05-18 UTC = noon 2026-05-17 UTC
    expected = int(
        _dt.datetime(2026, 5, 17, 12, 0, 0, tzinfo=_dt.UTC).timestamp()
        * 1000
    )
    assert cutoff_ms == expected


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


def test_starter_prompts_count_is_ten() -> None:
    assert len(STARTER_PROMPTS) == 10


def test_starter_prompts_avoid_loaded_vocabulary() -> None:
    """Per [[security-team-positioning-safety-not-surveillance]] the
    prompts must not read as accusation."""
    banned = ("violation", "infraction", "unauthorized")
    for prompt in STARTER_PROMPTS:
        lowered = prompt.lower()
        for word in banned:
            assert word not in lowered, (
                f"prompt {prompt!r} contains banned word {word!r}"
            )


def test_render_print_prompts_block_lists_all_ten() -> None:
    out = render_print_prompts_block()
    for prompt in STARTER_PROMPTS:
        assert prompt in out
    # Numbered 1..10
    for n in range(1, 11):
        assert f"{n:>2}." in out


# ---------------------------------------------------------------------------
# Window collection
# ---------------------------------------------------------------------------


def test_collect_events_filters_by_time_window(
    audit_path: pathlib.Path,
) -> None:
    now = _dt.datetime(2026, 5, 18, 12, 0, 0, tzinfo=_dt.UTC)
    recent = _event_at(now - _dt.timedelta(hours=1), decision_id=1)
    old = _event_at(now - _dt.timedelta(days=10), decision_id=2)
    _write_jsonl(audit_path, [old, recent])

    events, present = collect_events_for_window(
        audit_path, window=_dt.timedelta(hours=24), now=now,
    )
    assert present is True
    assert len(events) == 1
    assert events[0]["actor"]["session"]["uid"] == "req-1"


def test_collect_events_missing_file_reports_absent(
    tmp_path: pathlib.Path,
) -> None:
    missing = tmp_path / "does-not-exist.jsonl"
    events, present = collect_events_for_window(missing)
    assert events == []
    assert present is False


def test_collect_events_empty_file_reports_absent(
    audit_path: pathlib.Path,
) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.touch()
    events, present = collect_events_for_window(audit_path)
    assert events == []
    assert present is False


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


def test_prepare_investigation_writes_both_artifacts(
    tmp_path: pathlib.Path, audit_path: pathlib.Path,
) -> None:
    now = _dt.datetime(2026, 5, 18, 12, 0, 0, tzinfo=_dt.UTC)
    _write_jsonl(audit_path, [
        _event_at(now - _dt.timedelta(minutes=5), decision_id=1),
        _event_at(now - _dt.timedelta(minutes=10), decision_id=2),
    ])
    out_dir = tmp_path / "investigation"
    db_path = tmp_path / "state.db"
    profiles_path = tmp_path / "profiles.yaml"

    artifacts = prepare_investigation(
        out_dir=out_dir,
        audit_path=audit_path,
        window=_dt.timedelta(hours=24),
        db_path=str(db_path),
        profiles_path=str(profiles_path),
        healthz_url="http://127.0.0.1:1/healthz",  # intentionally dead
        now=now,
    )
    assert artifacts.evidence_path.exists()
    assert artifacts.context_path.exists()
    assert artifacts.evidence_path.name == INVESTIGATION_EVIDENCE_FILENAME
    assert artifacts.context_path.name == INVESTIGATION_CONTEXT_FILENAME
    assert artifacts.event_count == 2
    assert artifacts.audit_log_present is True
    assert artifacts.evidence_bytes > 100
    assert artifacts.context_bytes > 100

    body = artifacts.evidence_path.read_text(encoding="utf-8").strip()
    parsed = json.loads(body)
    assert parsed["class_uid"] == 2004
    assert parsed["unmapped"]["iam_jit"]["investigate"][
        "event_count"
    ] == 2
    assert parsed["unmapped"]["iam_jit"]["investigate"][
        "audit_log_present"
    ] is True


def test_prepare_investigation_empty_log_still_writes(
    tmp_path: pathlib.Path,
) -> None:
    missing = tmp_path / "missing.jsonl"
    out_dir = tmp_path / "investigation"
    artifacts = prepare_investigation(
        out_dir=out_dir,
        audit_path=missing,
        healthz_url="http://127.0.0.1:1/healthz",
    )
    assert artifacts.evidence_path.exists()
    assert artifacts.context_path.exists()
    assert artifacts.event_count == 0
    assert artifacts.audit_log_present is False
    # Even the "no events" finding should be non-trivial bytes
    # (the OCSF envelope is ~500 bytes).
    assert artifacts.evidence_bytes > 200

    parsed = json.loads(artifacts.evidence_path.read_text("utf-8"))
    assert parsed["unmapped"]["iam_jit"]["investigate"][
        "audit_log_present"
    ] is False
    assert parsed["unmapped"]["iam_jit"]["investigate"][
        "event_count"
    ] == 0


def test_prepare_investigation_overwrites_same_path(
    tmp_path: pathlib.Path, audit_path: pathlib.Path,
) -> None:
    """Running investigate twice into the same dir should overwrite
    cleanly rather than leave a stale forest of files."""
    _write_jsonl(audit_path, [_event_at(_dt.datetime.now(_dt.UTC))])
    out_dir = tmp_path / "investigation"
    a1 = prepare_investigation(
        out_dir=out_dir, audit_path=audit_path,
        healthz_url="http://127.0.0.1:1/healthz",
    )
    a2 = prepare_investigation(
        out_dir=out_dir, audit_path=audit_path,
        healthz_url="http://127.0.0.1:1/healthz",
    )
    assert a1.evidence_path == a2.evidence_path
    assert a2.evidence_path.exists()
    # Only ONE evidence file in the dir (overwrite, not append).
    files = sorted(p.name for p in out_dir.iterdir())
    assert files == [
        INVESTIGATION_CONTEXT_FILENAME,
        INVESTIGATION_EVIDENCE_FILENAME,
    ]


# ---------------------------------------------------------------------------
# Now-what message
# ---------------------------------------------------------------------------


def test_render_now_what_lists_artifact_paths(
    tmp_path: pathlib.Path, audit_path: pathlib.Path,
) -> None:
    _write_jsonl(audit_path, [_event_at(_dt.datetime.now(_dt.UTC))])
    artifacts = prepare_investigation(
        out_dir=tmp_path / "out", audit_path=audit_path,
        healthz_url="http://127.0.0.1:1/healthz",
    )
    msg = render_now_what_block(artifacts)
    assert str(artifacts.evidence_path) in msg
    assert str(artifacts.context_path) in msg
    # Privacy story is included by default — operators see the
    # "no Anthropic call" line without having to dig into docs.
    assert "Anthropic" in msg
    # The "now what" header surfaces the local-Claude framing per
    # [[don't-tailor-to-lighthouse]] — generic, not Claude-Code-only.
    assert "local Claude client" in msg


def test_render_now_what_flags_missing_audit_log(
    tmp_path: pathlib.Path,
) -> None:
    missing = tmp_path / "missing.jsonl"
    artifacts = prepare_investigation(
        out_dir=tmp_path / "out", audit_path=missing,
        healthz_url="http://127.0.0.1:1/healthz",
    )
    msg = render_now_what_block(artifacts)
    assert "audit log was missing" in msg


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_investigate_exits_zero_and_writes_files(
    runner: CliRunner, tmp_path: pathlib.Path, audit_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = _dt.datetime.now(_dt.UTC)
    _write_jsonl(audit_path, [
        _event_at(now - _dt.timedelta(minutes=5), decision_id=1),
        _event_at(now - _dt.timedelta(minutes=10), decision_id=2),
    ])
    out_dir = tmp_path / "out"
    monkeypatch.setenv("IAM_JIT_BOUNCER_AUDIT_LOG", str(audit_path))

    result = runner.invoke(
        main,
        [
            "investigate",
            "--out-dir", str(out_dir),
            "--time-range", "24h",
            "--healthz-url", "http://127.0.0.1:1/healthz",
            "--db", str(tmp_path / "state.db"),
            "--profiles", str(tmp_path / "profiles.yaml"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert (out_dir / INVESTIGATION_EVIDENCE_FILENAME).exists()
    assert (out_dir / INVESTIGATION_CONTEXT_FILENAME).exists()
    assert "Artifacts written" in result.output


def test_cli_investigate_print_prompts_no_files(
    runner: CliRunner, tmp_path: pathlib.Path,
) -> None:
    out_dir = tmp_path / "out"
    result = runner.invoke(
        main,
        ["investigate", "--print-prompts", "--out-dir", str(out_dir)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    for prompt in STARTER_PROMPTS:
        assert prompt in result.output
    # The dir was never created because we exited before the worker.
    assert not out_dir.exists()


def test_cli_investigate_missing_audit_log_still_succeeds(
    runner: CliRunner, tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out_dir = tmp_path / "out"
    missing = tmp_path / "missing.jsonl"
    monkeypatch.setenv("IAM_JIT_BOUNCER_AUDIT_LOG", str(missing))
    result = runner.invoke(
        main,
        [
            "investigate",
            "--out-dir", str(out_dir),
            "--healthz-url", "http://127.0.0.1:1/healthz",
            "--db", str(tmp_path / "state.db"),
            "--profiles", str(tmp_path / "profiles.yaml"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "audit log was missing" in result.output
    assert (out_dir / INVESTIGATION_EVIDENCE_FILENAME).exists()


def test_cli_investigate_rejects_bad_filter(
    runner: CliRunner, tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_AUDIT_LOG", str(tmp_path / "x.jsonl"))
    result = runner.invoke(
        main,
        [
            "investigate",
            "--out-dir", str(tmp_path / "out"),
            "--filter", "garbage_no_operator",
        ],
    )
    assert result.exit_code != 0
    assert "ERROR" in result.output


def test_cli_investigate_rejects_bad_time_range(
    runner: CliRunner, tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_AUDIT_LOG", str(tmp_path / "x.jsonl"))
    result = runner.invoke(
        main,
        [
            "investigate",
            "--out-dir", str(tmp_path / "out"),
            "--time-range", "24m",
        ],
    )
    assert result.exit_code != 0
    assert "ERROR" in result.output


def test_cli_investigate_does_not_call_outbound_hosts(
    runner: CliRunner, tmp_path: pathlib.Path, audit_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per [[self-host-zero-billing-dependency]] investigate must
    never reach an outbound host. We monkeypatch the socket layer
    so any non-loopback dial raises — the loopback /healthz GET
    targets 127.0.0.1 and is permitted; anything else fails the
    test."""
    import socket as _socket

    real_getaddrinfo = _socket.getaddrinfo
    real_create_connection = _socket.create_connection

    def fake_create_connection(address, *args, **kwargs):
        host, _port = address
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(
                f"investigate attempted outbound dial to {address!r}"
            )
        return real_create_connection(address, *args, **kwargs)

    def fake_getaddrinfo(host, *args, **kwargs):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(
                f"investigate attempted outbound DNS for {host!r}"
            )
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(_socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(_socket, "getaddrinfo", fake_getaddrinfo)

    _write_jsonl(audit_path, [_event_at(_dt.datetime.now(_dt.UTC))])
    monkeypatch.setenv("IAM_JIT_BOUNCER_AUDIT_LOG", str(audit_path))
    result = runner.invoke(
        main,
        [
            "investigate",
            "--out-dir", str(tmp_path / "out"),
            "--healthz-url", "http://127.0.0.1:1/healthz",
            "--db", str(tmp_path / "state.db"),
            "--profiles", str(tmp_path / "profiles.yaml"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
