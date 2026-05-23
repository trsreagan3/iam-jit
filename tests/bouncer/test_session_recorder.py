"""Tests for the session recorder + the `ibounce session` CLI (#285).

Per the spec:

- ``--record-sessions-dir`` creates per-session files; multiple sessions
  produce multiple files
- File contains a ``_meta`` header followed by OCSF events
- ``session list`` enumerates files + event counts + timestamps
- ``session show <id>`` prints summary; bad ID -> clean error
- ``session export <id>`` produces an OCSF Detection Finding
- ``session purge --older-than X`` removes only old files
- Empty sessions dir -> list shows nothing (not error)
- File permissions are 0o600
- Sentinel grep: an event containing ``sentinel-XYZ`` APPEARS in the
  recording file (we WANT data captured here, unlike redacted exports)
- No data from one session_id leaks into another's file
"""

from __future__ import annotations

import json
import os
import pathlib
import time

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import (
    RECORDING_FILE_MODE,
    RECORDING_SCHEMA_VERSION,
    SessionRecorder,
    detection_finding_from_session,
    event_count_by_type,
    extract_session_id,
    is_valid_session_id,
    list_sessions,
    purge_older_than,
    read_session,
    read_session_file,
)
from iam_jit.bouncer_cli import main as ibounce_main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    session_id: str,
    *,
    operation: str = "s3:GetObject",
    verdict: str = "allow",
    agent_name: str = "claude-code",
    extra: dict | None = None,
    time_ms: int | None = None,
) -> dict:
    ev: dict = {
        "metadata": {"version": "1.1.0"},
        "time": time_ms if time_ms is not None else int(time.time() * 1000),
        "class_uid": 6003,
        "class_name": "API Activity",
        "activity_id": 1,
        "activity_name": operation,
        "api": {
            "operation": operation,
            "service": {"name": operation.split(":")[0]},
        },
        "actor": {
            "user": {"uid": "arn:aws:iam::111122223333:user/dev"},
        },
        "resources": [],
        "unmapped": {
            "iam_jit": {
                "verdict": verdict,
                "profile": "safe-default",
                "agent": {
                    "session_id": session_id,
                    "name": agent_name,
                    "detected_from": "mcp_clientinfo",
                },
            },
        },
    }
    if extra:
        ev["unmapped"]["iam_jit"].update(extra)
    return ev


# Use UUIDv7-shaped IDs throughout. The validator accepts any [A-Za-z0-9_-]
# string up to 128 chars, but matching the real shape catches schema
# drift sooner.
SID_A = "01956c44-c5c1-7c31-9bca-7c0aaa000001"
SID_B = "01956c44-c5c1-7c31-9bca-7c0aaa000099"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class TestSessionIdValidation:
    def test_uuid_accepted(self) -> None:
        assert is_valid_session_id(SID_A)

    def test_path_traversal_rejected(self) -> None:
        assert not is_valid_session_id("../../etc/passwd")

    def test_slash_rejected(self) -> None:
        assert not is_valid_session_id("a/b")

    def test_empty_rejected(self) -> None:
        assert not is_valid_session_id("")

    def test_non_string_rejected(self) -> None:
        assert not is_valid_session_id(None)
        assert not is_valid_session_id(123)

    def test_extract_pulls_session_id(self) -> None:
        ev = _make_event(SID_A)
        assert extract_session_id(ev) == SID_A

    def test_extract_returns_none_when_no_agent(self) -> None:
        ev = _make_event(SID_A)
        del ev["unmapped"]["iam_jit"]["agent"]
        assert extract_session_id(ev) is None


# ---------------------------------------------------------------------------
# Recording lifecycle
# ---------------------------------------------------------------------------


class TestSessionRecorder:
    def test_multiple_sessions_produce_multiple_files(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(SID_A))
            rec.record(_make_event(SID_B))
            rec.record(_make_event(SID_A))
        finally:
            rec.stop()
        files = sorted(tmp_path.glob("*.ndjson"))
        assert len(files) == 2
        names = {f.name for f in files}
        assert f"{SID_A}.ndjson" in names
        assert f"{SID_B}.ndjson" in names

    def test_file_starts_with_meta_header(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(SID_A))
        finally:
            rec.stop()
        path = tmp_path / f"{SID_A}.ndjson"
        lines = path.read_text().splitlines()
        first = json.loads(lines[0])
        assert "_meta" in first
        meta = first["_meta"]
        assert meta["recording_schema_version"] == RECORDING_SCHEMA_VERSION
        assert meta["session_id"] == SID_A
        assert meta["bouncer_product"] == "ibounce"
        assert meta["agent_name"] == "claude-code"
        assert "recording_started_at" in meta

    def test_events_after_header_are_ocsf(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(SID_A, operation="s3:ListBuckets"))
            rec.record(_make_event(SID_A, operation="s3:GetObject"))
        finally:
            rec.stop()
        lines = (tmp_path / f"{SID_A}.ndjson").read_text().splitlines()
        events = [json.loads(line) for line in lines[1:]]
        assert [e["api"]["operation"] for e in events] == [
            "s3:ListBuckets",
            "s3:GetObject",
        ]

    def test_file_permissions_0o600(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(SID_A))
        finally:
            rec.stop()
        path = tmp_path / f"{SID_A}.ndjson"
        mode = os.stat(path).st_mode & 0o777
        assert mode == RECORDING_FILE_MODE, (
            f"recording file perms must be 0o{RECORDING_FILE_MODE:o}; "
            f"got 0o{mode:o}"
        )

    def test_event_without_session_id_is_dropped(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            ev = _make_event(SID_A)
            del ev["unmapped"]["iam_jit"]["agent"]
            rec.record(ev)
        finally:
            rec.stop()
        assert list(tmp_path.glob("*.ndjson")) == []
        assert rec.status()["dropped_events"] == 1

    def test_no_cross_session_leakage(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A SENTINEL value in session A's event must NOT appear in
        session B's file. This is the spec's "no data from one
        session_id leaks into another's file" test."""
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(
                SID_A,
                extra={"sentinel": "sentinel-AAA-only-in-A"},
            ))
            rec.record(_make_event(
                SID_B,
                extra={"sentinel": "sentinel-BBB-only-in-B"},
            ))
        finally:
            rec.stop()
        file_a = (tmp_path / f"{SID_A}.ndjson").read_text()
        file_b = (tmp_path / f"{SID_B}.ndjson").read_text()
        assert "sentinel-AAA-only-in-A" in file_a
        assert "sentinel-AAA-only-in-A" not in file_b
        assert "sentinel-BBB-only-in-B" in file_b
        assert "sentinel-BBB-only-in-B" not in file_a

    def test_sentinel_grep_data_captured(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Per the spec's sentinel test: seed an event containing
        ``sentinel-XYZ`` and assert it APPEARS in the recording. The
        recording is the *unredacted* source of truth — unlike redacted
        exports, we WANT the data captured here.
        """
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(
                SID_A,
                extra={"resource_arn": "arn:aws:s3:::bucket/sentinel-XYZ"},
            ))
        finally:
            rec.stop()
        content = (tmp_path / f"{SID_A}.ndjson").read_text()
        assert "sentinel-XYZ" in content

    def test_partial_suffix_during_session(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        rec.record(_make_event(SID_A))
        # BEFORE stop(): .partial visible, final not yet.
        assert (tmp_path / f"{SID_A}.ndjson.partial").exists()
        assert not (tmp_path / f"{SID_A}.ndjson").exists()
        rec.stop()
        # AFTER stop(): atomic rename — final visible, .partial gone.
        assert not (tmp_path / f"{SID_A}.ndjson.partial").exists()
        assert (tmp_path / f"{SID_A}.ndjson").exists()

    def test_finalise_idle_renames_stale_session(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(
            dir=tmp_path,
            bouncer_product="ibounce",
            heartbeat_timeout_seconds=60,
        )
        rec.start()
        rec.record(_make_event(SID_A))
        # Advance the clock past the heartbeat by passing an explicit
        # `now` 10 minutes in the future.
        future = time.time() + 600
        finalised = rec.finalise_idle(now=future)
        assert finalised == [SID_A]
        assert (tmp_path / f"{SID_A}.ndjson").exists()
        assert not (tmp_path / f"{SID_A}.ndjson.partial").exists()
        rec.stop()

    def test_startup_finalises_stale_partials(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A `.partial` left by a prior SIGKILL should be finalised
        when the next start() runs."""
        # Hand-craft a stale .partial file.
        stale = tmp_path / f"{SID_A}.ndjson.partial"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text(
            json.dumps({"_meta": {"session_id": SID_A}}) + "\n"
        )
        # Backdate mtime well past the heartbeat.
        old = time.time() - 10_000
        os.utime(stale, (old, old))
        rec = SessionRecorder(
            dir=tmp_path,
            bouncer_product="ibounce",
            heartbeat_timeout_seconds=60,
        )
        rec.start()
        try:
            assert not (tmp_path / f"{SID_A}.ndjson.partial").exists()
            assert (tmp_path / f"{SID_A}.ndjson").exists()
        finally:
            rec.stop()


# ---------------------------------------------------------------------------
# Listing / read helpers
# ---------------------------------------------------------------------------


class TestListAndRead:
    def test_empty_dir_returns_empty_list(
        self, tmp_path: pathlib.Path
    ) -> None:
        assert list_sessions(tmp_path) == []

    def test_nonexistent_dir_returns_empty_list(
        self, tmp_path: pathlib.Path
    ) -> None:
        ghost = tmp_path / "does-not-exist"
        assert list_sessions(ghost) == []

    def test_list_reports_event_counts(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            for _ in range(3):
                rec.record(_make_event(SID_A))
            rec.record(_make_event(SID_B))
        finally:
            rec.stop()
        rows = {r["session_id"]: r for r in list_sessions(tmp_path)}
        assert rows[SID_A]["event_count"] == 3
        assert rows[SID_B]["event_count"] == 1
        assert rows[SID_A]["agent_name"] == "claude-code"

    def test_list_reports_start_and_end_timestamps(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(SID_A, time_ms=1_700_000_000_000))
            rec.record(_make_event(SID_A, time_ms=1_700_000_010_000))
        finally:
            rec.stop()
        row = list_sessions(tmp_path)[0]
        assert row["start_ms"] == 1_700_000_000_000
        assert row["end_ms"] == 1_700_000_010_000

    def test_read_session_round_trips_meta_and_events(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(SID_A, operation="s3:Get"))
            rec.record(_make_event(SID_A, operation="s3:List"))
        finally:
            rec.stop()
        meta, events = read_session(tmp_path, SID_A)
        assert meta["session_id"] == SID_A
        assert meta["bouncer_product"] == "ibounce"
        assert len(events) == 2
        assert events[0]["api"]["operation"] == "s3:Get"

    def test_read_session_rejects_invalid_id(
        self, tmp_path: pathlib.Path
    ) -> None:
        with pytest.raises(ValueError):
            read_session(tmp_path, "../../etc/passwd")

    def test_read_session_file_missing_raises(
        self, tmp_path: pathlib.Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            read_session_file(tmp_path / "nope.ndjson")

    def test_event_count_by_type(
        self, tmp_path: pathlib.Path
    ) -> None:
        events = [
            _make_event(SID_A, operation="s3:GetObject"),
            _make_event(SID_A, operation="s3:GetObject"),
            _make_event(SID_A, operation="s3:ListBuckets"),
        ]
        counts = event_count_by_type(events)
        assert counts == {"s3:GetObject": 2, "s3:ListBuckets": 1}


# ---------------------------------------------------------------------------
# Detection Finding export shape
# ---------------------------------------------------------------------------


class TestExportShape:
    def test_detection_finding_wraps_session(
        self, tmp_path: pathlib.Path
    ) -> None:
        rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
        rec.start()
        try:
            rec.record(_make_event(SID_A, time_ms=1_700_000_000_000))
            rec.record(_make_event(SID_A, time_ms=1_700_000_010_000))
        finally:
            rec.stop()
        meta, events = read_session(tmp_path, SID_A)
        finding = detection_finding_from_session(meta, events)
        assert finding["class_uid"] == 2004
        assert finding["class_name"] == "Detection Finding"
        assert finding["start_time"] == 1_700_000_000_000
        assert finding["end_time"] == 1_700_000_010_000
        sess = finding["unmapped"]["iam_jit"]["session"]
        assert sess["session_id"] == SID_A
        assert sess["event_count"] == 2
        assert len(sess["events"]) == 2


# ---------------------------------------------------------------------------
# Purge
# ---------------------------------------------------------------------------


class TestPurge:
    def test_purge_removes_only_old_files(
        self, tmp_path: pathlib.Path
    ) -> None:
        old = tmp_path / f"{SID_A}.ndjson"
        new = tmp_path / f"{SID_B}.ndjson"
        old.write_text("{}\n")
        new.write_text("{}\n")
        # Backdate `old` to 40 days ago.
        old_mtime = time.time() - (40 * 86400)
        os.utime(old, (old_mtime, old_mtime))
        removed = purge_older_than(tmp_path, older_than_seconds=30 * 86400)
        assert str(old) in removed
        assert str(new) not in removed
        assert not old.exists()
        assert new.exists()

    def test_purge_skips_partial_files(
        self, tmp_path: pathlib.Path
    ) -> None:
        """`.partial` files belong to live sessions; even if stale on
        disk, purge leaves them alone (the recorder's start() recovery
        path owns finalisation)."""
        partial = tmp_path / f"{SID_A}.ndjson.partial"
        partial.write_text("{}\n")
        old = time.time() - (90 * 86400)
        os.utime(partial, (old, old))
        removed = purge_older_than(tmp_path, older_than_seconds=30 * 86400)
        assert removed == []
        assert partial.exists()


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------


class TestSessionCli:
    def _seed_two_sessions(self, dir_: pathlib.Path) -> None:
        rec = SessionRecorder(dir=dir_, bouncer_product="ibounce")
        rec.start()
        try:
            for _ in range(3):
                rec.record(_make_event(SID_A))
            rec.record(_make_event(SID_B, agent_name="cursor"))
        finally:
            rec.stop()

    def test_session_list_empty_dir_clean_message(
        self, tmp_path: pathlib.Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            ["session", "list", "--dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "no recordings" in result.output

    def test_session_list_enumerates_sessions(
        self, tmp_path: pathlib.Path
    ) -> None:
        self._seed_two_sessions(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            ["session", "list", "--dir", str(tmp_path)],
        )
        assert result.exit_code == 0, result.output
        assert SID_A in result.output
        assert SID_B in result.output
        assert "claude-code" in result.output
        assert "cursor" in result.output

    def test_session_list_json(self, tmp_path: pathlib.Path) -> None:
        self._seed_two_sessions(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            ["session", "list", "--dir", str(tmp_path), "--json"],
        )
        assert result.exit_code == 0
        rows = json.loads(result.output)
        sids = {r["session_id"] for r in rows}
        assert sids == {SID_A, SID_B}

    def test_session_show_summary(
        self, tmp_path: pathlib.Path
    ) -> None:
        self._seed_two_sessions(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            ["session", "show", SID_A, "--dir", str(tmp_path)],
        )
        assert result.exit_code == 0, result.output
        assert "ibounce" in result.output
        assert "event_count:       3" in result.output

    def test_session_show_bad_id_clean_error(
        self, tmp_path: pathlib.Path
    ) -> None:
        runner = CliRunner()
        # Valid format but no file present.
        result = runner.invoke(
            ibounce_main,
            ["session", "show", SID_A, "--dir", str(tmp_path)],
        )
        assert result.exit_code == 2
        assert "no recording" in result.output.lower()

    def test_session_show_traversal_attempt_clean_error(
        self, tmp_path: pathlib.Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            ["session", "show", "../etc/passwd", "--dir", str(tmp_path)],
        )
        assert result.exit_code == 2
        assert "invalid session_id" in result.output.lower()

    def test_session_export_produces_detection_finding(
        self, tmp_path: pathlib.Path
    ) -> None:
        self._seed_two_sessions(tmp_path)
        out_path = tmp_path / "exported.json"
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            [
                "session", "export", SID_A,
                "--dir", str(tmp_path),
                "--out", str(out_path),
            ],
        )
        assert result.exit_code == 0, result.output
        body = json.loads(out_path.read_text())
        assert body["class_uid"] == 2004
        assert body["class_name"] == "Detection Finding"
        assert (
            body["unmapped"]["iam_jit"]["session"]["session_id"] == SID_A
        )
        # The export file inherits 0o600 — it carries the same
        # sensitive content as the source recording.
        mode = os.stat(out_path).st_mode & 0o777
        assert mode == 0o600

    def test_session_purge_dry_run(
        self, tmp_path: pathlib.Path
    ) -> None:
        # Seed two sessions, backdate one.
        self._seed_two_sessions(tmp_path)
        old = tmp_path / f"{SID_A}.ndjson"
        old_mtime = time.time() - (40 * 86400)
        os.utime(old, (old_mtime, old_mtime))
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            [
                "session", "purge",
                "--dir", str(tmp_path),
                "--older-than", "30d",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "would remove 1 recording(s)" in result.output
        # File still exists after dry-run.
        assert old.exists()

    def test_session_purge_removes_old(
        self, tmp_path: pathlib.Path
    ) -> None:
        self._seed_two_sessions(tmp_path)
        old = tmp_path / f"{SID_A}.ndjson"
        old_mtime = time.time() - (40 * 86400)
        os.utime(old, (old_mtime, old_mtime))
        runner = CliRunner()
        result = runner.invoke(
            ibounce_main,
            [
                "session", "purge",
                "--dir", str(tmp_path),
                "--older-than", "30d",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "removed 1 recording(s)" in result.output
        assert not old.exists()
        # The newer one survives.
        assert (tmp_path / f"{SID_B}.ndjson").exists()

    def test_no_forbidden_words_in_user_facing_output(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Per [[security-team-positioning-safety-not-surveillance]]
        the surface must not lapse into adversarial language. Sweep the
        help text for the suite's three forbidden words."""
        runner = CliRunner()
        result = runner.invoke(ibounce_main, ["session", "--help"])
        assert result.exit_code == 0
        lower = result.output.lower()
        for forbidden in ("violation", "infraction", "unauthorized"):
            assert forbidden not in lower
        for sub in ("list", "show", "export", "purge"):
            sub_result = runner.invoke(
                ibounce_main, ["session", sub, "--help"],
            )
            assert sub_result.exit_code == 0
            sub_lower = sub_result.output.lower()
            for forbidden in ("violation", "infraction", "unauthorized"):
                assert forbidden not in sub_lower, (
                    f"forbidden word {forbidden!r} found in `session "
                    f"{sub} --help`"
                )


# ---------------------------------------------------------------------------
# §A30 / #359 — stop() idempotency tests.
#
# The proxy now installs a SIGTERM handler that triggers serve()'s
# `finally` block, which calls recorder.stop(). The handler is fire-
# and-forget; a second SIGTERM during shutdown can race with the first.
# stop() MUST be safe to call twice (or N times) without crashing.
# The end-to-end subprocess test lives in test_proxy_signal_shutdown.py.
# ---------------------------------------------------------------------------


SID_A_IDEMP = "11111111-1111-1111-1111-111111111111"


def test_session_recorder_stop_is_idempotent_after_finalization(
    tmp_path: pathlib.Path,
) -> None:
    """§A30 — calling stop() twice MUST NOT crash + the second call
    is a no-op (final file stays, no new partial appears)."""
    rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
    rec.start()
    rec.record(_make_event(SID_A_IDEMP))
    rec.stop()
    final = tmp_path / f"{SID_A_IDEMP}.ndjson"
    partial = tmp_path / f"{SID_A_IDEMP}.ndjson.partial"
    assert final.exists()
    assert not partial.exists()

    # Second stop() should be a clean no-op.
    rec.stop()
    assert final.exists(), "second stop() must not destroy the final file"
    assert not partial.exists()


def test_session_recorder_stop_idempotent_with_no_active_sessions(
    tmp_path: pathlib.Path,
) -> None:
    """§A30 — stop() with no events recorded (no session opened) MUST
    NOT crash. Covers the SIGTERM-before-first-request case."""
    rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
    rec.start()
    rec.stop()
    rec.stop()  # second call still a no-op


def test_session_recorder_stop_without_start_is_noop(
    tmp_path: pathlib.Path,
) -> None:
    """§A30 — defensive: stop() before start() is a no-op (avoids the
    case where serve()'s finally fires before start() ran).
    """
    rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
    rec.stop()  # never started; MUST NOT raise


def test_session_recorder_stop_finalizes_all_active_sessions(
    tmp_path: pathlib.Path,
) -> None:
    """§A30 — multiple concurrent sessions all get finalised by a
    single stop(). Covers the SIGTERM-during-N-active-sessions case
    (the most common reason for stale .partial files in the field)."""
    sids = [
        "aaaaaaaa-1111-2222-3333-444444444444",
        "bbbbbbbb-1111-2222-3333-444444444444",
        "cccccccc-1111-2222-3333-444444444444",
    ]
    rec = SessionRecorder(dir=tmp_path, bouncer_product="ibounce")
    rec.start()
    for sid in sids:
        rec.record(_make_event(sid))
    # Sanity: all three sessions have a .partial right now.
    for sid in sids:
        assert (tmp_path / f"{sid}.ndjson.partial").exists()
        assert not (tmp_path / f"{sid}.ndjson").exists()
    # The simulated SIGTERM path.
    rec.stop()
    for sid in sids:
        assert not (tmp_path / f"{sid}.ndjson.partial").exists(), (
            f"session {sid} left a .partial after stop()"
        )
        assert (tmp_path / f"{sid}.ndjson").exists(), (
            f"session {sid} did not get finalised by stop()"
        )
