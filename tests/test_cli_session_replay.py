"""Tests for the cross-product `iam-jit session replay <FILE>` CLI (#285).

Per the spec:

- Default mode prints events in order
- ``--realtime`` sleeps approximate-correctly between events
- ``--what-if-profile`` loads the named profile + reports diffs
  (ibounce-only for now; non-ibounce recordings get a stderr gap note)
- ``--filter`` applies
- ``--max-events`` caps
- Bad file -> clean error
- Mock bouncer library for tests (no live bouncer needed)
"""

from __future__ import annotations

import json
import pathlib
import time
from unittest import mock

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import RECORDING_SCHEMA_VERSION
from iam_jit.cli import main as iam_jit_main


SID = "01956c44-c5c1-7c31-9bca-7c0aaa000777"


def _write_recording(
    path: pathlib.Path,
    *,
    bouncer_product: str = "ibounce",
    agent_name: str = "claude-code",
    events: list[dict] | None = None,
) -> None:
    """Hand-craft a recording file. We don't go through the recorder so
    the test can produce arbitrary verdicts + times deterministically."""
    if events is None:
        events = []
    header = {
        "_meta": {
            "recording_schema_version": RECORDING_SCHEMA_VERSION,
            "session_id": SID,
            "agent_name": agent_name,
            "bouncer_product": bouncer_product,
            "recording_started_at": "2026-05-18T10:14:22Z",
        }
    }
    with path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(header) + "\n")
        for ev in events:
            fh.write(json.dumps(ev) + "\n")


def _ev(
    *,
    operation: str,
    verdict: str = "allow",
    time_ms: int,
    service: str | None = None,
) -> dict:
    svc = service if service is not None else operation.split(":")[0]
    return {
        "time": time_ms,
        "class_uid": 6003,
        "class_name": "API Activity",
        "activity_name": operation,
        "api": {
            "operation": operation,
            "service": {"name": svc},
        },
        "actor": {"user": {"uid": "arn:aws:iam::111122223333:user/dev"}},
        "resources": [],
        "unmapped": {
            "iam_jit": {
                "verdict": verdict,
                "profile": "full-user",
                "agent": {"session_id": SID, "name": "claude-code"},
            }
        },
    }


class TestSessionReplayCli:
    def test_replay_prints_events_in_order(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "session.ndjson"
        _write_recording(
            path,
            events=[
                _ev(operation="s3:ListBuckets", time_ms=1_700_000_000_000),
                _ev(operation="s3:GetObject", time_ms=1_700_000_001_000),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main, ["session", "replay", str(path)]
        )
        assert result.exit_code == 0, result.output
        # Both operations appear, in order.
        idx_list = result.output.find("s3:ListBuckets")
        idx_get = result.output.find("s3:GetObject")
        assert 0 < idx_list < idx_get
        # Delta between event 1 and event 2 is ~1.000s.
        assert "+1.000s" in result.output

    def test_replay_json_mode_emits_objects(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "session.ndjson"
        _write_recording(
            path,
            events=[
                _ev(operation="s3:ListBuckets", time_ms=1_700_000_000_000),
                _ev(operation="s3:GetObject", time_ms=1_700_000_002_500),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main, ["session", "replay", str(path), "--json"]
        )
        assert result.exit_code == 0
        lines = [
            line for line in result.output.splitlines() if line.startswith("{")
        ]
        assert len(lines) == 2
        obj1 = json.loads(lines[0])
        obj2 = json.loads(lines[1])
        assert obj1["delta_seconds"] is None
        assert obj2["delta_seconds"] == pytest.approx(2.5, rel=0.01)

    def test_replay_max_events_caps(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "session.ndjson"
        _write_recording(
            path,
            events=[
                _ev(operation="s3:Op1", time_ms=1_700_000_000_000),
                _ev(operation="s3:Op2", time_ms=1_700_000_001_000),
                _ev(operation="s3:Op3", time_ms=1_700_000_002_000),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            ["session", "replay", str(path), "--max-events", "2"],
        )
        assert result.exit_code == 0
        assert "s3:Op1" in result.output
        assert "s3:Op2" in result.output
        assert "s3:Op3" not in result.output

    def test_replay_filter_applies(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "session.ndjson"
        _write_recording(
            path,
            events=[
                _ev(operation="s3:GetObject", time_ms=1_700_000_000_000),
                _ev(operation="iam:CreateUser", time_ms=1_700_000_001_000,
                    service="iam"),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            [
                "session", "replay", str(path),
                "--filter", "api.service.name=s3",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "s3:GetObject" in result.output
        assert "iam:CreateUser" not in result.output

    def test_replay_filter_regex_match(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "session.ndjson"
        _write_recording(
            path,
            events=[
                _ev(operation="s3:GetObject", verdict="allow",
                    time_ms=1_700_000_000_000),
                _ev(operation="s3:DeleteBucket", verdict="deny",
                    time_ms=1_700_000_001_000),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            [
                "session", "replay", str(path),
                "--filter", "unmapped.iam_jit.verdict~^den",
            ],
        )
        assert result.exit_code == 0
        assert "s3:DeleteBucket" in result.output
        assert "s3:GetObject" not in result.output

    def test_replay_missing_file_clean_error(
        self, tmp_path: pathlib.Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            ["session", "replay", str(tmp_path / "nope.ndjson")],
        )
        assert result.exit_code == 2
        assert "not found" in result.output.lower()

    def test_replay_realtime_sleeps_approximately(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "session.ndjson"
        # Two events ~150ms apart so the test isn't too slow.
        _write_recording(
            path,
            events=[
                _ev(operation="s3:Op1", time_ms=1_700_000_000_000),
                _ev(operation="s3:Op2", time_ms=1_700_000_000_150),
            ],
        )
        runner = CliRunner()
        t0 = time.monotonic()
        result = runner.invoke(
            iam_jit_main,
            ["session", "replay", str(path), "--realtime"],
        )
        elapsed = time.monotonic() - t0
        assert result.exit_code == 0
        # Expect AT LEAST the ~150ms gap; tolerate generous overhead.
        assert elapsed >= 0.10, (
            f"realtime mode should pause between events; took {elapsed:.3f}s"
        )

    def test_replay_what_if_non_ibounce_surfaces_gap(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Per the spec: if a bouncer's profile evaluator isn't easily
        callable from outside, skip --what-if for that product +
        document the gap. The CLI surfaces a clear yellow stderr note
        and continues with the replay."""
        path = tmp_path / "session.ndjson"
        _write_recording(
            path,
            bouncer_product="kbouncer",
            events=[
                _ev(operation="s3:GetObject", time_ms=1_700_000_000_000),
            ],
        )
        # Newer click merges stderr into output by default; the
        # gap-note still fires, just lands in `result.output` rather
        # than a separate stream. Either way is fine for the assertion.
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            [
                "session", "replay", str(path),
                "--what-if-profile", "safe-default",
            ],
        )
        assert result.exit_code == 0, result.output
        # Replay still prints the event AND the gap is announced.
        assert "s3:GetObject" in result.output
        assert "only wired for ibounce" in result.output

    def test_replay_what_if_ibounce_reports_diff(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Mock the local profile loader so the test doesn't depend on
        the operator's local profile store. The what-if path is the
        only code under test; the loader is glue."""
        path = tmp_path / "session.ndjson"
        # Recorded verdict was 'allow'; what-if profile will return
        # 'deny' so the diff is non-empty.
        _write_recording(
            path,
            bouncer_product="ibounce",
            events=[
                _ev(operation="s3:DeleteBucket", verdict="allow",
                    time_ms=1_700_000_000_000),
            ],
        )
        fake_evaluator = lambda ev: ("deny", "profile blocks s3:DeleteBucket")
        with mock.patch(
            "iam_jit.cli_session_replay._what_if_evaluator",
            return_value=(fake_evaluator, "mocked-readonly"),
        ):
            runner = CliRunner()
            result = runner.invoke(
                iam_jit_main,
                [
                    "session", "replay", str(path),
                    "--what-if-profile", "mocked-readonly",
                ],
            )
        assert result.exit_code == 0, result.output
        # Summary + diff line both present.
        assert "what-if vs recorded" in result.output
        assert "differed" in result.output
        assert "differences:" in result.output
        assert "recorded=allow" in result.output
        assert "what-if=deny" in result.output
