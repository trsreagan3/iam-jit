"""Tests for the plan-capture reader / writer."""

from __future__ import annotations

import gzip
import json
import pathlib

import pytest

from iam_jit.plan_capture import (
    SCHEMA_VERSION_V1ALPHA1,
    CapturedCall,
    PlanCaptureError,
    parse_line,
    read_capture,
    read_captures,
    summarize,
    write_capture,
)


def _line(**overrides) -> str:  # type: ignore[no-untyped-def]
    base = {
        "schema": SCHEMA_VERSION_V1ALPHA1,
        "ts": "2026-05-16T14:22:01.503Z",
        "service": "s3",
        "action": "ListBuckets",
        "region": "us-east-1",
        "iam_jit": {
            "iam_action": "s3:ListBuckets",
            "iam_resource": "*",
            "access_type": "read-only",
        },
    }
    base.update(overrides)
    return json.dumps(base)


def test_parse_line_minimal_ok() -> None:
    call = parse_line(_line())
    assert call.service == "s3"
    assert call.iam_action == "s3:ListBuckets"
    assert call.is_read_only is True


def test_parse_line_unknown_schema_rejected() -> None:
    bad = _line(schema="something-else/v0")
    with pytest.raises(PlanCaptureError, match="unsupported schema"):
        parse_line(bad)


def test_parse_line_missing_required_field_rejected() -> None:
    line = json.dumps({
        "schema": SCHEMA_VERSION_V1ALPHA1,
        "ts": "2026-05-16T14:22:01.503Z",
        # missing service
        "action": "ListBuckets",
        "region": "us-east-1",
        "iam_jit": {
            "iam_action": "s3:ListBuckets",
            "iam_resource": "*",
            "access_type": "read-only",
        },
    })
    with pytest.raises(PlanCaptureError, match="missing/invalid required field 'service'"):
        parse_line(line)


def test_parse_line_iam_jit_block_required() -> None:
    line = json.dumps({
        "schema": SCHEMA_VERSION_V1ALPHA1,
        "ts": "2026-05-16T14:22:01.503Z",
        "service": "s3",
        "action": "ListBuckets",
        "region": "us-east-1",
        # missing iam_jit
    })
    with pytest.raises(PlanCaptureError, match="iam_jit"):
        parse_line(line)


def test_parse_line_iam_resource_array_normalized_to_tuple() -> None:
    line = _line(iam_jit={
        "iam_action": "s3:GetObject",
        "iam_resource": ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"],
        "access_type": "read-only",
    })
    call = parse_line(line)
    assert call.iam_resource == ("arn:aws:s3:::a/*", "arn:aws:s3:::b/*")


def test_parse_line_iam_resource_array_must_be_strings() -> None:
    line = _line(iam_jit={
        "iam_action": "s3:GetObject",
        "iam_resource": ["valid", 42],
        "access_type": "read-only",
    })
    with pytest.raises(PlanCaptureError, match="array must contain strings"):
        parse_line(line)


def test_parse_line_blank_line_rejected() -> None:
    with pytest.raises(PlanCaptureError, match="blank lines"):
        parse_line("")


def test_parse_line_invalid_json() -> None:
    with pytest.raises(PlanCaptureError, match="invalid JSON"):
        parse_line("{not json")


# ---------------------------------------------------------------------------
# File reading.
# ---------------------------------------------------------------------------


def test_read_capture_roundtrip(tmp_path: pathlib.Path) -> None:
    src = [
        CapturedCall(
            ts="2026-05-16T14:22:01.000Z",
            service="s3", action="ListBuckets", region="us-east-1",
            iam_action="s3:ListBuckets", iam_resource="*",
            access_type="read-only",
        ),
        CapturedCall(
            ts="2026-05-16T14:22:02.000Z",
            service="ec2", action="DescribeInstances", region="us-east-1",
            iam_action="ec2:DescribeInstances", iam_resource="*",
            access_type="read-only",
        ),
    ]
    p = tmp_path / "plan.jsonl"
    n = write_capture(p, src)
    assert n == 2
    out = list(read_capture(p))
    assert len(out) == 2
    assert out[0].iam_action == "s3:ListBuckets"
    assert out[1].service == "ec2"


def test_read_capture_gzip(tmp_path: pathlib.Path) -> None:
    src = [
        CapturedCall(
            ts="2026-05-16T14:22:01.000Z",
            service="s3", action="ListBuckets", region="us-east-1",
            iam_action="s3:ListBuckets", iam_resource="*",
            access_type="read-only",
        )
    ]
    p = tmp_path / "plan.jsonl.gz"
    write_capture(p, src)
    out = list(read_capture(p))
    assert len(out) == 1
    assert out[0].iam_action == "s3:ListBuckets"


def test_read_captures_multiple_files(tmp_path: pathlib.Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    write_capture(a, [CapturedCall(
        ts="t1", service="s3", action="A", region="us-east-1",
        iam_action="s3:A", iam_resource="*", access_type="read-only",
    )])
    write_capture(b, [CapturedCall(
        ts="t2", service="ec2", action="B", region="us-east-1",
        iam_action="ec2:B", iam_resource="*", access_type="read-write",
    )])
    out = list(read_captures([a, b]))
    assert [c.iam_action for c in out] == ["s3:A", "ec2:B"]


def test_read_capture_trailing_blank_lines_skipped(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "plan.jsonl"
    p.write_text(_line() + "\n\n\n")
    out = list(read_capture(p))
    assert len(out) == 1


def test_read_capture_malformed_line_aborts(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "plan.jsonl"
    p.write_text(_line() + "\n{not-json}\n")
    with pytest.raises(PlanCaptureError, match="line 2: invalid JSON"):
        list(read_capture(p))


# ---------------------------------------------------------------------------
# summarize()
# ---------------------------------------------------------------------------


def test_summarize_rolls_up_correctly() -> None:
    calls = [
        CapturedCall(
            ts="t", service="s3", action="ListBuckets", region="us-east-1",
            iam_action="s3:ListBuckets", iam_resource="*", access_type="read-only",
        ),
        CapturedCall(
            ts="t", service="s3", action="GetBucketLocation", region="us-east-1",
            iam_action="s3:GetBucketLocation",
            iam_resource=("arn:aws:s3:::a", "arn:aws:s3:::b"),
            access_type="read-only",
        ),
        CapturedCall(
            ts="t", service="ec2", action="DescribeInstances", region="us-east-1",
            iam_action="ec2:DescribeInstances", iam_resource="*",
            access_type="read-only",
        ),
    ]
    s = summarize(calls)
    assert s["total"] == 3
    assert s["by_service"] == {"s3": 2, "ec2": 1}
    assert s["by_access_type"] == {"read-only": 3}
    assert s["iam_actions"] == [
        "ec2:DescribeInstances", "s3:GetBucketLocation", "s3:ListBuckets",
    ]
    assert "arn:aws:s3:::a" in s["resources_touched"]
    assert "arn:aws:s3:::b" in s["resources_touched"]


def test_summarize_empty() -> None:
    s = summarize([])
    assert s["total"] == 0
    assert s["by_service"] == {}
    assert s["iam_actions"] == []


# WB11-09 regression: iam_resource: null is rejected, not silently
# normalised to "*".
def test_parse_line_iam_resource_null_rejected() -> None:
    line = json.dumps({
        "schema": SCHEMA_VERSION_V1ALPHA1,
        "ts": "2026-05-16T14:22:01.503Z",
        "service": "s3",
        "action": "ListBuckets",
        "region": "us-east-1",
        "iam_jit": {
            "iam_action": "s3:ListBuckets",
            "iam_resource": None,
            "access_type": "read-only",
        },
    })
    with pytest.raises(PlanCaptureError, match="iam_resource"):
        parse_line(line)


def test_parse_line_iam_resource_empty_array_rejected() -> None:
    line = _line(iam_jit={
        "iam_action": "s3:GetObject",
        "iam_resource": [],
        "access_type": "read-only",
    })
    with pytest.raises(PlanCaptureError, match="must not be empty"):
        parse_line(line)


# WB11-10 regression: per-line + total-file caps protect against
# decompression-bomb captures.
def test_read_capture_rejects_oversized_line(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single JSONL line over the 1MB cap aborts iteration."""
    import iam_jit.plan_capture as pc
    monkeypatch.setattr(pc, "_MAX_LINE_BYTES", 256)  # tighter for test
    p = tmp_path / "huge.jsonl"
    bloat = "X" * 1024
    p.write_text(json.dumps({
        "schema": SCHEMA_VERSION_V1ALPHA1,
        "ts": "t", "service": "s3", "action": "A", "region": "us-east-1",
        "iam_jit": {"iam_action": "s3:A", "iam_resource": "*", "access_type": "read-only"},
        "bloat": bloat,
    }) + "\n")
    with pytest.raises(PlanCaptureError, match="exceeds"):
        list(read_capture(p))


def test_read_capture_rejects_oversized_total(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Many small lines summing past the total-file cap aborts iteration."""
    import iam_jit.plan_capture as pc
    monkeypatch.setattr(pc, "_MAX_FILE_BYTES_UNCOMPRESSED", 1024)
    p = tmp_path / "many.jsonl"
    line = _line() + "\n"
    p.write_text(line * 100)  # > 1024 bytes total
    with pytest.raises(PlanCaptureError, match="decompression-bomb"):
        list(read_capture(p))
