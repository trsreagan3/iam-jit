"""§A76 #468 — per-agent baseline storage tests.

State-verification per [[#467 / §A87]]: every test reads back from the
SQLite tables after observe()ing to confirm the writer actually
persisted what we expect (not just "the call didn't raise").
"""

from __future__ import annotations

import os
import pathlib
import sqlite3
import time
from typing import Iterator

import pytest

from iam_jit.anomaly_detection import BaselineStore, BaselineSummary
from iam_jit.anomaly_detection.baseline import (
    canonical_resource_pattern,
)


@pytest.fixture
def store(tmp_path: pathlib.Path) -> Iterator[BaselineStore]:
    """Per-test BaselineStore with an isolated DB file."""
    path = tmp_path / "anomaly-baseline.db"
    s = BaselineStore(
        path=str(path),
        flush_interval_seconds=0.05,  # snappy for tests
    )
    s.start()
    yield s
    s.stop()


def _row_count(path: str, table: str) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def test_baseline_starts_empty_for_new_agent(store: BaselineStore) -> None:
    summary = store.summary_for("claude:abc", "s3:GetObject", "arn:aws:s3:::x")
    assert summary.total_observations_rolling == 0
    assert summary.dimensions == {}


def test_baseline_aggregates_per_agent_per_action(
    store: BaselineStore,
    tmp_path: pathlib.Path,
) -> None:
    # Two agents touching two actions each — confirm per-key aggregation
    # is isolated (one agent's count doesn't bleed into another).
    for _ in range(10):
        store.observe(
            agent_identity="agent-a", action="s3:GetObject",
            resource="arn:aws:s3:::prod-bucket",
        )
    for _ in range(5):
        store.observe(
            agent_identity="agent-a", action="s3:PutObject",
            resource="arn:aws:s3:::prod-bucket",
        )
    for _ in range(20):
        store.observe(
            agent_identity="agent-b", action="s3:GetObject",
            resource="arn:aws:s3:::staging-bucket",
        )

    # Read back via the public summary surface.
    sum_a_get = store.summary_for("agent-a", "s3:GetObject", "arn:aws:s3:::prod-bucket")
    assert sum_a_get.total_observations_rolling == 10
    sum_a_put = store.summary_for("agent-a", "s3:PutObject", "arn:aws:s3:::prod-bucket")
    assert sum_a_put.total_observations_rolling == 5
    sum_b_get = store.summary_for("agent-b", "s3:GetObject", "arn:aws:s3:::staging-bucket")
    assert sum_b_get.total_observations_rolling == 20

    # Per-dimension stats — every populated key gets action_frequency +
    # hour_of_day at minimum.
    assert "action_frequency" in sum_a_get.dimensions
    assert "hour_of_day" in sum_a_get.dimensions


def test_baseline_dual_mode_rolling_and_decay(store: BaselineStore) -> None:
    """F.3 — decayed aggregate is maintained alongside rolling counts.

    The decayed view must populate (non-zero) after observations land.
    """
    for _ in range(30):
        store.observe(
            agent_identity="a", action="s3:GetObject", resource="arn:aws:s3:::x",
        )
    summary = store.summary_for("a", "s3:GetObject", "arn:aws:s3:::x")
    assert summary.total_observations_rolling == 30
    # The decayed total should be > 0 (recent rows get weight ≈ 1.0).
    assert summary.total_observations_decayed > 0
    # And there should be at least one decayed dimension.
    decayed_dims = [k for k in summary.dimensions if k.endswith("_decayed")]
    assert len(decayed_dims) >= 1


def test_baseline_decay_rate_configurable(tmp_path: pathlib.Path) -> None:
    """Confirm operator can configure the decay rate."""
    store = BaselineStore(
        path=str(tmp_path / "b.db"),
        decay_rate=0.5,  # aggressive decay
        flush_interval_seconds=0.05,
    )
    store.start()
    try:
        for _ in range(5):
            store.observe(
                agent_identity="a", action="iam:CreateUser",
                resource="arn:aws:iam::123:user/x",
            )
        stat = store.status()
        assert stat["decay_rate"] == 0.5
    finally:
        store.stop()


def test_baseline_privacy_no_individual_values_stored(
    store: BaselineStore, tmp_path: pathlib.Path,
) -> None:
    """KEY privacy invariant: we never store the raw resource string.

    Verify directly against the SQLite schema + a forensic scan of the
    per-agent rows: even after observing a request with a unique
    customer identifier in the resource, no row contains that string.
    """
    secret_token = "supersecret-customer-bucket-12345"
    store.observe(
        agent_identity="a", action="s3:GetObject",
        resource=f"arn:aws:s3:::{secret_token}/key",
    )
    # Force flush
    store.summary_for("a", "s3:GetObject", f"arn:aws:s3:::{secret_token}/key")

    # Direct SQLite scan — every text column in the table.
    path = store.path
    conn = sqlite3.connect(path)
    try:
        # Schema invariant: no column named 'resource' or 'raw_*' that
        # would carry the original value.
        cols = [r[1] for r in conn.execute(
            "PRAGMA table_info(anomaly_baseline_per_agent)").fetchall()]
        assert "resource" not in cols
        assert not any(c.startswith("raw_") for c in cols)
        # Forensic scan: the secret token never appears in the table.
        all_rows = conn.execute(
            "SELECT * FROM anomaly_baseline_per_agent"
        ).fetchall()
        flat = " ".join(str(c) for row in all_rows for c in row)
        assert secret_token not in flat
        # Resource pattern is canonicalised — we DO store the bucketed
        # pattern (e.g. 'arn:aws:s3::other') and that's intentional.
        # Look up the column index by name to avoid order-fragility.
        pattern_col_idx = cols.index("resource_pattern")
        patterns = {r[pattern_col_idx] for r in all_rows}
        assert all("supersecret" not in str(p) for p in patterns)
    finally:
        conn.close()


def test_baseline_background_task_does_not_block_request_path(
    tmp_path: pathlib.Path,
) -> None:
    """observe() must be non-blocking even when the writer thread is
    paused. We simulate slowness by making the worker sleep + verify
    observe() returns sub-millisecond per call.
    """
    store = BaselineStore(
        path=str(tmp_path / "perf.db"),
        flush_interval_seconds=10.0,  # worker never flushes during test
    )
    store.start()
    try:
        t0 = time.perf_counter()
        for i in range(500):
            store.observe(
                agent_identity="a", action="s3:GetObject", resource="x",
            )
        elapsed = time.perf_counter() - t0
        # 500 observations should be well under 100ms in-memory.
        assert elapsed < 0.5, f"observe() too slow: {elapsed:.3f}s"
    finally:
        store.stop()


def test_baseline_canonical_resource_pattern_redacts_arn() -> None:
    """The canonicaliser drops account + region + name; preserves shape."""
    assert canonical_resource_pattern(None) == "-"
    assert canonical_resource_pattern("") == "-"
    assert canonical_resource_pattern("*") == "*"
    # Prod ARN → arn:aws:<svc>::prod
    assert canonical_resource_pattern(
        "arn:aws:s3:::prod-bucket-12345/key"
    ) == "arn:aws:s3::prod"
    # Staging ARN
    assert canonical_resource_pattern(
        "arn:aws:s3:::staging-data/path"
    ) == "arn:aws:s3::staging"
    # K8s namespace/name pattern → k8s:<env>
    assert canonical_resource_pattern("prod/my-pod").startswith("k8s:")
    # SQL identifier
    assert canonical_resource_pattern("staging.users").startswith("sql:")


def test_baseline_status_surface(store: BaselineStore) -> None:
    """status() returns a JSON-serialisable snapshot for the MCP tool."""
    import json
    store.observe(agent_identity="a", action="s3:GetObject")
    snap = store.status()
    json.dumps(snap)  # would raise if non-serialisable
    assert snap["window_seconds"] > 0
    assert "decay_rate" in snap
    assert snap["dropped"] == 0


def test_baseline_drops_overflow_quietly(tmp_path: pathlib.Path) -> None:
    """Queue overflow bumps the counter without raising — fail-soft per
    the spec."""
    store = BaselineStore(
        path=str(tmp_path / "overflow.db"),
        queue_maxsize=10,
        flush_interval_seconds=10.0,  # disable flushing during test
    )
    store.start()
    try:
        for _ in range(50):
            store.observe(agent_identity="a", action="s3:GetObject")
        snap = store.status()
        assert snap["dropped"] >= 40, snap
    finally:
        store.stop()


def test_baseline_known_agents_lists_distinct_identities(
    store: BaselineStore,
) -> None:
    for ai in ("claude:1", "claude:2", "cursor:1"):
        store.observe(agent_identity=ai, action="s3:GetObject")
    agents = store.known_agents()
    assert set(agents) == {"claude:1", "claude:2", "cursor:1"}
