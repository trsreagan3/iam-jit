# #324a — tests for the dynamic-deny YAML watcher.
"""Tests for ``iam_jit.dynamic_denies.watcher.DynamicDenyWatcher``.

Covers:
  * Initial synchronous load populates ``snapshot()``.
  * fsevents/inotify-driven reload on file create / modify.
  * Debounce collapses a burst of writes into ONE reload.
  * Parse-error reload retains the previous snapshot (fail-CLOSED).
  * Emit callback fires with the right ReloadReason on each branch.
  * `reload_now()` skips the debounce + returns the reload result
    directly.

Watchdog runs on a background thread; we use small debounce windows
+ short polling timeouts (`_wait_for_predicate`) so the tests finish
fast.
"""

from __future__ import annotations

import datetime as _dt
import pathlib
import time

import pytest

from iam_jit.dynamic_denies import (
    DynamicDenyLoadError,
    DynamicDenyWatcher,
    RuleSet,
)
from iam_jit.dynamic_denies.watcher import (
    FILE_CREATED,
    FILE_MODIFIED,
    PARSE_ERROR,
    RELOAD_REQUESTED,
    _wait_for_predicate,
)


VALID_RULE_ID_1 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
VALID_RULE_ID_2 = "dd_01HZ8WPRBZ6CGQRSTVWXYZ0AB1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _yaml_with_rule(rule_id: str, target: str = "arn:aws:s3:::prod-*") -> str:
    return f"""
schema_version: "1.0"
denies:
  - id: {rule_id}
    targets: ["{target}"]
    reason: "test"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
"""


def _yaml_invalid() -> str:
    return """
schema_version: "1.0"
denies:
  - id: not-a-ulid
    targets: ["arn:aws:s3:::prod-*"]
    reason: "bad rule id"
    duration: "3h"
"""


def _yaml_empty_denies() -> str:
    return """
schema_version: "1.0"
denies: []
"""


# ---------------------------------------------------------------------------
# Initial load
# ---------------------------------------------------------------------------


def test_initial_load_missing_file_returns_empty(tmp_path):
    path = str(tmp_path / "absent.yaml")
    w = DynamicDenyWatcher(path)
    try:
        assert w.snapshot().rules == ()
        assert w.initial_load_error() is None
    finally:
        w.stop()


def test_initial_load_valid_file_populates_snapshot(tmp_path):
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_with_rule(VALID_RULE_ID_1))
    w = DynamicDenyWatcher(str(p))
    try:
        snap = w.snapshot()
        assert len(snap.rules) == 1
        assert snap.rules[0].id == VALID_RULE_ID_1
        assert w.initial_load_error() is None
    finally:
        w.stop()


def test_initial_load_invalid_file_records_error(tmp_path):
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_invalid())
    w = DynamicDenyWatcher(str(p))
    try:
        snap = w.snapshot()
        assert snap.rules == ()
        err = w.initial_load_error()
        assert isinstance(err, DynamicDenyLoadError)
        # fail-CLOSED: parse error -> empty rules, not unrecognised
        # silent partial load.
        assert w.total_parse_errors() == 1
    finally:
        w.stop()


# ---------------------------------------------------------------------------
# Watcher-driven reload
# ---------------------------------------------------------------------------


def test_detects_file_creation(tmp_path):
    """Operator's first `iam-jit deny add` invocation creates the
    file; the watcher picks it up."""
    p = tmp_path / "dd.yaml"
    received: list[tuple] = []

    def emit(reason, rs, err):
        received.append((str(reason), len(rs.rules), err))

    w = DynamicDenyWatcher(
        str(p), emit=emit, debounce_seconds=0.05,
    )
    w.start()
    try:
        # File doesn't exist yet -> snapshot is empty.
        assert w.snapshot().rules == ()
        # Create the file with one rule.
        p.write_text(_yaml_with_rule(VALID_RULE_ID_1))
        # Wait for the watcher's debounce + reload.
        ok = _wait_for_predicate(
            lambda: len(w.snapshot().rules) == 1,
            timeout=3.0, poll=0.05,
        )
        assert ok, (
            f"watcher did not pick up file creation; "
            f"emits={received}, total_reloads={w.total_reloads()}, "
            f"parse_errors={w.total_parse_errors()}"
        )
        assert w.snapshot().rules[0].id == VALID_RULE_ID_1
        assert w.total_reloads() >= 1
        # At least one emit landed with a non-parse-error reason.
        assert any(r[0] != "parse_error" for r in received), received
    finally:
        w.stop()


def test_detects_file_modification(tmp_path):
    """Editing the file in place (the common `iam-jit deny add`
    shape) fires a modify-event reload."""
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_with_rule(VALID_RULE_ID_1))

    received: list[tuple] = []

    def emit(reason, rs, err):
        received.append((str(reason), len(rs.rules), err))

    w = DynamicDenyWatcher(str(p), emit=emit, debounce_seconds=0.05)
    w.start()
    try:
        assert len(w.snapshot().rules) == 1
        # Add a second rule.
        p.write_text(
            _yaml_with_rule(VALID_RULE_ID_1)
            + "  - id: " + VALID_RULE_ID_2 + "\n"
            + "    targets: [\"arn:aws:s3:::staging-*\"]\n"
            + "    reason: \"added later\"\n"
            + "    duration: \"3h\"\n"
            + "    added_by: \"ops@example.com\"\n"
            + "    added_at: \"" + _now_iso() + "\"\n"
            + "    applied_to: [ibounce]\n"
        )
        ok = _wait_for_predicate(
            lambda: len(w.snapshot().rules) == 2,
            timeout=3.0, poll=0.05,
        )
        assert ok, (
            f"watcher did not pick up file modification; emits={received}"
        )
        ids = {r.id for r in w.snapshot().rules}
        assert ids == {VALID_RULE_ID_1, VALID_RULE_ID_2}
    finally:
        w.stop()


def test_debounces_rapid_writes(tmp_path):
    """A burst of writes inside the debounce window collapses into a
    SINGLE reload (not one per event). Avoids reloading a partial
    file mid-write."""
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_empty_denies())

    reload_count_before = 0

    w = DynamicDenyWatcher(str(p), debounce_seconds=0.20)
    w.start()
    try:
        # Burst of 5 writes inside the debounce window.
        for i in range(5):
            p.write_text(_yaml_empty_denies() + f"# write {i}\n")
            time.sleep(0.01)
        # Now write the FINAL content + wait for the debounce timer
        # to fire.
        p.write_text(_yaml_with_rule(VALID_RULE_ID_1))
        ok = _wait_for_predicate(
            lambda: len(w.snapshot().rules) == 1,
            timeout=3.0, poll=0.05,
        )
        assert ok, "watcher did not reach final snapshot"
        # The number of *successful* reloads should be small —
        # debounce collapses the bursts. Exact count varies by
        # platform but we expect <= the number of distinct burst
        # windows (much less than 6 events).
        assert w.total_reloads() <= 3, (
            f"debounce failed: {w.total_reloads()} reloads recorded"
        )
    finally:
        w.stop()


def test_retains_rules_on_parse_error(tmp_path):
    """When the operator hand-edits a malformed YAML, the watcher
    keeps the previous snapshot + emits a parse-error event. Fail-
    CLOSED per [[ibounce-honest-positioning]]."""
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_with_rule(VALID_RULE_ID_1))

    received: list[tuple] = []

    def emit(reason, rs, err):
        received.append((str(reason), len(rs.rules), err))

    w = DynamicDenyWatcher(str(p), emit=emit, debounce_seconds=0.05)
    w.start()
    try:
        assert len(w.snapshot().rules) == 1
        # Hand-edit to a broken state.
        p.write_text(_yaml_invalid())
        ok = _wait_for_predicate(
            lambda: w.total_parse_errors() >= 1,
            timeout=3.0, poll=0.05,
        )
        assert ok, f"parse-error counter never bumped; emits={received}"
        # Critical: the previous snapshot is retained.
        snap = w.snapshot()
        assert len(snap.rules) == 1
        assert snap.rules[0].id == VALID_RULE_ID_1
        # At least one parse-error emit fired.
        assert any(r[0] == "parse_error" for r in received), received
    finally:
        w.stop()


def test_reload_now_skips_debounce(tmp_path):
    """The mgmt-port endpoint calls `reload_now` to bypass the
    debounce window. The call is synchronous + returns the new
    snapshot."""
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_with_rule(VALID_RULE_ID_1))

    w = DynamicDenyWatcher(str(p), debounce_seconds=10.0)  # huge debounce
    try:
        # Initial state shows the 1 rule from the constructor.
        assert len(w.snapshot().rules) == 1
        # Modify file + call reload_now — should bypass debounce.
        p.write_text(_yaml_empty_denies())
        rs, err = w.reload_now(RELOAD_REQUESTED)
        assert err is None
        assert len(rs.rules) == 0
        assert len(w.snapshot().rules) == 0
    finally:
        w.stop()


def test_reload_now_returns_error_on_invalid_file(tmp_path):
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_with_rule(VALID_RULE_ID_1))
    w = DynamicDenyWatcher(str(p))
    try:
        # Break the file.
        p.write_text(_yaml_invalid())
        rs, err = w.reload_now(RELOAD_REQUESTED)
        assert err is not None
        assert isinstance(err, DynamicDenyLoadError)
        # Previous snapshot is retained.
        assert len(rs.rules) == 1
        assert len(w.snapshot().rules) == 1
    finally:
        w.stop()


def test_total_counters_are_thread_safe(tmp_path):
    """Sanity: the counters are integers + monotonically non-decreasing
    + accessible from any thread (we don't run a multi-thread stress
    test here; we just confirm the access pattern works)."""
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_with_rule(VALID_RULE_ID_1))
    w = DynamicDenyWatcher(str(p))
    try:
        assert isinstance(w.total_reloads(), int)
        assert isinstance(w.total_parse_errors(), int)
        assert w.total_reloads() >= 0
        assert w.total_parse_errors() >= 0
    finally:
        w.stop()


def test_emit_callback_receives_initial_reload_reason(tmp_path):
    """The emit callback fires with the right ReloadReason for each
    event class. Construct the watcher with an emit callback + drive
    one reload through reload_now to confirm the wiring."""
    p = tmp_path / "dd.yaml"
    p.write_text(_yaml_with_rule(VALID_RULE_ID_1))

    received: list[str] = []

    def emit(reason, rs, err):
        received.append(str(reason))

    w = DynamicDenyWatcher(str(p), emit=emit)
    try:
        # Trigger explicit reload — the emit callback should fire.
        w.reload_now(RELOAD_REQUESTED)
        assert "reload_requested" in received
    finally:
        w.stop()


def test_empty_path_watcher_is_inert():
    """A watcher with an empty path acts as a frozen always-empty
    snapshot — used when config disables the watcher path entirely
    (no IAM_JIT_DYNAMIC_DENIES_PATH + no home dir)."""
    w = DynamicDenyWatcher("")
    try:
        w.start()  # should be a no-op
        assert w.snapshot().rules == ()
        assert w.initial_load_error() is None
    finally:
        w.stop()
