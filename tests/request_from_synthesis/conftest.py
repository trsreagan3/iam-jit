"""Test isolation for the request_from_synthesis suite.

The synthesis-default audit sink (#475 / §A60d) writes to a JSONL log —
by default the same `~/.iam-jit/audit.jsonl` the ibounce proxy uses.
Without isolation, every test that goes through
:func:`request_role_from_synthesis_for_mcp` would pollute the developer's
real audit log AND cause failures in the bouncer-audit-endpoint tests
(which read from the same path).

The autouse fixture below points every test at a tmp_path-rooted log,
so the synthesis surface is exercised end-to-end (sink + JSONL append +
OCSF translation) without leaking outside the test session. Tests that
need to assert ON the log content can request the same `_isolated_…`
fixture explicitly to grab the path.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _default_synthesis_audit_log_isolated(tmp_path, monkeypatch):
    """Redirect the synthesis sink's default path to a tmp file. Tests
    that don't introspect the log just rely on the silent isolation;
    tests that DO introspect can still resolve the same path via the
    env var or by writing to the returned path."""
    log_path = tmp_path / "synthesis-audit-default.jsonl"
    monkeypatch.setenv("IAM_JIT_SYNTHESIS_AUDIT_LOG", str(log_path))
    yield log_path
