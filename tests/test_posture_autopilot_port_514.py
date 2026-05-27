"""#514 — posture cross-bouncer port discovery reads autopilot.status.json.

Two cases:
  1. Fixture autopilot.status.json with a custom port → posture detects
     ibounce as running on that custom port (not the default).
  2. No autopilot.status.json → falls back to default-port probe without
     regression (existing behavior preserved).
"""

from __future__ import annotations

import json
import socket

import pytest

from iam_jit.posture.bouncers import (
    IBOUNCE_DEFAULT_PORT,
    _read_autopilot_port_hints,
    detect_ibounce,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bind_free_port() -> tuple[socket.socket, int]:
    """Bind a loopback TCP socket on a random free port. Caller closes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Scrub posture-relevant env vars so the host's real state never
    leaks into the test."""
    for var in (
        "AWS_ENDPOINT_URL",
        "IAM_JIT_DATA_DIR",
    ):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# _read_autopilot_port_hints
# ---------------------------------------------------------------------------


def test_read_autopilot_port_hints_returns_empty_when_no_file(monkeypatch, tmp_path):
    """No autopilot.status.json → empty dict (no crash)."""
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    hints = _read_autopilot_port_hints()
    assert hints == {}


def test_read_autopilot_port_hints_returns_empty_on_bad_json(monkeypatch, tmp_path):
    """Corrupt status.json → empty dict (parse failure is non-fatal)."""
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    (tmp_path / "autopilot.status.json").write_text("not-json")
    hints = _read_autopilot_port_hints()
    assert hints == {}


def test_read_autopilot_port_hints_extracts_running_ports(monkeypatch, tmp_path):
    """Valid status.json with ibounce port=9876 → {ibounce: [9876]}."""
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    payload = {
        "bouncers": {
            "ibounce": {"port": 9876, "running": True},
            "kbounce": {"port": 8766, "running": True},
        }
    }
    (tmp_path / "autopilot.status.json").write_text(json.dumps(payload))
    hints = _read_autopilot_port_hints()
    assert hints.get("ibounce") == [9876]
    assert hints.get("kbounce") == [8766]


def test_read_autopilot_port_hints_skips_running_false(monkeypatch, tmp_path):
    """Bouncers marked running=False are excluded from hints."""
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    payload = {
        "bouncers": {
            "ibounce": {"port": 9876, "running": False},
        }
    }
    (tmp_path / "autopilot.status.json").write_text(json.dumps(payload))
    hints = _read_autopilot_port_hints()
    assert "ibounce" not in hints


def test_read_autopilot_port_hints_treats_missing_running_as_check(monkeypatch, tmp_path):
    """Bouncers with no running field are checked per safety-mode-lean-permissive."""
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    payload = {
        "bouncers": {
            "ibounce": {"port": 9876},  # no "running" key
        }
    }
    (tmp_path / "autopilot.status.json").write_text(json.dumps(payload))
    hints = _read_autopilot_port_hints()
    assert hints.get("ibounce") == [9876]


# ---------------------------------------------------------------------------
# detect_ibounce with canary port
# ---------------------------------------------------------------------------


def test_detect_ibounce_finds_custom_port_via_autopilot_status(monkeypatch, tmp_path):
    """When autopilot.status.json records ibounce on a custom port and
    something IS listening there, posture reports running=True + the
    custom port (not the default 8767).

    This is the #514 regression: before the fix, posture only probed
    IBOUNCE_DEFAULT_PORT=8767 and missed canary-port deployments.
    """
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))

    # Bind a free port to simulate ibounce running on a custom port.
    sock, custom_port = _bind_free_port()
    assert custom_port != IBOUNCE_DEFAULT_PORT, (
        "Got the default port by accident — rerun the test"
    )

    try:
        # Write the status fixture pointing at the custom port.
        payload = {
            "bouncers": {
                "ibounce": {"port": custom_port, "running": True},
            }
        }
        (tmp_path / "autopilot.status.json").write_text(json.dumps(payload))

        block = detect_ibounce()
        assert block["running"] is True, (
            f"Expected running=True for ibounce on port {custom_port}"
        )
        assert block["port"] == custom_port, (
            f"Expected port={custom_port}, got {block['port']}"
        )
    finally:
        sock.close()


def test_detect_ibounce_falls_back_to_default_port_when_no_autopilot_file(
    monkeypatch, tmp_path
):
    """No autopilot.status.json → detection falls back to default-port probe.

    Nothing is listening on the default port in this test so running=False,
    but the important invariant is that the function doesn't crash and
    returns the default port as block["default_port"].
    """
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    # No status file written — tmp_path is empty.
    block = detect_ibounce()
    # Should not raise; default_port must still be the constant.
    assert block["default_port"] == IBOUNCE_DEFAULT_PORT
    # Nothing is listening on the default port in CI, so running is False.
    # We don't assert running=False (CI may have something on 8767) but
    # we do assert no KeyError on the block.
    assert "running" in block
    assert "port" in block
