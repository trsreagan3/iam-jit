"""#383 / §A42 — `iam-jit posture` + `iam_jit_posture` MCP tool tests.

Covers the test list from the §A42 launch-blocker spec:
  * iam-jit-issued-role detection (path + session marker + cache)
  * unknown reporting when no evidence
  * bouncer env-var + running-process detection
  * misconfig detection (env set but bouncer down)
  * JSON schema validity
  * --exit-1-on-unprotected exit code
  * credential-leak guard
  * MCP tool returns the same shape as --json
  * per-bouncer (ibounce) posture surface
"""

from __future__ import annotations

import json
import os
import socket
import threading

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main
from iam_jit.cli_posture import posture_for_mcp
from iam_jit.posture import (
    POSTURE_SCHEMA_VERSION,
    capture_posture,
    render_posture_human,
)
from iam_jit.posture.bouncers import (
    DBOUNCE_ENV_PGHOST,
    DBOUNCE_ENV_PGPORT,
    GBOUNCE_ENV_HTTP_PROXY,
    IBOUNCE_AWS_ENDPOINT_ENV,
    IBOUNCE_DEFAULT_PORT,
    KBOUNCE_ENV_KUBECONFIG,
    KBOUNCE_KUBECONFIG_MARKER,
    detect_all_bouncers,
    detect_ibounce,
)
from iam_jit.posture.identity import detect_iam_jit_role
from iam_jit.posture.sanitize import sanitize_posture, scrub_value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Scrub posture-relevant env vars so the host's real state never
    leaks into tests."""
    for var in (
        "IAM_JIT_ASSUMED_ROLE_ARN",
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ROLE_ARN",
        "AWS_ENDPOINT_URL",
        KBOUNCE_ENV_KUBECONFIG,
        DBOUNCE_ENV_PGHOST,
        DBOUNCE_ENV_PGPORT,
        GBOUNCE_ENV_HTTP_PROXY,
        "HTTPS_PROXY",
    ):
        monkeypatch.delenv(var, raising=False)


def _bind_loopback_port() -> tuple[socket.socket, int]:
    """Bind a loopback socket on a random free port + return (sock, port).
    Caller must close the socket when done."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


# ---------------------------------------------------------------------------
# Identity detection
# ---------------------------------------------------------------------------


def test_posture_detects_iam_jit_issued_role_via_path(monkeypatch):
    """Path marker /iam-jit/ in the role ARN is positive evidence."""
    monkeypatch.setenv(
        "AWS_ROLE_ARN",
        "arn:aws:iam::123456789012:role/iam-jit/ephemeral-Q9P",
    )
    ident = detect_iam_jit_role()
    assert ident["scoped_role_active"] is True
    assert any("/iam-jit/" in e for e in ident["iam_jit_issued_evidence"])


def test_posture_detects_iam_jit_issued_role_via_session_marker(monkeypatch):
    """`IAM_JIT_ASSUMED_ROLE_ARN` env pin is authoritative."""
    monkeypatch.setenv(
        "IAM_JIT_ASSUMED_ROLE_ARN",
        "arn:aws:iam::111:role/some-other-path/role",
    )
    ident = detect_iam_jit_role()
    assert ident["scoped_role_active"] is True
    assert any("IAM_JIT_ASSUMED_ROLE_ARN" in e for e in ident["iam_jit_issued_evidence"])


def test_posture_reports_unknown_when_no_evidence(monkeypatch):
    """No env vars, no cache -> 'unknown', NOT False per
    [[ibounce-honest-positioning]]."""
    ident = detect_iam_jit_role()
    assert ident["scoped_role_active"] == "unknown"
    assert any("no AWS role ARN" in n for n in ident["notes"])


def test_posture_reports_false_only_with_positive_negative_evidence(monkeypatch):
    """Visible ARN that LACKS the marker is positive evidence for False."""
    monkeypatch.setenv(
        "AWS_ROLE_ARN",
        "arn:aws:iam::111:role/developer",
    )
    ident = detect_iam_jit_role()
    assert ident["scoped_role_active"] is False


def test_posture_ambient_credential_source_reads_aws_profile(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "staging-readonly")
    ident = detect_iam_jit_role()
    assert "AWS_PROFILE=staging-readonly" in ident["ambient_credential_source"]


# ---------------------------------------------------------------------------
# Bouncer detection (env var + running process)
# ---------------------------------------------------------------------------


def test_posture_detects_bouncer_via_env_var_and_running_process(monkeypatch):
    """AWS_ENDPOINT_URL pointing at a loopback port that has a listener
    => running=True + env_var_pointing_here set + no misconfig."""
    sock, port = _bind_loopback_port()
    try:
        monkeypatch.setenv(
            "AWS_ENDPOINT_URL", f"http://127.0.0.1:{port}"
        )
        block = detect_ibounce()
        assert block["running"] is True
        assert block["env_var_pointing_here"] is not None
        assert str(port) in block["env_var_pointing_here"]
        assert block["misconfig"] is None
    finally:
        sock.close()


def test_posture_detects_misconfig_env_var_set_but_bouncer_down(monkeypatch):
    """Pick a port nothing is listening on; env set => misconfig flag."""
    # Bind a socket, immediately close it, capture the port. Nothing
    # else should grab that port between close + the test's probe.
    sock, port = _bind_loopback_port()
    sock.close()
    monkeypatch.setenv("AWS_ENDPOINT_URL", f"http://127.0.0.1:{port}")
    block = detect_ibounce()
    assert block["misconfig"] is not None
    assert "no bouncer listening" in block["misconfig"]


def test_posture_default_port_constant_matches_ibounce_cli():
    """Pin the default port so the bouncer-CLI flag default doesn't
    drift without the posture detector noticing."""
    assert IBOUNCE_DEFAULT_PORT == 8767


def test_posture_kbounce_kubeconfig_marker(monkeypatch, tmp_path):
    """KUBECONFIG pointing at a kbounce-generated file is detected via
    the marker; pointing at a plain kubeconfig is NOT."""
    kbounce_cfg = tmp_path / "kbounce.yaml"
    kbounce_cfg.write_text(
        f"{KBOUNCE_KUBECONFIG_MARKER}\napiVersion: v1\n"
    )
    monkeypatch.setenv(KBOUNCE_ENV_KUBECONFIG, str(kbounce_cfg))
    blocks = detect_all_bouncers()
    assert blocks["kbounce"]["env_var_pointing_here"] is not None

    # Now point at a regular kubeconfig — no marker.
    plain = tmp_path / "regular.yaml"
    plain.write_text("apiVersion: v1\nkind: Config\n")
    monkeypatch.setenv(KBOUNCE_ENV_KUBECONFIG, str(plain))
    blocks = detect_all_bouncers()
    assert blocks["kbounce"]["env_var_pointing_here"] is None


# ---------------------------------------------------------------------------
# Full snapshot + JSON shape
# ---------------------------------------------------------------------------


def test_posture_json_output_schema_valid():
    """Top-level keys + sub-blocks match the §A42 spec."""
    snap = capture_posture()
    assert snap["schema_version"] == POSTURE_SCHEMA_VERSION
    assert "captured_at" in snap
    assert "overall_mode" in snap
    assert "iam_jit" in snap
    assert "bouncers" in snap
    assert "effective_protection" in snap
    assert "unprotected_traffic_present" in snap
    assert "tips" in snap
    # Bouncers must include every product per
    # [[cross-product-agent-parity]].
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        assert name in snap["bouncers"]
    # Effective protection covers all four traffic classes.
    for key in ("aws_calls", "k8s_calls", "db_calls", "http_calls"):
        assert key in snap["effective_protection"]


def test_posture_overall_mode_neither_when_nothing_running(monkeypatch):
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::111:role/developer")
    snap = capture_posture()
    assert snap["overall_mode"] == "neither"
    assert snap["unprotected_traffic_present"] is True


def test_posture_overall_mode_bouncer_only(monkeypatch):
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::111:role/developer")
    sock, port = _bind_loopback_port()
    try:
        monkeypatch.setenv(
            "AWS_ENDPOINT_URL", f"http://127.0.0.1:{port}"
        )
        snap = capture_posture()
        assert snap["overall_mode"] == "bouncer only"
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# CLI command (Click)
# ---------------------------------------------------------------------------


def test_posture_cli_human_output_contains_banner(monkeypatch):
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["posture"])
    assert result.exit_code == 0, result.output
    assert "== iam-jit posture ==" in result.output
    assert "Identity:" in result.output
    assert "Bouncers:" in result.output
    assert "Effective protection:" in result.output


def test_posture_cli_json_output_is_valid_json(monkeypatch):
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["posture", "--json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["schema_version"] == POSTURE_SCHEMA_VERSION


def test_posture_exit_code_1_on_unprotected_traffic_when_flag_set(monkeypatch):
    """Nothing's running => unprotected_traffic_present is True =>
    exit 1 with the flag set."""
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main, ["posture", "--exit-1-on-unprotected"]
    )
    assert result.exit_code == 1


def test_posture_exit_code_0_without_unprotected_flag():
    """Without the flag, exit is always 0 regardless of state."""
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["posture"])
    assert result.exit_code == 0


def test_posture_check_direct_emits_loud_warning(monkeypatch):
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["posture", "--check-direct"])
    # The loud warning goes to stderr; CliRunner mixes stdout + stderr
    # into result.output by default.
    assert "DIRECT TRAFFIC DETECTED" in result.output


# ---------------------------------------------------------------------------
# Credential-leak guard
# ---------------------------------------------------------------------------


def test_posture_does_not_leak_credentials(monkeypatch):
    """Sanity check: setting an AWS_SECRET_ACCESS_KEY env var must NOT
    cause its value to appear in the posture output. The sanitizer
    runs by default."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    snap = capture_posture()
    # Walk the entire snapshot's string-leaf values; secret must not
    # appear anywhere.
    flat = json.dumps(snap)
    assert secret not in flat


def test_sanitizer_redacts_aws_access_keys():
    raw = "your key is AKIAIOSFODNN7EXAMPLE here"
    out = scrub_value(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED]" in out


def test_sanitizer_redacts_credential_keyed_dicts():
    payload = {
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "api_token": "fine",
        "MY_TOKEN": "alsohas-a-secret",
        "regular_field": "kept",
    }
    out = sanitize_posture(payload)
    assert out["AWS_SECRET_ACCESS_KEY"] == "[REDACTED]"
    assert out["MY_TOKEN"] == "[REDACTED]"
    assert out["regular_field"] == "kept"


def test_sanitizer_preserves_arns():
    """Role ARNs are identifiers, not secrets — they must pass
    through untouched even though they contain long opaque strings."""
    arn = "arn:aws:iam::123456789012:role/iam-jit/ephemeral-abc123def456"
    assert scrub_value(arn) == arn


# ---------------------------------------------------------------------------
# MCP tool parity
# ---------------------------------------------------------------------------


def test_mcp_posture_returns_same_shape_as_cli_json():
    """`iam_jit_posture` MCP tool returns a dict with the same top-
    level keys as the CLI's --json output."""
    mcp_out = posture_for_mcp({})
    cli_runner = CliRunner()
    cli_result = cli_runner.invoke(iam_jit_main, ["posture", "--json"])
    cli_out = json.loads(cli_result.output)
    assert set(mcp_out.keys()) == set(cli_out.keys())
    assert mcp_out["schema_version"] == cli_out["schema_version"]


def test_render_posture_human_includes_overall_line():
    snap = capture_posture()
    text = render_posture_human(snap)
    assert "Overall:" in text
    assert snap["overall_mode"] in text


# ---------------------------------------------------------------------------
# Honest-state regression: posture must report the RUNNING proxy's live
# mode/anomaly/pause from /healthz, not what THIS process would resolve.
# (Fixes the evaluator's #1 blocker: posture said "cooperative" while the
# proxy was "transparent".)
# ---------------------------------------------------------------------------


def test_ibounce_posture_mode_comes_from_healthz(monkeypatch):
    import iam_jit.posture.bouncers as b

    monkeypatch.setattr(b, "_read_ibounce_running_port", lambda: 8767)
    monkeypatch.setattr(
        b, "_fetch_healthz",
        lambda port, timeout=1.0: {
            "mode": "transparent",
            "enforcing": True,
            "active_profile": "safe-default",
            "anomaly_detection": {"mode": "block", "enabled": True},
            "pause": {"pause_id": "p1", "ends_at": "soon"},
        },
    )
    block = b.detect_ibounce()
    assert block["mode"] == "transparent"      # live, not in-process default
    assert block["mode_source"] == "healthz"
    assert block["enforcing"] is True
    assert block["active_profile"] == "safe-default"
    # Honest-state: anomaly + pause surfaced (were null/absent before).
    assert block["anomaly_detection"] == {"mode": "block", "enabled": True}
    assert block["pause"]["pause_id"] == "p1"


def test_ibounce_posture_falls_back_when_healthz_unavailable(monkeypatch):
    import iam_jit.posture.bouncers as b

    monkeypatch.setattr(b, "_read_ibounce_running_port", lambda: 8767)
    monkeypatch.setattr(b, "_fetch_healthz", lambda port, timeout=1.0: None)
    block = b.detect_ibounce()
    # No crash; mode resolved from in-process fallback (a real mode string).
    assert "mode" in block and block["mode"]


def test_gbounce_posture_mode_comes_from_healthz(monkeypatch):
    import iam_jit.posture.bouncers as b

    monkeypatch.setattr(b, "_loopback_port_open", lambda *a, **k: True)
    monkeypatch.setattr(b, "_read_autopilot_port_hints", lambda: {})
    monkeypatch.setattr(
        b, "_fetch_healthz",
        lambda port, timeout=1.0: {"mode": "mitm", "deny_hosts_count": 3,
                                   "mitm_enabled": True},
    )
    block = b.detect_gbounce()
    assert block["mode"] == "mitm"             # was hardcoded "unknown"
    assert block["mode_source"] == "healthz"
    assert block["deny_hosts_count"] == 3
