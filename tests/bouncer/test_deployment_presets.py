"""Tests for #254 — `ibounce run --preset security-observe`.

The preset is a single-flag shortcut for the canonical 'security-team
observation' deployment shape per [[bouncer-mode-selection-for-
agents]]. The preset activates:
  - --mode transparent (HARD; cannot override)
  - --audit-log-path <per-product default> (SOFT; operator wins)
  - --alert-rules <defaults> (SOFT)
  - --heartbeat-interval 30 (SOFT)
  - --default-policy allow (SOFT)

These tests cover:
  - all canonical settings activate
  - HARD override (operator passes --mode cooperative) errors clearly
  - SOFT override (operator passes --audit-log-path /custom) allows
  - banner names the active preset + which settings are derived
"""

from __future__ import annotations

import os
from typing import Any

from click.testing import CliRunner


def _patched_runner(monkeypatch: Any) -> tuple[CliRunner, dict[str, Any]]:
    """Patch serve() to capture ProxyConfig without actually binding."""
    from iam_jit.bouncer import proxy as proxy_mod
    captured: dict[str, Any] = {}

    async def _fake_serve(config: Any, *, store: Any) -> None:  # noqa: ARG001
        captured["config"] = config

    monkeypatch.setattr(proxy_mod, "serve", _fake_serve)
    # Also short-circuit the alerts license gate so the test doesn't
    # need an Enterprise license file on disk to exercise the preset
    # path (the preset turns on the alert engine).
    from iam_jit.bouncer.audit_export import alerts as _alerts
    monkeypatch.setattr(_alerts, "gate_alerts_license", lambda _path: None)
    return CliRunner(), captured


def test_security_observe_activates_canonical_settings(
    tmp_path: Any, monkeypatch: Any,
) -> None:
    """`ibounce run --preset security-observe` activates all the
    canonical settings (transparent mode, JSONL audit log at the
    per-product default path, alert rules defaults, 30s heartbeat,
    default-policy=allow)."""
    from iam_jit import bouncer_cli

    monkeypatch.setenv("HOME", str(tmp_path))
    runner, captured = _patched_runner(monkeypatch)

    result = runner.invoke(
        bouncer_cli.main,
        ["run", "--port", "0", "--preset", "security-observe"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, f"CLI failed: {result.output}"
    cfg = captured["config"]
    assert cfg.mode.value == "transparent"
    assert cfg.default_policy.value == "allow"
    # JSONL path defaults to ~/.iam-jit/audit/ibounce.jsonl when
    # operator didn't override.
    expected_path = str(tmp_path / ".iam-jit" / "audit" / "ibounce.jsonl")
    assert cfg.audit_log_path == expected_path
    # Alert engine: empty string = built-in defaults (per the existing
    # 'defaults'/'' magic in run_cmd).
    assert cfg.alert_rules_path == ""
    assert cfg.heartbeat_interval_seconds == 30


def test_security_observe_with_hard_mode_override_errors(
    tmp_path: Any, monkeypatch: Any,
) -> None:
    """`--preset security-observe --mode cooperative` errors with the
    'cannot override; either drop the preset OR drop the explicit flag'
    message. The whole point of security-observe is transparent."""
    from iam_jit import bouncer_cli

    monkeypatch.setenv("HOME", str(tmp_path))
    runner, _ = _patched_runner(monkeypatch)

    result = runner.invoke(
        bouncer_cli.main,
        [
            "run", "--port", "0",
            "--preset", "security-observe",
            "--mode", "cooperative",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code != 0, (
        f"expected error; got: {result.output}"
    )
    msg = result.output
    assert "security-observe" in msg
    assert "mode" in msg
    assert "HARD" in msg
    # The error must tell the operator how to resolve.
    assert "drop the --preset" in msg or "drop the explicit" in msg


def test_security_observe_with_matching_mode_succeeds(
    tmp_path: Any, monkeypatch: Any,
) -> None:
    """`--preset security-observe --mode transparent` is fine — the
    operator-supplied value MATCHES the preset HARD value. No error;
    behaves identically to the bare preset."""
    from iam_jit import bouncer_cli

    monkeypatch.setenv("HOME", str(tmp_path))
    runner, captured = _patched_runner(monkeypatch)

    result = runner.invoke(
        bouncer_cli.main,
        [
            "run", "--port", "0",
            "--preset", "security-observe",
            "--mode", "transparent",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert captured["config"].mode.value == "transparent"


def test_security_observe_with_soft_audit_log_path_override_allowed(
    tmp_path: Any, monkeypatch: Any,
) -> None:
    """`--preset security-observe --audit-log-path /custom/path` is
    allowed; --audit-log-path is SOFT because operators have
    different SIEM destinations."""
    from iam_jit import bouncer_cli

    monkeypatch.setenv("HOME", str(tmp_path))
    runner, captured = _patched_runner(monkeypatch)

    custom = str(tmp_path / "custom" / "siem.jsonl")
    os.makedirs(os.path.dirname(custom), exist_ok=True)

    result = runner.invoke(
        bouncer_cli.main,
        [
            "run", "--port", "0",
            "--preset", "security-observe",
            "--audit-log-path", custom,
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert captured["config"].audit_log_path == custom
    # The HARD value still landed.
    assert captured["config"].mode.value == "transparent"


def test_security_observe_with_soft_heartbeat_override_allowed(
    tmp_path: Any, monkeypatch: Any,
) -> None:
    """`--heartbeat-interval` is SOFT — operators tune for their
    SIEM-absence window."""
    from iam_jit import bouncer_cli

    monkeypatch.setenv("HOME", str(tmp_path))
    runner, captured = _patched_runner(monkeypatch)

    result = runner.invoke(
        bouncer_cli.main,
        [
            "run", "--port", "0",
            "--preset", "security-observe",
            "--heartbeat-interval", "60",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert captured["config"].heartbeat_interval_seconds == 60


def test_security_observe_banner_shows_preset_and_derivation(
    tmp_path: Any, monkeypatch: Any,
) -> None:
    """The startup banner names the active preset + which settings are
    derived from it (so the operator sees exactly what changed)."""
    from iam_jit import bouncer_cli

    monkeypatch.setenv("HOME", str(tmp_path))
    runner, _ = _patched_runner(monkeypatch)

    result = runner.invoke(
        bouncer_cli.main,
        ["run", "--port", "0", "--preset", "security-observe"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, f"CLI failed: {result.output}"
    out = result.output
    assert "deployment preset: security-observe" in out
    # At least the canonical 5 derivations appear with (from preset)
    # annotations. We assert MODE specifically since it's the HARD
    # one + the lead value.
    assert "--mode" in out and "transparent" in out
    assert "from preset" in out


def test_security_observe_neutral_language_no_violation_terms(
    tmp_path: Any, monkeypatch: Any,
) -> None:
    """Per [[security-team-positioning-safety-not-surveillance]] the
    preset description + banner MUST avoid violation/infraction/
    unauthorized framing. These are observability tools, not
    surveillance."""
    from iam_jit.bouncer.deployment_presets import build_security_observe

    p = build_security_observe(product="ibounce")
    blob = (p.description + " ".join(
        f"{k}={v!r}" for k, (v, _) in p.values.items()
    )).lower()
    for forbidden in ("violation", "infraction", "unauthorized"):
        assert forbidden not in blob, (
            f"preset description leaks {forbidden!r}: {p.description}"
        )


def test_security_observe_no_phone_home(monkeypatch: Any) -> None:
    """Per [[self-host-zero-billing-dependency]] the preset MUST NOT
    add any phone-home. audit-webhook-url is intentionally NOT set
    by the preset (operator wires their own SIEM)."""
    from iam_jit.bouncer.deployment_presets import build_security_observe

    p = build_security_observe(product="ibounce")
    # The preset should not introduce a webhook URL.
    assert "audit_webhook_url" not in p.values
    assert "audit_webhook_token" not in p.values
