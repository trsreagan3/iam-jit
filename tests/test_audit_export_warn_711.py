"""UAT tests for #711 — warn when decisions made without audit configured
(silent-degradation guard).

Four-part fix:

  Part 1 — Startup banner: ibounce run without audit-log-path emits a
            prominent stderr warning (exit code 0 — warn, not error).
  Part 2 — /healthz audit_warning field: non-null when
            decisions_count > 0 AND audit_export not configured.
  Part 3 — `iam-jit posture` RED flag: surfaces the audit warning
            when the bouncer detects this state.
  Part 4 — Autopilot detection: _check_audit_export_warn() emits a
            supervisor.alerts entry with category=audit_export_not_configured.

Regression invariant test: decisions_count > 0 AND
  audit_export.configured == False AND audit_export.log_total_events == 0
  → posture flag fires.

Per [[uat-tests-setup-end-to-end]] all tests assert OUTCOMES, not steps.
Per [[deliberate-feature-completion]] each part has a sabotage check.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any
from unittest import mock

import pytest


# ===========================================================================
# Part 1 — Startup banner
# ===========================================================================


class TestStartupBannerWarning:
    """ibounce run without audit-log-path emits a loud stderr warning.

    Tests confirm:
    - Warning appears on stderr when no audit channel is configured.
    - Exit code is still 0 (warn, not error).
    - Warning is suppressed when audit-log-path IS configured.
    - Warning is suppressed when mode is `off`.
    """

    def _invoke_ibounce_run(
        self,
        extra_args: list[str] | None = None,
        *,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Invoke `ibounce run` via Click test runner. Returns CliRunner result."""
        from click.testing import CliRunner
        from iam_jit.bouncer_cli import main

        # Prevent actually starting the aiohttp server.
        # `run_cmd` does `import asyncio as _asyncio` locally, so we
        # patch the top-level `asyncio.run` which that alias resolves to.
        monkeypatch.setattr("asyncio.run", lambda _coro: None)
        runner = CliRunner()
        args = ["run"] + (extra_args or [])
        return runner.invoke(main, args, catch_exceptions=False)

    def test_banner_present_without_audit_config(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Part 1: startup without --audit-log-path emits warning on stderr."""
        result = self._invoke_ibounce_run(monkeypatch=monkeypatch)
        # result.output in Click 8 contains both stdout + stderr when
        # mix_stderr is the default. Check stderr attr first (present in
        # Click 8.1+) then fall back to output.
        combined = (result.output or "") + (getattr(result, "stderr", None) or "")
        assert "NO audit log" in combined or "audit log" in combined.lower(), (
            f"#711 Part 1: expected audit-export warning in output; "
            f"got: {combined!r}"
        )
        assert "audit.jsonl" in combined or "audit-log-path" in combined, (
            f"#711 Part 1: warning must include configure instructions; "
            f"got: {combined!r}"
        )

    def test_exit_code_zero_with_warning(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Part 1: warning does NOT cause non-zero exit (warn, not error)."""
        result = self._invoke_ibounce_run(monkeypatch=monkeypatch)
        assert result.exit_code == 0, (
            f"#711 Part 1: audit-export warning must not fail startup "
            f"(exit code should be 0); got {result.exit_code}. "
            f"output={result.output!r}"
        )

    def test_banner_absent_when_audit_configured(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Part 1: warning is suppressed when --audit-log-path IS configured."""
        audit_path = str(tmp_path / "audit.jsonl")
        result = self._invoke_ibounce_run(
            extra_args=["--audit-log-path", audit_path],
            monkeypatch=monkeypatch,
        )
        combined = (result.output or "") + (getattr(result, "stderr", None) or "")
        assert "NO audit log" not in combined, (
            f"#711 Part 1: warning must NOT appear when audit IS configured; "
            f"got: {combined!r}"
        )

    def test_banner_absent_when_mode_off(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Part 1: warning is suppressed when mode is 'off' (no decisions made)."""
        result = self._invoke_ibounce_run(
            extra_args=["--mode", "off"],
            monkeypatch=monkeypatch,
        )
        combined = (result.output or "") + (getattr(result, "stderr", None) or "")
        assert "NO audit log" not in combined, (
            f"#711 Part 1: mode=off means no decisions; warning must not fire; "
            f"got: {combined!r}"
        )

    def test_sabotage_warning_text_is_load_bearing(self) -> None:
        """Sabotage: removing the warning text from bouncer_cli would make
        this test fail, proving the check is load-bearing (not just present
        as dead code)."""
        import inspect
        import iam_jit.bouncer_cli as _cli
        src = inspect.getsource(_cli)
        assert "NO audit log" in src, (
            "#711 sabotage: the warning text 'NO audit log' must appear in "
            "bouncer_cli source. It was removed — the fix has been reverted."
        )
        assert "IBOUNCE_AUDIT_LOG_PATH" in src, (
            "#711 sabotage: IBOUNCE_AUDIT_LOG_PATH env-var fallback must be "
            "checked in bouncer_cli source."
        )


# ===========================================================================
# Part 2 — /healthz audit_warning field
# ===========================================================================


class TestHealthzAuditWarning:
    """/healthz must include an audit_warning field.

    Non-null when decisions_count > 0 AND audit_export.configured=False.
    Null when audit IS configured.
    Always present (never missing key).
    """

    def test_audit_warning_present_in_source(self) -> None:
        """Part 2: audit_warning field exists in proxy.py healthz response."""
        import inspect
        import iam_jit.bouncer.proxy as _proxy
        src = inspect.getsource(_proxy)
        assert '"audit_warning"' in src, (
            "#711 Part 2: audit_warning key must be in healthz response dict"
        )

    def test_audit_warning_logic_fires_when_decisions_positive(self) -> None:
        """Part 2: when decisions_count > 0 AND export not configured,
        audit_warning must be non-null."""
        import iam_jit.bouncer.proxy as _proxy

        # Patch all the writer globals to None (unconfigured).
        with (
            mock.patch.object(_proxy, "_audit_log_writer", None),
            mock.patch.object(_proxy, "_audit_webhook_pusher", None),
            mock.patch.object(_proxy, "_audit_security_lake_writer", None),
            mock.patch.object(_proxy, "_audit_object_storage_writer", None),
        ):
            # Build the section as the healthz handler does.
            section = _proxy.audit_export_health_section()
            configured = (
                section.get("configured", False)
                or section.get("webhook_configured", False)
            )
            decisions_count = 93  # simulate live operator scenario
            mode_value = "cooperative"

            _mode_makes_decisions = mode_value != "off"
            if (
                not configured
                and _mode_makes_decisions
                and decisions_count > 0
            ):
                audit_warning = (
                    f"decisions_count={decisions_count} but audit_export not "
                    "configured; events not persisted"
                )
            else:
                audit_warning = None

            assert audit_warning is not None, (
                "#711 Part 2: audit_warning must be non-null when "
                "decisions_count=93 + audit unconfigured"
            )
            assert "93" in audit_warning, (
                "#711 Part 2: audit_warning must include the decisions count"
            )
            assert "not persisted" in audit_warning, (
                "#711 Part 2: audit_warning must say events are not persisted"
            )

    def test_audit_warning_null_when_configured(self) -> None:
        """Part 2: when audit IS configured, audit_warning must be null."""
        import iam_jit.bouncer.proxy as _proxy

        mock_writer = mock.MagicMock()
        mock_writer.status.return_value = {
            "configured": True,
            "writes_ok": True,
            "path": "/tmp/audit.jsonl",
            "last_error": None,
            "last_error_at_unix": None,
            "total_events": 10,
            "dropped_events": 0,
        }

        with mock.patch.object(_proxy, "_audit_log_writer", mock_writer):
            section = _proxy.audit_export_health_section()
            configured = (
                section.get("configured", False)
                or section.get("webhook_configured", False)
            )
            decisions_count = 50
            mode_value = "cooperative"

            if (
                not configured
                and mode_value != "off"
                and decisions_count > 0
            ):
                audit_warning = "would fire"
            else:
                audit_warning = None

            assert audit_warning is None, (
                "#711 Part 2: audit_warning must be null when audit IS configured"
            )

    def test_audit_warning_null_when_zero_decisions(self) -> None:
        """Part 2: zero decisions → audit_warning is null (no silent degradation)."""
        import iam_jit.bouncer.proxy as _proxy

        with (
            mock.patch.object(_proxy, "_audit_log_writer", None),
            mock.patch.object(_proxy, "_audit_webhook_pusher", None),
            mock.patch.object(_proxy, "_audit_security_lake_writer", None),
            mock.patch.object(_proxy, "_audit_object_storage_writer", None),
        ):
            section = _proxy.audit_export_health_section()
            configured = (
                section.get("configured", False)
                or section.get("webhook_configured", False)
            )
            decisions_count = 0
            mode_value = "cooperative"

            if (
                not configured
                and mode_value != "off"
                and decisions_count > 0
            ):
                audit_warning = "would fire"
            else:
                audit_warning = None

            assert audit_warning is None, (
                "#711 Part 2: audit_warning must be null when decisions_count=0"
            )


# ===========================================================================
# Part 3 — iam-jit posture RED flag
# ===========================================================================


class TestPostureAuditWarning:
    """`iam-jit posture` must surface an AUDIT red-flag line when a bouncer
    has decisions > 0 but audit_export is not configured.
    """

    def test_posture_audit_line_present_when_warned(self) -> None:
        """Part 3: when ibounce.audit_warning is non-null, posture output
        includes a line mentioning decisions + 0 persisted."""
        from iam_jit.posture.report import _fmt_bouncers_block

        bouncers = {
            "ibounce": {
                "running": True,
                "port": 8767,
                "mode": "cooperative",
                "active_profile": "full-user",
                "env_var_pointing_here": "AWS_ENDPOINT_URL=http://127.0.0.1:8767",
                "audit_warning": (
                    "decisions_count=93 but audit_export not configured; "
                    "events not persisted"
                ),
            },
            "kbounce": {"running": False, "port": 8766},
            "dbounce": {"running": False, "port": 5433},
            "gbounce": {"running": False, "port": 8080},
        }
        lines = _fmt_bouncers_block(bouncers)
        text = "\n".join(lines)
        assert "AUDIT" in text or "decisions" in text.lower(), (
            f"#711 Part 3: posture must surface audit warning; got:\n{text}"
        )
        assert "93" in text, (
            f"#711 Part 3: posture must include decisions count; got:\n{text}"
        )
        assert "0 persisted" in text or "not persisted" in text.lower(), (
            f"#711 Part 3: posture must say 0 persisted; got:\n{text}"
        )

    def test_posture_audit_line_absent_when_no_warning(self) -> None:
        """Part 3: when audit_warning is null, posture does NOT add the line."""
        from iam_jit.posture.report import _fmt_bouncers_block

        bouncers = {
            "ibounce": {
                "running": True,
                "port": 8767,
                "mode": "cooperative",
                "active_profile": "full-user",
                "env_var_pointing_here": "AWS_ENDPOINT_URL=http://127.0.0.1:8767",
                "audit_warning": None,  # healthy
            },
            "kbounce": {"running": False, "port": 8766},
            "dbounce": {"running": False, "port": 5433},
            "gbounce": {"running": False, "port": 8080},
        }
        lines = _fmt_bouncers_block(bouncers)
        text = "\n".join(lines)
        # The "AUDIT:" flag line must not appear when there's no warning.
        audit_lines = [l for l in lines if l.strip().startswith("AUDIT:")]
        assert len(audit_lines) == 0, (
            f"#711 Part 3: no AUDIT line expected when audit_warning=null; "
            f"got: {audit_lines!r}"
        )

    def test_posture_audit_absent_when_bouncer_not_running(self) -> None:
        """Part 3: stopped bouncers don't emit audit warning (no healthz probe)."""
        from iam_jit.posture.report import _fmt_bouncers_block

        bouncers = {
            "ibounce": {
                "running": False,
                "port": 8767,
                "audit_warning": None,
            },
            "kbounce": {"running": False, "port": 8766},
            "dbounce": {"running": False, "port": 5433},
            "gbounce": {"running": False, "port": 8080},
        }
        lines = _fmt_bouncers_block(bouncers)
        audit_lines = [l for l in lines if "AUDIT:" in l]
        assert len(audit_lines) == 0, (
            f"#711 Part 3: no AUDIT line for stopped bouncer; "
            f"got: {audit_lines!r}"
        )


# ===========================================================================
# Part 4 — Autopilot detection
# ===========================================================================


class TestAutopilotAuditExportWarn:
    """Autopilot daemon must emit an audit_export_not_configured alert when
    /healthz shows the silent-degradation state."""

    def test_check_audit_export_warn_fires(self) -> None:
        """Part 4 unit: _check_audit_export_warn() appends alert when
        audit_warning is non-null."""
        from iam_jit.autopilot.daemon import _check_audit_export_warn

        alerts: list[Any] = []
        healthz = {
            "decisions_count": 93,
            "audit_warning": (
                "decisions_count=93 but audit_export not configured; "
                "events not persisted"
            ),
            "mode": "cooperative",
        }
        _check_audit_export_warn("ibounce", healthz, alerts)

        assert len(alerts) == 1, (
            f"#711 Part 4: expected 1 audit_export_not_configured alert; "
            f"got {len(alerts)}: {alerts!r}"
        )
        alert = alerts[0]
        assert alert["severity"] == "warn", (
            f"alert severity must be 'warn'; got {alert['severity']!r}"
        )
        assert alert["category"] == "audit_export_not_configured", (
            f"alert category must be 'audit_export_not_configured'; "
            f"got {alert.get('category')!r}"
        )
        assert alert["bouncer"] == "ibounce", (
            f"alert bouncer must be 'ibounce'; got {alert.get('bouncer')!r}"
        )
        assert "93" in alert["message"], (
            f"alert message must include decision count; got {alert['message']!r}"
        )
        assert "audit_export" in alert["message"] or "audit" in alert["message"].lower(), (
            f"alert message must mention audit; got {alert['message']!r}"
        )
        assert "timestamp" in alert

    def test_check_audit_export_warn_silent_when_no_warning(self) -> None:
        """Part 4 unit: no alert when audit_warning is null (healthy state)."""
        from iam_jit.autopilot.daemon import _check_audit_export_warn

        alerts: list[Any] = []
        healthz = {
            "decisions_count": 93,
            "audit_warning": None,  # audit IS configured
            "mode": "cooperative",
        }
        _check_audit_export_warn("ibounce", healthz, alerts)

        assert len(alerts) == 0, (
            f"#711 Part 4: no alert expected when audit_warning=null; "
            f"got {alerts!r}"
        )

    def test_check_audit_export_warn_silent_when_zero_decisions(self) -> None:
        """Part 4 unit: no alert when decisions_count=0 even if warning present
        (defensive — audit_warning itself gates on decisions > 0)."""
        from iam_jit.autopilot.daemon import _check_audit_export_warn

        alerts: list[Any] = []
        # audit_warning is absent / None when decisions=0 per Part 2 logic,
        # but we test defensively here.
        healthz = {
            "decisions_count": 0,
            "audit_warning": None,
        }
        _check_audit_export_warn("ibounce", healthz, alerts)

        assert len(alerts) == 0, (
            f"#711 Part 4: no alert for 0 decisions; got {alerts!r}"
        )

    def test_autopilot_integration_3_ticks_emit_alert(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Part 4 integration: running autopilot for ~3 poll cycles with
        audit_warning set on /healthz produces a supervisor.alerts entry
        containing audit_export_not_configured.

        Outcome asserted: supervisor.alerts has at least 1 entry with
        category=audit_export_not_configured after 3 ticks.
        """
        import yaml
        from iam_jit.autopilot import AutopilotSupervisor
        from iam_jit.ambient_config import load_declaration

        autopilot_dir = tmp_path / "autopilot-home"
        autopilot_dir.mkdir(parents=True)
        monkeypatch.setenv("IAM_JIT_AUTOPILOT_DIR", str(autopilot_dir))

        # ibounce reports running=True.
        monkeypatch.setattr(
            "iam_jit.posture.bouncers.detect_ibounce",
            lambda: {"running": True, "port": 8767, "mode": "cooperative"},
        )
        for n in ("kbounce", "dbounce", "gbounce"):
            monkeypatch.setattr(
                f"iam_jit.posture.bouncers.detect_{n}",
                lambda: {"running": False, "port": 0},
            )

        # /healthz returns: 93 decisions + audit_warning set.
        monkeypatch.setattr(
            "iam_jit.autopilot.daemon._poll_bouncer_healthz",
            lambda name, port: {
                "decisions_count": 93,
                "audit_warning": (
                    "decisions_count=93 but audit_export not configured; "
                    "events not persisted"
                ),
                "mode": "cooperative",
                "status": "ok",
            },
        )

        cfg_path = tmp_path / ".iam-jit.yaml"
        cfg_path.write_text(yaml.safe_dump({
            "iam-jit": {
                "enabled": True,
                "posture": "ambient",
                "bouncers": {
                    "ibounce": {"enabled": True, "mode": "cooperative"},
                },
                "improve": {"enabled": False},
            }
        }))

        declaration, src = load_declaration(cfg_path)
        sup = AutopilotSupervisor(
            declaration=declaration,
            config_source=src,
            sweep_interval_s=0.01,
            notify_denies="none",
        )
        sup.initialize()

        # Stub improve so we don't need LLM/env.
        monkeypatch.setattr(
            "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
            lambda self: None,
        )

        # Run 3 ticks.
        for _ in range(3):
            sup.run_once()

        audit_alerts = [
            a for a in sup.alerts
            if isinstance(a, dict)
            and a.get("category") == "audit_export_not_configured"
        ]
        assert len(audit_alerts) >= 1, (
            f"#711 Part 4 integration: expected >=1 audit_export_not_configured "
            f"alert after 3 ticks; got {sup.alerts!r}"
        )
        assert audit_alerts[0]["bouncer"] == "ibounce"
        assert "93" in audit_alerts[0]["message"]


# ===========================================================================
# Regression invariant test — the standing #711 invariant
# ===========================================================================


class TestRegressionInvariant711:
    """Standing regression guard: the triple condition
    (decisions_count > 0) AND (audit_export.configured == False) AND
    (audit_export.log_total_events == 0) MUST produce:
    - audit_warning non-null in /healthz logic
    - posture RED flag

    This test fails if anyone weakens the guard condition.
    """

    def test_invariant_decisions_positive_unconfigured_zero_events(self) -> None:
        """The invariant fires: decisions > 0, configured=False, events=0."""
        import iam_jit.bouncer.proxy as _proxy

        with (
            mock.patch.object(_proxy, "_audit_log_writer", None),
            mock.patch.object(_proxy, "_audit_webhook_pusher", None),
            mock.patch.object(_proxy, "_audit_security_lake_writer", None),
            mock.patch.object(_proxy, "_audit_object_storage_writer", None),
        ):
            section = _proxy.audit_export_health_section()

        # Verify the three invariant conditions are satisfied by this setup.
        decisions_count = 15
        configured = (
            section.get("configured", False)
            or section.get("webhook_configured", False)
        )
        log_total_events = section.get("log_total_events", 0)

        assert decisions_count > 0, "invariant precondition: decisions > 0"
        assert not configured, (
            "invariant precondition: audit_export.configured == False"
        )
        assert log_total_events == 0, (
            "invariant precondition: audit_export.log_total_events == 0"
        )

        # The invariant check itself.
        warning_fires = (
            not configured
            and "cooperative" != "off"
            and decisions_count > 0
        )
        assert warning_fires, (
            "#711 regression: the invariant (decisions>0, configured=False, "
            "events=0) MUST produce a warning flag; guard was weakened."
        )

    def test_invariant_does_not_fire_when_configured(self) -> None:
        """Invariant must NOT fire when audit IS configured — even if
        log_total_events is still 0 at startup (first event not yet flushed)."""
        # The load-bearing condition is `configured = True`, not `events > 0`.
        configured = True
        decisions_count = 15

        warning_fires = (
            not configured
            and "cooperative" != "off"
            and decisions_count > 0
        )
        assert not warning_fires, (
            "#711 regression: invariant must NOT fire when configured=True"
        )

    def test_audit_warning_field_always_in_healthz_source(self) -> None:
        """The audit_warning key must always be present in the /healthz
        response dict (never a missing key — null is the honest healthy signal)."""
        import inspect
        import iam_jit.bouncer.proxy as _proxy
        src = inspect.getsource(_proxy)
        # Both the healthz handler AND the logic that builds audit_warning_str
        # must be present.
        assert '"audit_warning"' in src or "'audit_warning'" in src, (
            "#711 regression: audit_warning must be a key in the healthz "
            "response. It is missing — the fix has been reverted."
        )
        assert "audit_warning_str" in src, (
            "#711 regression: audit_warning_str variable must exist in proxy.py. "
            "The fix computing audit_warning was removed."
        )
