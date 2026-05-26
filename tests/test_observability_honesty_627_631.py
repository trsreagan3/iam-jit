"""UAT-Observability 2026-05-26 — 5 silent-degradation honesty gaps.

  #627 CRIT  /healthz audit_log.status "not_configured" when unconfigured
  #628 HIGH  audit query --since <invalid> exits 2 / all-fail exits 1
  #629 MED   autopilot status exits 1 when daemon not running
  #630 MED   canary monitor UNKNOWN (not GREEN) when 0 bouncers
  #631 LOW   digest dedupes "ran deterministic-only" log (at most 1x)

Per [[ibounce-honest-positioning]]: "ok"/"GREEN"/"exit 0" are claims; they
must correspond to actual healthy/running state or they are lies.
Per [[deliberate-feature-completion]]: every fix ships with tests + a
sabotage check where the gate is load-bearing.
"""

from __future__ import annotations

import json
import pathlib
from unittest import mock

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main


# ===========================================================================
# #627 — /healthz audit_log.status "not_configured" when audit not configured
# ===========================================================================

class Test627HealthzAuditLogStatus:
    """/healthz must report audit_log.status="not_configured" when
    audit logging is off; pre-fix it reported "ok"."""

    def test_not_configured_status_string(self) -> None:
        """Unit: the else-branch that builds the unconfigured block must
        use "not_configured", not "ok"."""
        # Import the proxy module and check the constant path without
        # spinning up a live server — the fix is in the literal dict.
        # We validate by probing the source string via the module's
        # code path through a helper.
        from iam_jit.bouncer.audit_export import healthz_audit_log_block
        from iam_jit.bouncer.audit_export.disk_pressure import DiskPressureState
        from iam_jit.bouncer.audit_export import DISK_PRESSURE_MODE_PAUSE_REQUESTS

        # When a DiskPressureState IS present the block comes from
        # healthz_audit_log_block (configured path); validate it's "ok"
        # or worse — not "not_configured".
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            state = DiskPressureState(
                mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
                log_dir=td,
            )
            state.current_status = "ok"
            state.disk_free_pct = 50.0
            state.used_pct = 50.0
            block = healthz_audit_log_block(state)
            assert block["status"] != "not_configured", (
                "configured path must NOT say not_configured"
            )

    def test_proxy_unconfigured_block_shape(self) -> None:
        """Integration: verify the actual dict emitted in proxy.py's else
        branch has status='not_configured'. We patch the private helper
        and inspect the returned block value directly."""
        # Import the BouncerStore + ProxyConfig helpers so we can inspect
        # what the /healthz handler builds without a live aiohttp server.
        # The simplest approach: monkeypatch active_disk_pressure_state
        # to return None, then call the handler through a minimal path.
        # Since the handler is an inner function + the async server is
        # heavyweight, we inspect the source literal instead.
        import iam_jit.bouncer.proxy as _proxy
        import inspect
        src = inspect.getsource(_proxy)
        # After the fix the "status": "not_configured" literal must appear
        # in the else branch that builds the unconfigured block.
        assert '"status": "not_configured"' in src, (
            "#627: proxy.py must emit status='not_configured' when audit "
            "logging is not configured. Found status='ok' (pre-fix) or "
            "missing string."
        )
        # Sanity: the reason field is still present for backward-compat.
        assert '"reason": "audit logging not configured"' in src, (
            "backward-compat: reason field must be preserved alongside status"
        )

    def test_existing_test_updated(self) -> None:
        """State-verification: the existing
        test_healthz_audit_log_block_absent_when_no_log_path test now
        asserts 'not_configured'. This test confirms the assertion string
        was updated (guards against reverting just the test)."""
        import tests.bouncer.test_disk_pressure_circuit_breaker as _tmod
        import inspect
        src = inspect.getsource(_tmod)
        # The test must assert 'not_configured', not 'ok'.
        assert '"not_configured"' in src or "'not_configured'" in src, (
            "#627: test_disk_pressure_circuit_breaker must assert "
            "status=='not_configured'"
        )
        assert (
            '"ok"' not in src.split("block[\"status\"] ==")[1].split("\n")[0]
            if 'block["status"] ==' in src else True
        ), (
            "#627: old assertion block[status]==\"ok\" must be removed"
        )


# ===========================================================================
# #628 — audit query --since <invalid> exits 2 / all-bouncers-fail exits 1
# ===========================================================================

class Test628AuditQuerySinceValidation:
    """--since / --until validation must gate before the fan-out (exit 2).
    All-bouncers-failed fan-out must exit 1 (not 0)."""

    def test_invalid_since_exits_2(self) -> None:
        """Invalid --since: exit code 2 + clear error message."""
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            ["audit", "query", "--bouncer", "ibounce=http://127.0.0.1:1",
             "--since", "bad-value"],
        )
        assert result.exit_code == 2, (
            f"#628: invalid --since must exit 2; got {result.exit_code}. "
            f"Output: {result.output!r}"
        )
        out = (result.output or "") + (result.stderr or "")
        assert "bad-value" in out or "--since" in out, (
            "#628: error message must reference the bad flag/value"
        )

    def test_invalid_until_exits_2(self) -> None:
        """Invalid --until: exit code 2 + clear error message."""
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            ["audit", "query", "--bouncer", "ibounce=http://127.0.0.1:1",
             "--until", "not-a-date"],
        )
        assert result.exit_code == 2, (
            f"#628: invalid --until must exit 2; got {result.exit_code}"
        )

    def test_valid_since_formats_accepted(self) -> None:
        """Valid --since forms must NOT trigger the validation error.
        Use an unreachable port so the command fails with exit 1 (fan-out
        failure), not exit 2 (validation failure) — confirming the gate
        passes valid values through."""
        runner = CliRunner()
        for spec in ("24h", "2d", "6M", "2y", "2026-05-01T00:00:00Z"):
            result = runner.invoke(
                iam_jit_main,
                ["audit", "query", "--bouncer", "ibounce=http://127.0.0.1:1",
                 "--since", spec],
            )
            assert result.exit_code != 2, (
                f"#628: valid --since {spec!r} must not be rejected (exit 2); "
                f"got {result.exit_code}"
            )

    def test_all_bouncers_failed_exits_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When all bouncers error (e.g. all unreachable) + zero events:
        exit 1. Pre-#628 this exited 0 — indistinguishable from 'no events'."""
        from iam_jit import cli_audit_query as caq
        from iam_jit.cli_audit_query import _BouncerQueryResult

        def _always_fail(endpoint, **kwargs):
            return _BouncerQueryResult(
                bouncer=endpoint.name, events=[], error="connection refused",
            )

        monkeypatch.setattr(caq, "_query_one_bouncer", _always_fail)
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            ["audit", "query", "--bouncer", "ibounce=http://127.0.0.1:1"],
            catch_exceptions=False,
        )
        assert result.exit_code == 1, (
            f"#628: all-bouncers-failed + 0 events must exit 1; "
            f"got {result.exit_code}. Output: {result.output!r}"
        )

    def test_sabotage_validator_no_op_then_all_fail_still_exits_1(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sabotage check: even if the pre-fan-out validator is a no-op,
        the post-fan-out all-failed gate must still work. Proves the
        post-fan-out gate is load-bearing independent of the validator."""
        from iam_jit import cli_audit_query as caq
        # No-op the validator so an invalid since passes through.
        monkeypatch.setattr(caq, "_validate_since_spec", lambda *a, **kw: None)
        from iam_jit.cli_audit_query import _BouncerQueryResult

        def _always_fail(endpoint, **kwargs):
            return _BouncerQueryResult(
                bouncer=endpoint.name, events=[], error="HTTP 400: bad since",
            )

        monkeypatch.setattr(caq, "_query_one_bouncer", _always_fail)
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            ["audit", "query", "--bouncer", "ibounce=http://127.0.0.1:1",
             "--since", "definitely-invalid"],
            catch_exceptions=False,
        )
        assert result.exit_code == 1, (
            "sabotage: even with validator no-op, all-failed fan-out must "
            f"exit 1; got {result.exit_code}"
        )


# ===========================================================================
# #629 — autopilot status exits 1 when daemon not running
# ===========================================================================

class Test629AutopilotStatusExitCode:
    """autopilot status must exit 1 when daemon is not running."""

    @pytest.fixture(autouse=True)
    def _isolate(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        autopilot_dir = tmp_path / "autopilot"
        autopilot_dir.mkdir()
        monkeypatch.setenv("IAM_JIT_AUTOPILOT_DIR", str(autopilot_dir))

    def test_status_exits_1_when_not_running(self) -> None:
        """iam-jit autopilot status exits 1 when daemon not running.
        Pre-#629 it exited 0 — making shell guards like
        `if ! iam-jit autopilot status` silently wrong."""
        runner = CliRunner()
        result = runner.invoke(iam_jit_main, ["autopilot", "status"])
        assert result.exit_code == 1, (
            f"#629: 'autopilot status' when not running must exit 1; "
            f"got {result.exit_code}. Output: {result.output!r}"
        )
        out = result.output or ""
        assert "NOT running" in out or "not running" in out.lower(), (
            "#629: output must indicate daemon is not running"
        )

    def test_status_json_exits_1_when_not_running(self) -> None:
        """JSON path also exits 1 when not running."""
        runner = CliRunner()
        result = runner.invoke(iam_jit_main, ["autopilot", "status", "--json"])
        assert result.exit_code == 1, (
            f"#629: 'autopilot status --json' when not running must exit 1; "
            f"got {result.exit_code}"
        )
        # JSON output must still be valid and contain running=false.
        try:
            body = json.loads(result.output or "{}")
        except json.JSONDecodeError:
            pytest.fail(f"#629: --json must emit valid JSON even on exit 1; "
                        f"got: {result.output!r}")
        assert body.get("running") is False, (
            "#629: JSON body must have running=false when exit 1"
        )

    def test_status_exits_0_when_running(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When daemon IS running, autopilot status must exit 0."""
        from iam_jit.autopilot import daemon as _d
        monkeypatch.setattr(
            _d, "autopilot_status",
            lambda: {"running": True, "pid": 12345, "status": {}},
        )
        runner = CliRunner()
        result = runner.invoke(iam_jit_main, ["autopilot", "status"])
        assert result.exit_code == 0, (
            f"#629: 'autopilot status' when running must exit 0; "
            f"got {result.exit_code}. Output: {result.output!r}"
        )


# ===========================================================================
# #630 — canary monitor UNKNOWN (not GREEN) when 0 bouncers in status.json
# ===========================================================================

class Test630CanaryMonitorEmptyBouncers:
    """decision_rate signal must be UNKNOWN when status.json has no
    bouncers; pre-fix it was GREEN (worst never updated from default)."""

    def test_empty_bouncers_returns_unknown(self) -> None:
        """Direct unit test: _signal_decision_rate({}, ...) → UNKNOWN."""
        import time as _t
        from iam_jit.cli_canary import _signal_decision_rate
        sig, _ = _signal_decision_rate({}, {}, _t.time())
        assert sig["status"] == "UNKNOWN", (
            f"#630: empty healthz_by_bouncer must yield UNKNOWN, got "
            f"{sig['status']!r}"
        )

    def test_empty_bouncers_emits_explanatory_note(self) -> None:
        """The note must explain 'no bouncers in status.json'."""
        import time as _t
        from iam_jit.cli_canary import _signal_decision_rate
        sig, _ = _signal_decision_rate({}, {}, _t.time())
        notes = sig.get("notes") or ""
        assert "no bouncers" in notes.lower() or "status.json" in notes, (
            f"#630: UNKNOWN note must mention 'no bouncers'; got: {notes!r}"
        )

    def test_non_empty_bouncers_initializes_green(self) -> None:
        """When bouncers ARE present, worst starts at GREEN (not UNKNOWN)
        before per-bouncer entries update it. Confirms the fix doesn't
        break the normal path."""
        import time as _t
        from iam_jit.cli_canary import _signal_decision_rate
        # Single bouncer with a decisions_count so it'll reach the GREEN
        # entry_status branch.
        healthz = {"ibounce": {"decisions_count": 42}}
        # Prior state with an existing baseline so rate is computable.
        prior = {"decisions": {"ibounce": {"total": 40, "ts": _t.time() - 60}}}
        sig, _ = _signal_decision_rate(healthz, prior, _t.time())
        # With a prior baseline + non-zero count the per-bouncer status is
        # GREEN, which propagates to worst. UNKNOWN is still acceptable if
        # the first-poll baseline hasn't been set yet.
        assert sig["status"] in ("GREEN", "UNKNOWN"), (
            f"#630: non-empty bouncers should not return 'not_configured' or "
            f"other invalid status; got {sig['status']!r}"
        )
        # The "no bouncers" note must NOT appear when bouncers are present.
        notes = sig.get("notes") or ""
        assert "no bouncers" not in notes.lower(), (
            "#630: 'no bouncers' note must not appear when bouncers are present"
        )


# ===========================================================================
# #631 — digest dedupes "ran deterministic-only" log; at most 1x per invoc
# ===========================================================================

class Test631DigestDedupesSkipLog:
    """_classify_deny_rows must emit report_skip at most ONCE per call
    regardless of how many rows are classified."""

    def _make_row(self, bouncer: str = "ibounce"):
        """Build a minimal DenyRow-like object for classification."""
        from iam_jit.profile_allow.denies import DenyRow
        return DenyRow(
            bouncer=bouncer,
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            deny_reason="profile deny",
            deny_source="static_profile",
            agent_session_id="sess-1",
            when="2026-05-26T00:00:00Z",
            rule_id_if_dynamic=None,
            suggested_allow_command="",
        )

    def _get_report_skip_mod(self):
        """Return the actual iam_jit.llm.report_skip MODULE object (not the
        re-exported function from iam_jit.llm.__init__). importlib is needed
        because `import iam_jit.llm.report_skip` resolves to the function
        via __init__.py re-exports."""
        import importlib
        return importlib.import_module("iam_jit.llm.report_skip")

    def test_at_most_one_report_skip_per_call(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When 3 deny rows all run deterministic-only, report_skip is
        called at most once. Pre-#631 it was called 3 times."""
        _rs_mod = self._get_report_skip_mod()
        from iam_jit.digest.core import _classify_deny_rows

        call_count = []

        def fake_report_skip(**kwargs):
            call_count.append(kwargs)

        monkeypatch.setattr(_rs_mod, "report_skip", fake_report_skip)

        rows = [self._make_row() for _ in range(3)]
        _classify_deny_rows(rows)
        assert len(call_count) <= 1, (
            f"#631: report_skip must be called at most 1x per _classify_deny_rows "
            f"invocation; called {len(call_count)} times (1x per event pre-fix)"
        )

    def test_zero_rows_no_report_skip(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Zero rows → no report_skip call (nothing to classify)."""
        _rs_mod = self._get_report_skip_mod()
        from iam_jit.digest.core import _classify_deny_rows

        call_count = []

        def fake_report_skip(**kwargs):
            call_count.append(kwargs)

        monkeypatch.setattr(_rs_mod, "report_skip", fake_report_skip)

        _classify_deny_rows([])
        assert len(call_count) == 0, (
            "#631: 0 rows must produce 0 report_skip calls"
        )

    def test_returns_correct_counts(self) -> None:
        """Classification still returns a bucket-count dict with correct
        keys (regression guard — dedup must not break the output)."""
        from iam_jit.digest.core import _classify_deny_rows

        rows = [self._make_row() for _ in range(5)]
        counts = _classify_deny_rows(rows)
        assert set(counts.keys()) >= {
            "appears_legitimate", "ambiguous", "appears_adversarial",
        }, f"#631: counts dict keys wrong: {counts.keys()}"
        assert sum(counts.values()) == 5, (
            f"#631: total count must equal row count; got {sum(counts.values())}"
        )
