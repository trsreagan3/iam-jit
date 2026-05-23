"""§A93 / #509 Phase 2 — autopilot daemon ``--enable-side-llm`` tests.

Per [[bouncer-zero-llm-when-agent-in-loop]]:

  * Default behavior (flag UNSET): autopilot improve cycle runs in
    deterministic-only mode + emits a structured report_skip so
    operators see the deferral.
  * Flag SET without LLM creds: autopilot REFUSES TO START with a
    clear error (per [[ibounce-honest-positioning]]).
  * Flag SET with LLM creds: autopilot accepts + status.json
    surfaces ``side_llm_enabled: true``.

State-verification convention per ``docs/CONTRIBUTING.md`` — every
test asserts on OBSERVABLE state: status.json fields, the skip counter
snapshot, the AutopilotError code.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import yaml

from iam_jit.autopilot import (
    AutopilotError,
    AutopilotSupervisor,
    autopilot_start,
    resolve_pid_path,
)
from iam_jit.llm import reset_skip_counter, skip_counter_snapshot


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_autopilot_dir(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    autopilot_dir = tmp_path / "autopilot-home"
    autopilot_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("IAM_JIT_AUTOPILOT_DIR", str(autopilot_dir))
    return autopilot_dir


@pytest.fixture(autouse=True)
def _reset_skip_counter() -> None:
    reset_skip_counter()
    yield
    reset_skip_counter()


@pytest.fixture(autouse=True)
def _no_llm_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip every LLM-related env var so the default path is honestly
    'no creds configured'."""
    for var in (
        "IAM_JIT_LLM",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "IAM_JIT_BEDROCK_MODEL",
        "OLLAMA_HOST",
        "IAM_JIT_ENABLE_SIDE_LLM",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def write_config(tmp_path: pathlib.Path):
    def _w(body: dict) -> pathlib.Path:
        p = tmp_path / ".iam-jit.yaml"
        p.write_text(yaml.safe_dump(body))
        return p
    return _w


@pytest.fixture
def stub_posture_running(monkeypatch: pytest.MonkeyPatch):
    """Stub bouncer-posture detectors so the supervisor doesn't try to
    spawn / contact real bouncers."""
    state = {
        "ibounce": {"running": True, "port": 8767, "mode": "discovery"},
        "kbouncer": {"running": False, "port": 8766},
        "dbounce": {"running": False, "port": 5433},
        "gbounce": {"running": False, "port": 8080},
    }

    def _make_detector(name: str):
        def _d():
            return dict(state[name])
        return _d

    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce", _make_detector("ibounce")
    )
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_kbounce", _make_detector("kbouncer")
    )
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_dbounce", _make_detector("dbounce")
    )
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_gbounce", _make_detector("gbounce")
    )


@pytest.fixture
def stub_start_bouncer(monkeypatch: pytest.MonkeyPatch):
    def _fake(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": True, "pid": 99999,
            "command": [], "port": port or 8767, "mode": mode,
            "profile": profile,
        }
    monkeypatch.setattr("iam_jit.ambient_config.setup._start_bouncer", _fake)


@pytest.fixture
def quiet_improve(monkeypatch: pytest.MonkeyPatch):
    """Stub improve_profile so the supervisor's improve cycle doesn't
    drive the real pipeline (we're testing the daemon's gating, not the
    pipeline itself)."""
    captured: list[dict] = []

    def _fake(**kwargs):
        from iam_jit.improve import ImproveProfileResult
        captured.append(kwargs)
        return ImproveProfileResult(
            status="no_change",
            bouncer=kwargs.get("bouncer", "ibounce"),
            cadence_window="1h",
            posture=kwargs.get("posture", "ambient"),
        )

    monkeypatch.setattr("iam_jit.improve.improve_profile", _fake)
    return captured


# ---------------------------------------------------------------------------
# Default OFF — local-dev / agent-in-loop mode
# ---------------------------------------------------------------------------


def test_autopilot_default_runs_deterministic_only_and_records_skip(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No --enable-side-llm: improve cycle records a skip with reason
    REASON_NO_SIDE_LLM_ENABLED so operators see the deferral."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": True, "cadence": "per_session"},
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    autopilot_start(
        config_path=cfg, detach=False, notify_denies="none",
        sweep_interval_s=0.01, max_ticks=1,
    )
    # Observable: status.json says side_llm_enabled is False.
    sf = resolve_pid_path().parent / "autopilot.status.json"
    assert sf.exists()
    payload = json.loads(sf.read_text())
    assert payload["side_llm_enabled"] is False
    # Observable: report_skip was called → counter snapshot in status
    # has at least one autopilot.improve_cycle entry.
    skips = payload.get("llm_skips") or {}
    assert skips.get("counts", {}).get("autopilot.improve_cycle", 0) >= 1
    assert skips.get("total", 0) >= 1


def test_autopilot_default_improve_called_with_no_preferred_backend(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When side-LLM is OFF, improve_profile is still called (the
    deterministic event-derived path still installs rules)."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": True, "cadence": "per_session"},
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    autopilot_start(
        config_path=cfg, detach=False, notify_denies="none",
        sweep_interval_s=0.01, max_ticks=1,
    )
    # quiet_improve captured the call.
    assert len(quiet_improve) >= 1
    # No `preferred_backend` was passed (defaults to None).
    for call in quiet_improve:
        assert "preferred_backend" not in call or call["preferred_backend"] is None


def test_autopilot_default_skip_counter_visible_via_helper() -> None:
    """The in-process counter is also reachable directly via the
    library (parity with /healthz + posture)."""
    from iam_jit.autopilot.daemon import AutopilotSupervisor

    sup = AutopilotSupervisor(
        declaration={
            "iam-jit": {
                "enabled": True,
                "improve": {"enabled": True, "cadence": "per_session"},
                "bouncers": {},
            }
        },
        config_source="<test>",
        sweep_interval_s=0.01,
        improve_interval_s=0.0,
        side_llm_enabled=False,
    )
    sup.initialize()
    # Drive one improve cycle directly (no bouncers → no inner work,
    # but the up-front skip MUST fire).
    sup.run_improve_for_all()
    snap = skip_counter_snapshot()
    assert snap["counts"].get("autopilot.improve_cycle", 0) == 1


# ---------------------------------------------------------------------------
# Opt-in WITHOUT creds — must fail loudly
# ---------------------------------------------------------------------------


def test_autopilot_enable_side_llm_without_backend_raises(
    write_config,
) -> None:
    """--enable-side-llm with no IAM_JIT_LLM set MUST raise a clear
    AutopilotError + exit code so the operator can't silently end up
    with deterministic-only despite their flag."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True}},
            "improve": {"enabled": True, "cadence": "per_session"},
        }
    })
    with pytest.raises(AutopilotError) as exc_info:
        autopilot_start(
            config_path=cfg, detach=False,
            notify_denies="none", sweep_interval_s=0.01, max_ticks=1,
            enable_side_llm=True,
        )
    assert exc_info.value.code == "side_llm_no_backend"
    # The error message points the operator at the fix.
    assert "IAM_JIT_LLM" in str(exc_info.value)


def test_autopilot_enable_side_llm_with_unknown_backend_raises(
    write_config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM_JIT_LLM=gpt5-turbo (or any unsupported value) must raise."""
    monkeypatch.setenv("IAM_JIT_LLM", "gpt5-turbo")
    cfg = write_config({
        "iam-jit": {
            "enabled": True, "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True}},
            "improve": {"enabled": True},
        }
    })
    with pytest.raises(AutopilotError) as exc_info:
        autopilot_start(
            config_path=cfg, detach=False,
            sweep_interval_s=0.01, max_ticks=1,
            enable_side_llm=True,
        )
    assert exc_info.value.code == "side_llm_unknown_backend"


def test_autopilot_enable_side_llm_anthropic_without_key_raises(
    write_config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM_JIT_LLM=anthropic but no ANTHROPIC_API_KEY → loud failure."""
    monkeypatch.setenv("IAM_JIT_LLM", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = write_config({
        "iam-jit": {
            "enabled": True, "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True}},
            "improve": {"enabled": True},
        }
    })
    with pytest.raises(AutopilotError) as exc_info:
        autopilot_start(
            config_path=cfg, detach=False,
            sweep_interval_s=0.01, max_ticks=1,
            enable_side_llm=True,
        )
    assert exc_info.value.code == "side_llm_missing_credential"
    assert "ANTHROPIC_API_KEY" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Opt-in WITH creds — succeeds + status reflects the flag
# ---------------------------------------------------------------------------


def test_autopilot_enable_side_llm_with_anthropic_key_starts(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM_JIT_LLM=anthropic + ANTHROPIC_API_KEY set → autopilot accepts
    the flag + status.json reflects side_llm_enabled: true."""
    monkeypatch.setenv("IAM_JIT_LLM", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = write_config({
        "iam-jit": {
            "enabled": True, "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": True, "cadence": "per_session"},
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    autopilot_start(
        config_path=cfg, detach=False, notify_denies="none",
        sweep_interval_s=0.01, max_ticks=1,
        enable_side_llm=True,
    )
    sf = resolve_pid_path().parent / "autopilot.status.json"
    assert sf.exists()
    payload = json.loads(sf.read_text())
    assert payload["side_llm_enabled"] is True
    # When opt-in IS set, the "no-side-llm" skip MUST NOT fire for the
    # improve cycle (it would defeat the operator's explicit opt-in).
    skips = payload.get("llm_skips") or {}
    assert skips.get("counts", {}).get("autopilot.improve_cycle", 0) == 0


def test_autopilot_enable_side_llm_with_ollama_default_host_starts(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ollama defaults to localhost; no OLLAMA_HOST required to start."""
    monkeypatch.setenv("IAM_JIT_LLM", "ollama")
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    cfg = write_config({
        "iam-jit": {
            "enabled": True, "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": True},
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    # Should NOT raise.
    autopilot_start(
        config_path=cfg, detach=False, notify_denies="none",
        sweep_interval_s=0.01, max_ticks=1,
        enable_side_llm=True,
    )


# ---------------------------------------------------------------------------
# Status JSON schema parity
# ---------------------------------------------------------------------------


def test_autopilot_status_json_includes_llm_skips_block(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status JSON ALWAYS includes the llm_skips block (even when
    empty) so monitors can branch on a stable shape."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True, "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True}},
            "improve": {"enabled": False},  # disable improve → no skip emitted
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    autopilot_start(
        config_path=cfg, detach=False, notify_denies="none",
        sweep_interval_s=0.01, max_ticks=1,
    )
    sf = resolve_pid_path().parent / "autopilot.status.json"
    payload = json.loads(sf.read_text())
    assert "llm_skips" in payload
    block = payload["llm_skips"]
    assert set(block) >= {"total", "counts", "by_reason", "last_skips"}
