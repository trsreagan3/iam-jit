"""#398 — `iam_jit_setup_from_config` setup-applier tests.

Covers the planning surface (dry-run / never-execute) — actually
starting bouncers requires the bouncer binaries on PATH and is
exercised in the smoke tests, not here.

Tests:
  * dry_run returns plan without executing (no subprocess)
  * when_X_present heuristics resolve correctly
  * declared-but-missing dependency surfaces a warning + skip
  * already-running bouncer NOT restarted (creates-never-mutates)
  * env_vars_to_set populated for the agent
  * disabled master switch → no-op
  * Phase B improve.enabled=true → warning
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from iam_jit.ambient_config import apply_declaration, plan_declaration


# ---------------------------------------------------------------------------
# Helper — ibounce can be invoked as either the native console script OR
# `python -m iam_jit.bouncer_cli` when the script isn't on PATH (common in
# dev / wheel-only installs). Per [[ibounce-honest-positioning]] both are
# valid execution methods; assertions about ibounce's planned command must
# accept either shape. See #569.
# ---------------------------------------------------------------------------


def _is_ibounce_command(command_parts: list[str]) -> bool:
    """True iff ``command_parts`` invokes ibounce via either the native
    console script (``ibounce …``) OR the python module fallback
    (``python -m iam_jit.bouncer_cli …``). Both are honest execution
    methods per [[ibounce-honest-positioning]]; tests must accept both
    so the suite is robust to whether the console-script is on PATH in
    the current dev environment.
    """
    joined = " ".join(command_parts).lower()
    return "ibounce" in joined or "iam_jit.bouncer_cli" in joined


# ---------------------------------------------------------------------------
# Helpers + fixtures
# ---------------------------------------------------------------------------


def _posture_with(running: dict[str, Any] | None = None) -> dict[str, Any]:
    """Minimal posture snapshot for tests. ``running`` maps
    posture-key (ibounce/kbounce/dbounce/gbounce) to its block."""
    blocks = {
        "ibounce": {"running": False, "port": 8767},
        "kbounce": {"running": False, "port": 8766},
        "dbounce": {"running": False, "port": 5433},
        "gbounce": {"running": False, "port": 8080},
    }
    if running:
        for k, v in running.items():
            blocks[k] = {**blocks[k], **v}
    return {
        "schema_version": "1.0",
        "overall_mode": "neither",
        "bouncers": blocks,
        "effective_protection": {},
        "iam_jit": {},
    }


# ---------------------------------------------------------------------------
# Core behaviors
# ---------------------------------------------------------------------------


def test_setup_dry_run_returns_plan_without_executing() -> None:
    """plan_declaration should plan + return a SetupResult with
    dry_run=True and never touch subprocess / audit channels."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    result = plan_declaration(
        declaration,
        posture=_posture_with(),
        env={},
    )
    assert result.dry_run is True
    assert result.status == "ok"
    assert result.bouncers_started == []  # nothing executed
    assert len(result.bouncers_planned) == 1
    assert result.bouncers_planned[0]["name"] == "ibounce"
    # #569: accept BOTH console-script (`ibounce …`) and python-module
    # fallback (`python -m iam_jit.bouncer_cli …`); both are valid
    # execution methods per [[ibounce-honest-positioning]].
    assert _is_ibounce_command(result.bouncers_planned[0]["command"]), (
        f"command is neither ibounce nor python -m iam_jit.bouncer_cli: "
        f"{result.bouncers_planned[0]['command']!r}"
    )
    # env-var advisory populated
    assert "AWS_ENDPOINT_URL" in result.env_vars_to_set
    assert "8767" in result.env_vars_to_set["AWS_ENDPOINT_URL"]


def test_setup_starts_disabled_bouncer_when_enabled_true_in_declaration() -> None:
    """When the declaration says ibounce=true + the posture shows it's
    not running, the planner SHOULD record a planned start (the
    execute=False path is the contract under test; the actual subprocess
    is covered in smoke tests).
    """
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    result = plan_declaration(
        declaration, posture=_posture_with(), env={}
    )
    assert any(r["name"] == "ibounce" for r in result.bouncers_planned)


def test_setup_resolves_when_kubeconfig_present_true(
    tmp_path,
) -> None:
    """when_kubeconfig_present should resolve True when KUBECONFIG
    points at an existing file."""
    kube = tmp_path / "kubeconfig"
    kube.write_text("apiVersion: v1\nkind: Config\n")
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "kbouncer": {"enabled": "when_kubeconfig_present"},
            },
        }
    }
    result = plan_declaration(
        declaration,
        posture=_posture_with(),
        env={"KUBECONFIG": str(kube)},
    )
    resolved = next(
        r for r in result.resolved_conditionals if r["bouncer"] == "kbouncer"
    )
    assert resolved["enabled_resolved"] is True
    assert "KUBECONFIG" in resolved["evidence"]


def test_setup_resolves_when_kubeconfig_present_false() -> None:
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "kbouncer": {"enabled": "when_kubeconfig_present"},
            },
        }
    }
    # Env with no KUBECONFIG + ~/.kube/config likely absent in CI
    result = plan_declaration(
        declaration,
        posture=_posture_with(),
        env={},
    )
    # We can't guarantee ~/.kube/config doesn't exist on dev machines;
    # if it does exist, the test instead asserts the evidence string
    # mentions it.
    resolved = next(
        r for r in result.resolved_conditionals if r["bouncer"] == "kbouncer"
    )
    if resolved["enabled_resolved"]:
        assert "~/.kube/config" in resolved["evidence"]
    else:
        assert "absent" in resolved["evidence"] or "no KUBECONFIG" in resolved["evidence"]


def test_setup_warns_when_bouncer_declared_but_dependency_missing(
    tmp_path,
) -> None:
    """when_kubeconfig_present + no KUBECONFIG => kbouncer skipped with
    a transparent reason (not silently dropped)."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "kbouncer": {"enabled": "when_kubeconfig_present"},
            },
        }
    }
    # Pass empty env + a HOME that doesn't have a .kube dir.
    result = plan_declaration(
        declaration,
        posture=_posture_with(),
        env={"HOME": str(tmp_path)},
    )
    # If the dev machine has ~/.kube/config, this test is a soft-no-op.
    # We only assert when the resolver returned False.
    resolved = next(
        r for r in result.resolved_conditionals if r["bouncer"] == "kbouncer"
    )
    if not resolved["enabled_resolved"]:
        skipped_names = [s["name"] for s in result.bouncers_skipped]
        assert "kbouncer" in skipped_names
        # Check the skip reason cites the conditional + the evidence.
        skip_record = next(
            s for s in result.bouncers_skipped if s["name"] == "kbouncer"
        )
        assert "when_kubeconfig_present" in skip_record["reason"]


def test_setup_emits_admin_action_audit_event() -> None:
    """When execute=True the emit hook is called (no-op outside the
    bouncer process; we just verify the planner records the audit
    intent in the result. Direct emit testing lives in
    tests/bouncer/test_audit_export_admin_action.py)."""
    # We can't actually execute (no ibounce binary in test env), so
    # assert the planner's audit-recording surface is correct in the
    # plan path: audit_event_ids stays [] in dry-run, which is the
    # tested invariant (we don't emit on dry-run).
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True}},
        }
    }
    result = plan_declaration(
        declaration, posture=_posture_with(), env={}
    )
    assert result.audit_event_ids == []  # dry-run never emits


def test_setup_does_not_overwrite_existing_profile_without_consent() -> None:
    """A bouncer already running with mode=cooperative + profile=foo
    should NOT be restarted when the declaration asks for mode=strict
    or profile=bar. The setup result records the conflict as a warning.
    """
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "bar",
                },
            },
        }
    }
    posture = _posture_with({
        "ibounce": {
            "running": True,
            "port": 8767,
            "mode": "cooperative",
            "active_profile": "foo",
        }
    })
    result = plan_declaration(declaration, posture=posture, env={})
    # Already-running tracked.
    assert "ibounce" in result.bouncers_already_running
    # Warning surfaces the conflict.
    joined = "\n".join(result.warnings)
    assert "creates-never-mutates" in joined.lower() or "already running" in joined.lower()
    assert "ibounce" in joined


def test_setup_returns_env_vars_for_agent_subprocess() -> None:
    """The result's env_vars_to_set must populate AWS_ENDPOINT_URL
    when ibounce is running (or planned)."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True},
                "kbouncer": {"enabled": False},
            },
        }
    }
    result = plan_declaration(declaration, posture=_posture_with(), env={})
    assert "AWS_ENDPOINT_URL" in result.env_vars_to_set
    assert "127.0.0.1" in result.env_vars_to_set["AWS_ENDPOINT_URL"]


def test_setup_disabled_master_switch() -> None:
    declaration = {"iam-jit": {"enabled": False}}
    result = plan_declaration(declaration, posture=_posture_with(), env={})
    assert result.status == "disabled"
    assert result.bouncers_started == []
    assert result.bouncers_planned == []


def test_setup_phase_b_improve_warning() -> None:
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True}},
            "improve": {"enabled": True, "cadence": "daily"},
        }
    }
    result = plan_declaration(declaration, posture=_posture_with(), env={})
    joined = "\n".join(result.warnings)
    assert "improve.enabled" in joined
    assert "Phase B" in joined or "#401" in joined


def test_setup_explicit_false_bouncer_not_planned() -> None:
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": False},
                "kbouncer": {"enabled": False},
            },
        }
    }
    result = plan_declaration(declaration, posture=_posture_with(), env={})
    # Nothing planned, nothing skipped (explicit false is a clean opt-out).
    assert result.bouncers_planned == []
    # No bouncer-skipped record either; the operator's explicit false
    # is not a heuristic to surface.
    skipped_names = [s["name"] for s in result.bouncers_skipped]
    assert "ibounce" not in skipped_names
    assert "kbouncer" not in skipped_names


def test_setup_db_env_resolution_true() -> None:
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "dbounce": {"enabled": "when_db_env_present"},
            },
        }
    }
    result = plan_declaration(
        declaration,
        posture=_posture_with(),
        env={"PGHOST": "127.0.0.1"},
    )
    resolved = next(
        r for r in result.resolved_conditionals if r["bouncer"] == "dbounce"
    )
    assert resolved["enabled_resolved"] is True
    assert "PGHOST" in resolved["evidence"]


def test_setup_proxy_env_resolution_true() -> None:
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "gbounce": {"enabled": "when_proxy_env_present"},
            },
        }
    }
    result = plan_declaration(
        declaration,
        posture=_posture_with(),
        env={"HTTPS_PROXY": "http://127.0.0.1:8080"},
    )
    resolved = next(
        r for r in result.resolved_conditionals if r["bouncer"] == "gbounce"
    )
    assert resolved["enabled_resolved"] is True


def test_setup_already_running_records_env_var() -> None:
    """Even when a bouncer is already running (no start), the env-var
    advisory should still be populated so the agent's subprocesses
    are routed correctly."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True}},
        }
    }
    posture = _posture_with(
        {"ibounce": {"running": True, "port": 8767, "mode": "discovery"}}
    )
    result = plan_declaration(declaration, posture=posture, env={})
    assert "AWS_ENDPOINT_URL" in result.env_vars_to_set


def test_setup_apply_declaration_is_idempotent_with_running_bouncer() -> None:
    """Calling apply_declaration twice in a row with a running bouncer
    should NOT introduce duplicate entries — the bouncer surface is
    stable."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True}},
        }
    }
    posture = _posture_with(
        {"ibounce": {"running": True, "port": 8767, "mode": "discovery"}}
    )
    result1 = plan_declaration(declaration, posture=posture, env={})
    result2 = plan_declaration(declaration, posture=posture, env={})
    assert result1.bouncers_already_running == result2.bouncers_already_running
    assert result1.env_vars_to_set == result2.env_vars_to_set


# ---------------------------------------------------------------------------
# #569 — state-verification tests for both ibounce execution shapes.
# Per CONTRIBUTING.md state-verification convention these assert observable
# state of the planned command list (not function return shape).
# ---------------------------------------------------------------------------


def test_setup_dry_run_accepts_console_script_form() -> None:
    """When `ibounce` is on PATH, the planned command uses the native
    console-script form (`ibounce run …`) and the result's friendly
    label says so. The `_is_ibounce_command` helper recognizes it.
    """
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    # Mock shutil.which to return a fake `ibounce` path. The module
    # under test calls shutil.which directly via _find_binary, so patch
    # the import site.
    with patch(
        "iam_jit.ambient_config.setup.shutil.which",
        return_value="/usr/local/bin/ibounce",
    ):
        result = plan_declaration(
            declaration, posture=_posture_with(), env={}
        )
    assert len(result.bouncers_planned) == 1
    record = result.bouncers_planned[0]
    cmd = record["command"]
    # Native console-script form: first arg is the `ibounce` binary path.
    assert cmd[0] == "/usr/local/bin/ibounce", (
        f"expected console-script form; got command={cmd!r}"
    )
    assert "iam_jit.bouncer_cli" not in " ".join(cmd), (
        f"console-script form should not include python module; got {cmd!r}"
    )
    # Helper accepts the shape.
    assert _is_ibounce_command(cmd)
    # Friendly label + resolution attribute the path honestly.
    assert record["binary_resolution"] == "console_script"
    assert record["dry_run_command_friendly_label"] == "ibounce"


def test_setup_dry_run_accepts_python_module_form() -> None:
    """When `ibounce` is NOT on PATH, _find_binary falls back to
    `python -m iam_jit.bouncer_cli` and the resulting planned command
    must still be recognized as a valid ibounce invocation. This is the
    pre-existing #569 fix that closes the original assertion gap.
    """
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    with patch(
        "iam_jit.ambient_config.setup.shutil.which",
        return_value=None,
    ):
        result = plan_declaration(
            declaration, posture=_posture_with(), env={}
        )
    assert len(result.bouncers_planned) == 1
    record = result.bouncers_planned[0]
    cmd = record["command"]
    # Python module form: contains `-m` + `iam_jit.bouncer_cli`.
    assert "-m" in cmd, f"expected python -m form; got command={cmd!r}"
    assert "iam_jit.bouncer_cli" in cmd, (
        f"expected iam_jit.bouncer_cli module; got command={cmd!r}"
    )
    # Helper accepts the shape.
    assert _is_ibounce_command(cmd)
    # Friendly label + resolution attribute the fallback honestly per
    # [[ibounce-honest-positioning]].
    assert record["binary_resolution"] == "python_module_fallback"
    assert "via python -m" in record["dry_run_command_friendly_label"]
    # The bouncer was NOT skipped — fallback is a valid execution method.
    assert record["skipped"] is False


def test_setup_dry_run_helper_accepts_both_shapes() -> None:
    """Direct unit test for the test-local `_is_ibounce_command` helper.
    Both honest execution shapes must be recognized; unrelated commands
    must not.
    """
    # Native console-script forms.
    assert _is_ibounce_command(["ibounce", "run", "--port", "8767"])
    assert _is_ibounce_command(["/usr/local/bin/ibounce", "run"])
    # Python module fallback forms (with various python interpreter paths).
    assert _is_ibounce_command(
        ["/usr/bin/python3", "-m", "iam_jit.bouncer_cli", "run"]
    )
    assert _is_ibounce_command(
        ["/Users/dev/.venv/bin/python3.12", "-m", "iam_jit.bouncer_cli",
         "run", "--port", "8767"]
    )
    # Negative cases: unrelated commands must not match.
    assert not _is_ibounce_command(["kbouncer", "run"])
    assert not _is_ibounce_command(["python", "-c", "print(1)"])
    assert not _is_ibounce_command(["dbounce", "run", "--port", "5433"])
    assert not _is_ibounce_command([])
