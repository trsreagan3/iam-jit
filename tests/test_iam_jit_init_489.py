"""State-verification tests for #489 + #532 CRIT (§A89 launch-blocker,
UC-30 canonical onboarding) — `iam-jit init` interactive bootstrap
interview.

Per [[tests-and-independent-uat-required]] every feature ships with
tests + an independent UAT pass. Per CONTRIBUTING.md every reported
success status MUST also assert observable state matches.

Tests cover:

  1. Non-interactive (no TTY): defaults applied; config file written;
     decisions logged to stdout; default values land in YAML.
  2. ``--dry-run``: config preview printed; NO file written.
  3. Flag-driven non-interactive (``--shape canary --mode cooperative
     --bouncers ibounce,gbounce``): config matches the passed flags.
  4. Interactive (``CliRunner.invoke(..., input=...)``): walks prompts;
     writes expected config.
  5. Pre-existing config: refuses to clobber per
     [[creates-never-mutates]] absent ``--overwrite``.
  6. ``--data-dir`` honored — writes to that path, not ``~/.iam-jit/``.
  7. Sabotage check: monkeypatched ``_build_config`` returning ``{}``
     causes init to REFUSE the write (proves validation is load-bearing
     per CONTRIBUTING.md anti-pattern guidance).

UAT #13 gap-closers (5 new tests appended below existing suite):
  10. IAM_JIT_DATA_DIR env var honored by `iam-jit init --data-dir`.
  11. --data-dir flag wins over $IAM_JIT_DATA_DIR env var.
  12. Next steps block includes shellinit when a bouncer is detected running.
  13. Next steps block omits shellinit when no bouncers are detected.
  14. --no-doctor-check emits stderr warning per [[ibounce-honest-positioning]].
  15. Generated YAML "Apply with" comment uses resolved --data-dir path.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml
from click.testing import CliRunner

from iam_jit import cli as cli_module
from iam_jit import cli_init
from iam_jit.cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent boto3 STS lookups during account detection + accounts
    seeding (the latter is reused from local_server)."""
    def _boom(*a, **k):  # noqa: ANN001, ARG001
        raise RuntimeError("no aws creds in tests")
    monkeypatch.setattr("boto3.client", _boom)


@pytest.fixture(autouse=True)
def _no_home_pollution(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin HOME to tmp_path so any code that reads `pathlib.Path.home()`
    (harness detection, default data dir) can't escape the sandbox."""
    monkeypatch.setenv("HOME", str(tmp_path / "fake-home"))
    (tmp_path / "fake-home").mkdir(parents=True, exist_ok=True)


@pytest.fixture
def isolated_data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Per-test data dir under tmp_path; NOT pre-created so tests can
    assert what `init` does to a fresh location."""
    return tmp_path / "iam-jit"


def _runner() -> CliRunner:
    return CliRunner()


def _read_config_yaml(path: pathlib.Path) -> dict:
    """Read + parse the rendered iam-jit.yaml. Strips header comments
    via PyYAML's safe_load (which already ignores them)."""
    return yaml.safe_load(path.read_text())


# ---------------------------------------------------------------------------
# Test 1 — non-interactive defaults
# ---------------------------------------------------------------------------


def test_non_interactive_defaults_write_config_with_expected_shape(
    isolated_data_dir: pathlib.Path,
) -> None:
    """Bare `iam-jit init --non-interactive --data-dir ...` lands the
    documented defaults (shape=local-solo / mode=discovery / bouncers=
    [ibounce] / harness=none) into the config file. Decisions are
    logged so an agent can audit them."""
    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    assert result.exit_code == 0, result.output

    # Decisions are surfaced to stdout for non-TTY callers.
    assert "[init] shape: local-solo" in result.output
    assert "[init] mode: discovery" in result.output
    assert "[init] bouncers: ibounce" in result.output
    assert "[init] harness_detected: none" in result.output

    # Observable filesystem state matches the claim.
    config_path = isolated_data_dir / "iam-jit.yaml"
    assert config_path.exists()

    body = _read_config_yaml(config_path)
    assert body["iam-jit"]["enabled"] is True
    assert body["iam-jit"]["schema_version"] == "1.0"
    assert body["iam-jit"]["posture"] == "ambient"
    assert "ibounce" in body["iam-jit"]["bouncers"]
    assert body["iam-jit"]["bouncers"]["ibounce"]["enabled"] is True
    assert body["iam-jit"]["bouncers"]["ibounce"]["mode"] == "discovery"
    # Only one bouncer by default.
    assert list(body["iam-jit"]["bouncers"].keys()) == ["ibounce"]


# ---------------------------------------------------------------------------
# Test 2 — --dry-run does NOT write
# ---------------------------------------------------------------------------


def test_dry_run_prints_config_and_does_not_write(
    isolated_data_dir: pathlib.Path,
) -> None:
    """--dry-run must print the rendered YAML but leave the filesystem
    untouched. Per [[creates-never-mutates]] a dry-run is always safe."""
    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive", "--dry-run",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    assert result.exit_code == 0, result.output

    # Output contains the YAML body so the operator (or agent) can
    # inspect what would be written.
    assert "iam-jit:" in result.output
    assert "(dry-run; would write to" in result.output

    # Observable state: nothing on disk.
    assert not (isolated_data_dir / "iam-jit.yaml").exists()
    # The data dir itself was not created either (we never touched it).
    assert not isolated_data_dir.exists()


# ---------------------------------------------------------------------------
# Test 3 — flag-driven non-interactive matches passed flags
# ---------------------------------------------------------------------------


def test_flag_driven_non_interactive_matches_passed_choices(
    isolated_data_dir: pathlib.Path,
) -> None:
    """Per-step flags bypass each prompt while accepting defaults for
    the rest. The written config MUST reflect the passed flags."""
    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
            "--shape", "canary",
            "--mode", "cooperative",
            "--bouncers", "ibounce,gbounce",
        ],
    )
    assert result.exit_code == 0, result.output

    body = _read_config_yaml(isolated_data_dir / "iam-jit.yaml")
    bouncers = body["iam-jit"]["bouncers"]
    assert set(bouncers.keys()) == {"ibounce", "gbounce"}
    for name in ("ibounce", "gbounce"):
        assert bouncers[name]["enabled"] is True
        assert bouncers[name]["mode"] == "cooperative"
    # canary is non-corp-managed, so posture stays ambient.
    assert body["iam-jit"]["posture"] == "ambient"


def test_corp_managed_shape_sets_managed_posture(
    isolated_data_dir: pathlib.Path,
) -> None:
    """The corp-managed shape switches posture to managed (pin every
    profile + forbid auto-improve) per the ambient_config schema."""
    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
            "--shape", "corp-managed",
        ],
    )
    assert result.exit_code == 0, result.output
    body = _read_config_yaml(isolated_data_dir / "iam-jit.yaml")
    assert body["iam-jit"]["posture"] == "managed"


# ---------------------------------------------------------------------------
# Test 4 — interactive flow via CliRunner input
# ---------------------------------------------------------------------------


def test_interactive_flow_walks_prompts_and_writes_expected_config(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate an interactive session: pick multi-user shape + all
    bouncers + strict mode + decline doctor apply. The rendered YAML
    must reflect every operator choice."""
    # CliRunner.invoke with `input=` feeds stdin; we also force the
    # is-tty check to True so the prompts actually run.
    monkeypatch.setattr(
        cli_init, "_is_interactive", lambda non_interactive_flag: True,
    )

    # Stdin sequence (one prompt at a time):
    #   shape: multi-user
    #   bouncer set: all
    #   mode: strict
    #   doctor apply confirm: n (decline)
    stdin = "multi-user\nall\nstrict\nn\n"
    result = _runner().invoke(
        main,
        [
            "init",
            "--data-dir", str(isolated_data_dir),
            "--harness", "none",  # bypass harness detect for determinism
        ],
        input=stdin,
    )
    assert result.exit_code == 0, result.output

    body = _read_config_yaml(isolated_data_dir / "iam-jit.yaml")
    assert body["iam-jit"]["posture"] == "ambient"  # not corp-managed
    bouncers = body["iam-jit"]["bouncers"]
    assert set(bouncers.keys()) == {"ibounce", "kbouncer", "dbounce", "gbounce"}
    for name, block in bouncers.items():
        assert block["enabled"] is True, name
        assert block["mode"] == "strict", name


# ---------------------------------------------------------------------------
# Test 5 — pre-existing config refused absent --overwrite
# ---------------------------------------------------------------------------


def test_preexisting_config_is_refused_without_overwrite(
    isolated_data_dir: pathlib.Path,
) -> None:
    """Re-running `iam-jit init` against an already-populated config
    file MUST refuse + exit non-zero per [[creates-never-mutates]]. The
    pre-existing file content is NOT touched."""
    isolated_data_dir.mkdir(parents=True)
    sentinel = "# OPERATOR EDIT — must not be clobbered by init\n"
    config_path = isolated_data_dir / "iam-jit.yaml"
    config_path.write_text(sentinel)

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    assert result.exit_code != 0
    assert "refusing to overwrite" in result.output

    # Observable state: file content unchanged.
    assert config_path.read_text() == sentinel


def test_preexisting_config_overwrite_flag_clobbers(
    isolated_data_dir: pathlib.Path,
) -> None:
    """With --overwrite the file IS replaced (operator opted in
    explicitly). The new file is a valid declaration."""
    isolated_data_dir.mkdir(parents=True)
    config_path = isolated_data_dir / "iam-jit.yaml"
    config_path.write_text("# stale\n")

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive", "--overwrite",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    assert result.exit_code == 0, result.output

    body = _read_config_yaml(config_path)
    assert body["iam-jit"]["enabled"] is True
    assert "ibounce" in body["iam-jit"]["bouncers"]


# ---------------------------------------------------------------------------
# Test 6 — --data-dir honored
# ---------------------------------------------------------------------------


def test_data_dir_flag_routes_config_to_that_path(
    tmp_path: pathlib.Path,
) -> None:
    """--data-dir /tmp/xxx writes to that path, not ~/.iam-jit/.
    Verifies the default-home-dir fallback only fires when the flag
    is absent."""
    custom = tmp_path / "elsewhere" / "iam-jit-data"
    result = _runner().invoke(
        main,
        ["init", "--non-interactive", "--data-dir", str(custom)],
    )
    assert result.exit_code == 0, result.output

    # Observable state: config landed at the explicit path.
    expected = custom / "iam-jit.yaml"
    assert expected.exists()

    # Default data dir under fake-HOME was NOT touched.
    default_path = pathlib.Path.home() / ".iam-jit" / "iam-jit.yaml"
    assert not default_path.exists()


# ---------------------------------------------------------------------------
# Test 7 — Sabotage: empty _build_config refuses write
# ---------------------------------------------------------------------------


def test_sabotage_empty_build_config_refuses_write(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per CONTRIBUTING.md state-verification: every success claim
    needs an observable check. If `_build_config` returned an empty
    dict (e.g. a refactor regression), init MUST refuse the write so
    we don't produce a config file the doctor-apply chokes on later.

    This is the load-bearing validation the test exercises — if the
    guard is removed, this test fails LOUDLY at PR time per
    [[ibounce-honest-positioning]]."""
    monkeypatch.setattr(cli_init, "_build_config", lambda **kwargs: {})

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    # ClickException exits 1 by default.
    assert result.exit_code != 0
    assert "init refused to write" in result.output

    # Observable: no config file landed.
    assert not (isolated_data_dir / "iam-jit.yaml").exists()


def test_sabotage_missing_iam_jit_block_refuses_write(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Companion to the empty-dict sabotage: if `_build_config`
    returns a dict that's missing the `iam-jit.enabled` block (which
    the ambient_config schema requires), init MUST refuse rather than
    write a config the schema rejects."""
    monkeypatch.setattr(
        cli_init, "_build_config",
        lambda **kwargs: {"iam-jit": {"enabled": False}},
    )

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    assert result.exit_code != 0
    assert "init refused to write" in result.output
    assert not (isolated_data_dir / "iam-jit.yaml").exists()


# ---------------------------------------------------------------------------
# Test 8 — Generated config validates against the ambient_config schema
# ---------------------------------------------------------------------------


def test_generated_config_passes_ambient_config_validation(
    isolated_data_dir: pathlib.Path,
) -> None:
    """Cross-product parity: the config `init` writes MUST be loadable
    by `ambient_config.load_declaration` (the same loader
    `iam-jit doctor apply-config` uses). Without this guarantee the
    summary's "next step: doctor apply-config" hint would 500 on the
    very next operator command."""
    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    assert result.exit_code == 0, result.output

    # Use the production loader (not a duplicate validator) so this
    # test stays in sync with whatever schema changes ship.
    from iam_jit.ambient_config import load_declaration
    config_path = isolated_data_dir / "iam-jit.yaml"
    declaration, source = load_declaration(config_path)
    assert source == str(config_path)
    assert declaration["iam-jit"]["enabled"] is True
    assert "ibounce" in declaration["iam-jit"]["bouncers"]


# ---------------------------------------------------------------------------
# Test 9 — Cross-flag combo: invalid bouncer name rejected
# ---------------------------------------------------------------------------


def test_invalid_bouncer_name_rejected_with_actionable_error(
    isolated_data_dir: pathlib.Path,
) -> None:
    """A typo'd bouncer must fail-CLOSED with the valid set listed —
    not silently produce a degenerate config. Per [[ibounce-honest-
    positioning]]."""
    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive",
            "--data-dir", str(isolated_data_dir),
            "--bouncers", "ibounce,not-a-real-bouncer",
        ],
    )
    assert result.exit_code != 0
    # Click's BadParameter surfaces the valid set + the bad name.
    assert "not-a-real-bouncer" in result.output
    assert "ibounce" in result.output  # the valid-set hint

    # Observable: nothing landed.
    assert not (isolated_data_dir / "iam-jit.yaml").exists()


# ---------------------------------------------------------------------------
# UAT #13 gap-closer tests (tests 10-15)
# ---------------------------------------------------------------------------


def test_iam_jit_data_dir_env_var_honored(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM_JIT_DATA_DIR env var must route the config to that path —
    was silently ignored before (HIGH gap, [[cross-product-agent-parity]]
    with serve + uninstall which already honor it)."""
    custom = tmp_path / "env-driven-dir"
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(custom))

    result = _runner().invoke(
        main,
        ["init", "--non-interactive", "--no-doctor-check"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    # Config must be at the env-var-specified path.
    expected = custom / "iam-jit.yaml"
    assert expected.exists(), (
        f"Expected {expected} to exist; IAM_JIT_DATA_DIR was not honored"
    )
    # Default ~/.iam-jit path must NOT have been written.
    default_path = pathlib.Path.home() / ".iam-jit" / "iam-jit.yaml"
    assert not default_path.exists()


def test_data_dir_flag_wins_over_env_var(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When both $IAM_JIT_DATA_DIR and --data-dir are set, the explicit
    --data-dir flag must win (Click envvar= precedence)."""
    env_dir = tmp_path / "env-dir"
    flag_dir = tmp_path / "flag-dir"
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(env_dir))

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive", "--no-doctor-check",
            "--data-dir", str(flag_dir),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    # Flag-dir wins.
    assert (flag_dir / "iam-jit.yaml").exists()
    # Env-dir was NOT touched.
    assert not (env_dir / "iam-jit.yaml").exists()


def test_next_steps_includes_shellinit_when_bouncer_running(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When at least one bouncer is detected running, the Next steps
    block must include `eval "$(iam-jit shellinit)"` as the first
    action per [[ibounce-honest-positioning]]."""
    # Monkeypatch posture detection to report ibounce as running.
    monkeypatch.setattr(
        "iam_jit.cli_init._any_bouncer_running",
        lambda: True,
    )

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive", "--no-doctor-check",
            "--data-dir", str(isolated_data_dir),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    # shellinit must appear in Next steps.
    assert "shellinit" in result.output
    assert "eval" in result.output

    # It must appear BEFORE "Apply the config" (i.e. as the first step).
    shellinit_pos = result.output.find("shellinit")
    apply_pos = result.output.find("Apply the config")
    assert shellinit_pos < apply_pos, (
        "shellinit hint must be the FIRST next-step, before 'Apply the config'"
    )


def test_next_steps_omits_shellinit_when_no_bouncers_running(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no bouncers are running, the Next steps block must NOT
    include a shellinit line (no-op wiring would mislead the operator)."""
    monkeypatch.setattr(
        "iam_jit.cli_init._any_bouncer_running",
        lambda: False,
    )

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive", "--no-doctor-check",
            "--data-dir", str(isolated_data_dir),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    # Check only the Next steps block (after the summary header).
    next_steps_pos = result.output.find("Next steps:")
    assert next_steps_pos != -1
    next_steps_block = result.output[next_steps_pos:]
    assert "shellinit" not in next_steps_block


def test_no_doctor_check_emits_stderr_warning(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--no-doctor-check must emit a visible warning so operators who
    passed the flag know they opted out of verification. Per
    [[ibounce-honest-positioning]] opt-outs must be visible.

    CliRunner merges stderr into result.output; assert the warning
    text appears in the combined stream. The implementation writes to
    sys.stderr so it reaches the operator's terminal even in piped usage.
    """
    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive", "--no-doctor-check",
            "--data-dir", str(isolated_data_dir),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    # CliRunner merges stderr into output. The warning must be visible.
    combined = result.output
    assert "[warn]" in combined, (
        f"Expected [warn] warning in output; got:\n{combined}"
    )
    assert "install-check suppressed" in combined
    assert "iam-jit doctor install-check" in combined


def test_yaml_comment_uses_resolved_config_path(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 'Apply with' comment in the generated YAML must reference the
    resolved --data-dir path, NOT the hardcoded ~/.iam-jit/ fallback.
    Operators using custom paths were seeing wrong paths in the comment."""
    custom_dir = tmp_path / "custom-data"
    expected_config = custom_dir / "iam-jit.yaml"

    result = _runner().invoke(
        main,
        [
            "init", "--non-interactive", "--no-doctor-check",
            "--data-dir", str(custom_dir),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert expected_config.exists()

    raw = expected_config.read_text()
    # The "Apply with" comment must reference the custom path.
    assert str(expected_config) in raw, (
        f"Expected 'Apply with' comment to reference {expected_config}; "
        f"got:\n{raw[:500]}"
    )
    # Must NOT reference the hardcoded default path.
    assert "~/.iam-jit/iam-jit.yaml" not in raw
