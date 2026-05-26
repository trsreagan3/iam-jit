"""State-verification tests for #626 Phase 3 — `iam-jit shellinit`.

`iam-jit shellinit` emits a paste-ready shell-export block for the
bouncers that are currently running. The `iam-jit doctor install-check`
FAIL rows point operators at this command (and at
`eval "$(iam-jit shellinit)"`), so the two must stay in lockstep.

Tests cover:
  1. Bash output contains AWS_ENDPOINT_URL export when ibounce running.
  2. Fish output uses `set -x` syntax.
  3. PowerShell output uses `$Env:` syntax.
  4. No bouncers running -> comment-only output (eval is safe no-op).
  5. Misconfigured bouncer -> commented misconfig line, no export.
  6. --shell flag overrides $SHELL auto-detection.
  7. Sabotage: monkeypatch render_shellinit to always emit a fake
     export; assert the no-bouncer case now wrongly contains a real
     export — proves the snapshot-driven probe is load-bearing.

UAT #13 gap-closers (3 new tests appended):
  8. Fish shell comment header uses fish syntax (eval (iam-jit shellinit)).
  9. Bash shell comment header uses bash syntax (eval "$(iam-jit shellinit)").
  10. PowerShell comment header uses pipe-to-IEX syntax.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from click.testing import CliRunner

from iam_jit import cli_shellinit as si
from iam_jit.cli import main


@pytest.fixture(autouse=True)
def _pinned_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(home / ".iam-jit"))


@pytest.fixture(autouse=True)
def _cleared_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "AWS_ENDPOINT_URL", "KUBECONFIG", "PGHOST", "PGPORT",
        "HTTP_PROXY", "HTTPS_PROXY",
    ):
        monkeypatch.delenv(var, raising=False)


def _no_bouncers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "iam_jit.posture.bouncers._loopback_port_open",
        lambda *a, **kw: False,
    )


def _only_ibounce(monkeypatch: pytest.MonkeyPatch) -> None:
    def _probe(port: int, host: str = "127.0.0.1", **kw: Any) -> bool:
        return port == 8767
    monkeypatch.setattr(
        "iam_jit.posture.bouncers._loopback_port_open", _probe,
    )


def _invoke(*extra: str) -> Any:
    return CliRunner().invoke(
        main, ["shellinit", *extra], catch_exceptions=False,
    )


# ---------------------------------------------------------------------------
# Test 1 — bash output contains AWS_ENDPOINT_URL export when running
# ---------------------------------------------------------------------------


def test_bash_output_exports_aws_endpoint_url_when_ibounce_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _only_ibounce(monkeypatch)
    result = _invoke("--shell", "bash")
    assert result.exit_code == 0, result.output
    # Header comment present.
    assert "# iam-jit shellinit" in result.output
    # Export uses bash syntax + correct URL.
    assert "export AWS_ENDPOINT_URL='http://127.0.0.1:8767'" in result.output
    # Other bouncers commented-out (not running).
    assert "(no KUBECONFIG export — kbounce not running)" in result.output
    assert "(no PG* exports — dbounce not running)" in result.output
    assert "(no HTTP_PROXY export — gbounce not running)" in result.output


# ---------------------------------------------------------------------------
# Test 2 — fish syntax
# ---------------------------------------------------------------------------


def test_fish_output_uses_set_x_syntax(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _only_ibounce(monkeypatch)
    result = _invoke("--shell", "fish")
    assert result.exit_code == 0
    assert "set -x AWS_ENDPOINT_URL 'http://127.0.0.1:8767'" in result.output
    # No bash-style export STATEMENTS (substring check would match
    # the comment string "export"; require line-start form).
    for line in result.output.splitlines():
        assert not line.startswith("export "), (
            f"fish output should not contain bash export lines: {line!r}"
        )


# ---------------------------------------------------------------------------
# Test 3 — powershell syntax
# ---------------------------------------------------------------------------


def test_powershell_output_uses_env_syntax(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _only_ibounce(monkeypatch)
    result = _invoke("--shell", "powershell")
    assert result.exit_code == 0
    assert "$Env:AWS_ENDPOINT_URL = 'http://127.0.0.1:8767'" in result.output


# ---------------------------------------------------------------------------
# Test 4 — no bouncers -> comment-only output (eval is safe no-op)
# ---------------------------------------------------------------------------


def test_no_bouncers_emits_only_comments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_bouncers(monkeypatch)
    result = _invoke("--shell", "bash")
    assert result.exit_code == 0
    # NO export STATEMENTS (line-start form — comments may contain
    # the word "export").
    for line in result.output.splitlines():
        assert not line.startswith("export "), (
            f"no-bouncer output should not contain export lines: {line!r}"
        )
    # Detected-not-running line present (proves snapshot drove output).
    assert "Detected NOT running: ibounce, kbounce, dbounce, gbounce" in result.output
    # Header comment present.
    assert "# iam-jit shellinit" in result.output


# ---------------------------------------------------------------------------
# Test 5 — misconfigured bouncer commented, not exported
# ---------------------------------------------------------------------------


def test_misconfigured_bouncer_is_commented_not_exported() -> None:
    snapshot = {
        "bouncers": {
            "ibounce": {
                "running": True,
                "port": 8767,
                "misconfig": "AWS_ENDPOINT_URL points at :9999 not :8767",
            },
            "kbounce": {"running": False},
            "dbounce": {"running": False},
            "gbounce": {"running": False},
        }
    }
    out = si.render_shellinit(snapshot, shell="bash")
    # No export line for the misconfigured bouncer.
    assert "export AWS_ENDPOINT_URL" not in out
    # Misconfig is surfaced as a comment so eval won't break.
    assert "# ibounce MISCONFIG:" in out


# ---------------------------------------------------------------------------
# Test 6 — --shell flag overrides $SHELL auto-detection
# ---------------------------------------------------------------------------


def test_shell_flag_overrides_env_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _only_ibounce(monkeypatch)
    monkeypatch.setenv("SHELL", "/bin/bash")  # auto would pick bash
    result = _invoke("--shell", "fish")  # explicit override
    assert "set -x AWS_ENDPOINT_URL" in result.output
    # No bash-style export line at column 0.
    for line in result.output.splitlines():
        assert not line.startswith("export AWS_ENDPOINT_URL")


# ---------------------------------------------------------------------------
# Test 7 — SABOTAGE: prove render_shellinit's snapshot-driven probe
# is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_render_shellinit_proves_snapshot_drives_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If we monkeypatch render_shellinit to always emit a hardcoded
    AWS_ENDPOINT_URL export, the no-bouncer case suddenly contains a
    bogus export. This proves the real snapshot-driven render IS
    load-bearing per CONTRIBUTING.md anti-theater guidance.
    """
    _no_bouncers(monkeypatch)

    def _fake_render(snap: dict, *, shell: str, **_kw: object) -> str:  # noqa: ARG001
        return "export AWS_ENDPOINT_URL='http://example.invalid'\n"
    monkeypatch.setattr(si, "render_shellinit", _fake_render)

    result = _invoke("--shell", "bash")
    # Without the real render, the bogus export is present despite
    # no bouncers running — proving render_shellinit is load-bearing.
    assert "http://example.invalid" in result.output


# ---------------------------------------------------------------------------
# UAT #13 gap-closer tests 8-10 — shell-specific comment header syntax
# ---------------------------------------------------------------------------


def test_fish_shell_header_uses_fish_eval_syntax(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fish shell comment header must use `eval (iam-jit shellinit)`
    (no dollar-paren) — bash syntax doesn't work in fish."""
    _no_bouncers(monkeypatch)
    result = _invoke("--shell", "fish")
    assert result.exit_code == 0, result.output

    # Fish eval form must be present.
    assert "eval (iam-jit shellinit)" in result.output
    # Bash dollar-paren form must NOT appear.
    assert 'eval "$(iam-jit shellinit)"' not in result.output
    assert "eval $(iam-jit shellinit)" not in result.output


def test_bash_shell_header_uses_bash_eval_syntax(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bash shell comment header must use `eval "$(iam-jit shellinit)"`
    (dollar-paren form); fish syntax must not appear."""
    _no_bouncers(monkeypatch)
    result = _invoke("--shell", "bash")
    assert result.exit_code == 0, result.output

    # Bash eval form must be present.
    assert 'eval "$(iam-jit shellinit)"' in result.output
    # Fish eval form (no dollar) must not appear.
    assert "eval (iam-jit shellinit)" not in result.output


def test_powershell_shell_header_uses_invoke_expression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PowerShell comment header must use
    `iam-jit shellinit | Invoke-Expression` — not bash or fish syntax."""
    _no_bouncers(monkeypatch)
    result = _invoke("--shell", "powershell")
    assert result.exit_code == 0, result.output

    assert "Invoke-Expression" in result.output
    # Neither bash nor fish eval form should appear.
    assert 'eval "$(iam-jit shellinit)"' not in result.output
    assert "eval (iam-jit shellinit)" not in result.output
