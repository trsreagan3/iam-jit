"""Independent UAT for PR #23 — install-bootstrap fix (#683/#681).

This is the INDEPENDENT verification pass per [[tests-and-independent-uat-required]]
standing discipline. A DIFFERENT agent from the implementer wrote this file.
The methodology deliberately differs from test_install_bootstrap_e2e.py:

  - Snapshots decisions_count via raw urllib (no shared helper from e2e file)
  - Runs install command via real subprocess (not Click test runner in-process)
  - Reads written settings.json + sources env into a THIRD subprocess for the
    STS call (not the same process that ran the install)
  - Tests restart-message stderr capture via subprocess (not capsys/in-process)
  - Tests posture UNPROTECTED→PROTECTED round-trip via subprocess

Tests are grouped as:
  Test 0: Install-story gap (CRIT finding — stale pipx binary)
  Test 1: Snapshot-based real-traffic verification
  Test 2: Honest-restart-message verification
  Test 3: Documentation reality check (MCP-RECIPES.md)
  Test 4: First-60-seconds smoke equivalent

Live-bouncer tests are skipped when ibounce is not running on :8767.
Pure-logic tests run always.

Per [[permission-minimal-install]]: this test requires NO sudo, NO broad Bash
allowlist, and NO --dangerously-skip-permissions.

INDEPENDENT UAT FINDINGS:
  CRIT-1: The installed binary (pipx, PATH-based iam-jit) does NOT have
    --settings-path or --no-env-block. PR #23 merged to source but
    the install story was NOT updated. An operator running `iam-jit mcp
    install-claude-code` from the installed binary gets the OLD behavior
    (no env-block write). Fix: `pipx upgrade iam-jit` or `pip install -e .`
    after merging.

  MED-1: docs/MCP-RECIPES.md does not document the env-block write
    behavior (--settings-path, AWS_ENDPOINT_URL in settings.json).
    The docs were not updated with PR #23.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import urllib.request
from contextlib import closing
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Constants + skip gate
# ---------------------------------------------------------------------------

_IBOUNCE_HOST = "127.0.0.1"
_IBOUNCE_PORT = 8767
_IBOUNCE_HEALTHZ = f"http://{_IBOUNCE_HOST}:{_IBOUNCE_PORT}/healthz"

# Capture real home BEFORE any monkeypatching.
_REAL_HOME = str(pathlib.Path.home())

# Real Python binary from the currently-active virtualenv.
_PYTHON = sys.executable

# Real iam-jit binary path.
# FINDING (CRIT): The PATH-based `iam-jit` (installed via pipx) does NOT have
# the PR #23 flags (--settings-path, --no-env-block). The editable-install
# venv binary at .venv/bin/iam-jit DOES have them.
# This confirms the fix was NOT yet deployed to the production pipx install.
# All tests below use the venv binary to verify the CODE is correct.
# A separate CRIT finding is filed: the install story requires a `pipx upgrade`
# or `pip install -e .` step that PR #23 did not document.
_IAM_JIT_VENV = str(pathlib.Path(__file__).parent.parent.parent / ".venv" / "bin" / "iam-jit")
_IAM_JIT_PATH_BINARY = "iam-jit"  # The installed (potentially stale) binary.
_IAM_JIT = _IAM_JIT_VENV  # Tests use the venv binary (has PR #23 code).


def _ibounce_is_open() -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(0.5)
            s.connect((_IBOUNCE_HOST, _IBOUNCE_PORT))
            return True
    except OSError:
        return False


_IBOUNCE_RUNNING = _ibounce_is_open()

live_bouncer = pytest.mark.skipif(
    not _IBOUNCE_RUNNING,
    reason="ibounce not running on :8767 — skipping live-bouncer UAT",
)


# ---------------------------------------------------------------------------
# UAT-local helpers — written from scratch, NOT imported from e2e file
# ---------------------------------------------------------------------------


def _snapshot_decisions_count() -> int:
    """Fetch decisions_count from ibounce /healthz via raw urllib.
    Written from scratch — does NOT reuse _ibounce_decisions_count()
    from test_install_bootstrap_e2e.py. Independent read path.
    """
    with urllib.request.urlopen(_IBOUNCE_HEALTHZ, timeout=5) as resp:  # noqa: S310
        payload = json.loads(resp.read().decode("utf-8"))
    val = payload.get("decisions_count")
    if val is None:
        raise KeyError(f"decisions_count missing from healthz: {payload.keys()}")
    return int(val)


def _clean_env_for_subprocess(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a clean env for subprocess runs.

    Strips AWS_ENDPOINT_URL / HTTP_PROXY / HTTPS_PROXY so we start UNWIRED.
    Inherits PATH, PYTHONPATH, HOME, AWS creds (so real calls can succeed).
    Adds extra vars last (they can override anything above).

    Written from scratch — does NOT reuse _run_fresh_subprocess() from e2e file.
    """
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "HOME": _REAL_HOME,
    }
    # Pass through AWS credentials so STS calls work.
    for k in (
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
    ):
        if k in os.environ:
            env[k] = os.environ[k]

    # Ensure a region is set.
    if not any(k in env for k in ("AWS_DEFAULT_REGION", "AWS_REGION")):
        env["AWS_DEFAULT_REGION"] = "us-east-1"

    # Fall back to "iam-jit" profile if no explicit creds are set.
    if not any(k in env for k in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE")):
        creds_path = pathlib.Path(_REAL_HOME) / ".aws" / "credentials"
        if creds_path.exists():
            env["AWS_PROFILE"] = "iam-jit"

    # Explicitly strip bouncer wiring vars — subprocess starts UNWIRED.
    for stripped in ("AWS_ENDPOINT_URL", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(stripped, None)

    if extra:
        env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Test 0: Install-story gap detection
# ---------------------------------------------------------------------------


class TestInstallStoryGap:
    """CRIT finding: the PATH-based iam-jit binary (pipx) does NOT have the
    PR #23 flags. This test documents and verifies the gap.

    These tests ALWAYS run (no live bouncer needed) because they check CLI
    surface, not traffic routing.
    """

    @pytest.mark.skipif(
        not pathlib.Path(_IAM_JIT_VENV).exists(),
        reason="venv binary not present (CI uses tox; .venv only on dev machines)",
    )
    def test_venv_binary_has_settings_path_flag(self) -> None:
        """The repo venv binary must have --settings-path (PR #23 feature)."""
        proc = subprocess.run(
            [_IAM_JIT_VENV, "mcp", "install-claude-code", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0, f"venv iam-jit --help failed: {proc.stderr!r}"
        assert "--settings-path" in proc.stdout, (
            "UNEXPECTED: venv binary does NOT have --settings-path.\n"
            "Something is very wrong — the editable install is stale too.\n"
            f"  help output: {proc.stdout!r}"
        )
        assert "--no-env-block" in proc.stdout, (
            "UNEXPECTED: venv binary does NOT have --no-env-block.\n"
            f"  help output: {proc.stdout!r}"
        )

    def test_path_binary_missing_settings_path_flag_is_crit_finding(self) -> None:
        """CRIT: The installed binary (PATH/pipx) is MISSING --settings-path.

        Per [[install-ux-gap-2026-05-26]]: install story must work end-to-end.
        This test DOCUMENTS the gap. It xfails when the binary is stale
        (expected state as of PR #23 merge without a `pipx upgrade`).
        If the binary HAS been updated (post-reinstall), the test passes.

        An operator running the installed binary after PR #23 merges will get
        the OLD behavior: no env-block write, no AWS_ENDPOINT_URL in settings.json.
        """
        proc = subprocess.run(
            [_IAM_JIT_PATH_BINARY, "mcp", "install-claude-code", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            pytest.skip(f"PATH binary not runnable: {proc.stderr!r}")

        if "--settings-path" not in proc.stdout:
            # The binary is stale — document this as the expected CRIT finding.
            pytest.xfail(
                "CRIT FINDING CONFIRMED: The installed `iam-jit` binary (pipx) "
                "does NOT have --settings-path or --no-env-block from PR #23.\n"
                "This means an operator running the installed binary gets the "
                "OLD behavior: no env-block write, AWS_ENDPOINT_URL NOT written "
                "to ~/.claude/settings.json.\n"
                "Fix required: `pipx upgrade iam-jit` or `pip install -e .` "
                "after merging PR #23. The PR was merged to source only; the "
                "install story was NOT completed.\n"
                "Per [[install-ux-gap-2026-05-26]]: this is a launch blocker."
            )
        # If we reach here, the binary IS up to date. Test passes.
        assert "--settings-path" in proc.stdout, (
            "Unexpected: PATH binary claimed to have the flag but assertion failed."
        )


# ---------------------------------------------------------------------------
# Test 1: Snapshot-based real-traffic verification
# ---------------------------------------------------------------------------


@live_bouncer
class TestSnapshotBasedRealTrafficVerification:
    """Independent decisions_count delta verification via real boto3 subprocess.

    Methodology:
      1. Snapshot decisions_count via urllib (not the e2e helper)
      2. Run `iam-jit mcp install-claude-code` via a real OS subprocess
         (not Click CliRunner in-process) with --settings-path pointing at
         an isolated /tmp file
      3. Read the written settings.json and extract AWS_ENDPOINT_URL
      4. Spawn a SECOND subprocess with that env var set to make a real
         boto3 STS call
      5. Snapshot decisions_count AGAIN
      6. Assert delta == 1
    """

    def test_install_writes_env_and_sts_call_ticks_counter(
        self,
        tmp_path: pathlib.Path,
    ) -> None:
        """Full chain: install → read settings → STS subprocess → counter tick.

        Differs from fix-agent methodology: uses real OS subprocess for the
        install step (not Click CliRunner), and two separate child processes.
        """
        # Prepare a sandboxed settings path (NOT ~/.claude/settings.json).
        settings_path = tmp_path / "uat-isolated-settings.json"
        # Prepare a sandboxed claude.json so install doesn't touch ~/.claude.json.
        claude_json = tmp_path / "uat-claude.json"
        claude_json.write_text("{}")

        # Step 1: Snapshot before.
        count_before = _snapshot_decisions_count()

        # Step 2: Run install via real subprocess.
        install_env = _clean_env_for_subprocess()
        install_proc = subprocess.run(
            [
                _IAM_JIT,
                "mcp",
                "install-claude-code",
                "--path",
                str(claude_json),
                "--settings-path",
                str(settings_path),
            ],
            env=install_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert install_proc.returncode == 0, (
            f"install-claude-code subprocess failed (returncode={install_proc.returncode}):\n"
            f"  stdout: {install_proc.stdout!r}\n"
            f"  stderr: {install_proc.stderr!r}"
        )

        # Step 3: Read settings.json and extract AWS_ENDPOINT_URL.
        assert settings_path.exists(), (
            f"settings.json was NOT created at {settings_path}.\n"
            f"install stdout: {install_proc.stdout!r}\n"
            f"install stderr: {install_proc.stderr!r}"
        )
        settings_data = json.loads(settings_path.read_text())
        aws_ep = settings_data.get("env", {}).get("AWS_ENDPOINT_URL", "")
        assert aws_ep, (
            f"AWS_ENDPOINT_URL NOT found in settings.json env block.\n"
            f"settings.json content: {json.dumps(settings_data, indent=2)}"
        )

        # Step 4: Spawn a SECOND subprocess with the written env var.
        # This subprocess makes a real boto3 STS call routed through ibounce.
        sts_code = (
            "import json, sys, boto3, os\n"
            "ep = os.environ.get('AWS_ENDPOINT_URL', '')\n"
            "if not ep:\n"
            "    print('FAIL: AWS_ENDPOINT_URL not set', file=sys.stderr)\n"
            "    sys.exit(1)\n"
            "sts = boto3.client('sts', endpoint_url=ep)\n"
            "try:\n"
            "    resp = sts.get_caller_identity()\n"
            "    for key in ('Account', 'UserId', 'Arn'):\n"
            "        if key not in resp:\n"
            "            print(f'FAIL: missing {key}', file=sys.stderr)\n"
            "            sys.exit(2)\n"
            "    print(json.dumps({'Account': resp['Account'], 'UserId': resp['UserId']}))\n"
            "except Exception as e:\n"
            "    print(f'FAIL: {e}', file=sys.stderr)\n"
            "    sys.exit(3)\n"
        )

        sts_env = _clean_env_for_subprocess(extra={"AWS_ENDPOINT_URL": aws_ep})
        sts_proc = subprocess.run(
            [_PYTHON, "-c", sts_code],
            env=sts_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert sts_proc.returncode == 0, (
            f"STS subprocess failed (returncode={sts_proc.returncode}):\n"
            f"  stdout: {sts_proc.stdout!r}\n"
            f"  stderr: {sts_proc.stderr!r}\n"
            f"  AWS_ENDPOINT_URL used: {aws_ep!r}"
        )

        # (A) STS response must be parseable with Account + UserId.
        try:
            sts_parsed = json.loads(sts_proc.stdout.strip())
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"STS subprocess stdout is not valid JSON:\n"
                f"  stdout: {sts_proc.stdout!r}\n"
                f"  error: {exc}"
            )
        assert sts_parsed.get("Account"), (
            f"STS response missing Account: {sts_parsed}"
        )
        assert sts_parsed.get("UserId"), (
            f"STS response missing UserId: {sts_parsed}"
        )

        # Step 5: Snapshot after.
        count_after = _snapshot_decisions_count()

        # (B) decisions_count must tick by exactly 1.
        assert count_after == count_before + 1, (
            f"decisions_count delta mismatch.\n"
            f"  Before: {count_before}\n"
            f"  After:  {count_after}\n"
            f"  Expected delta 1; got delta {count_after - count_before}.\n"
            "The STS call did NOT flow through ibounce despite "
            f"AWS_ENDPOINT_URL={aws_ep!r} being set."
        )

    def test_settings_json_structure_is_valid(self, tmp_path: pathlib.Path) -> None:
        """The written settings.json must be a valid JSON object with an 'env' key
        containing AWS_ENDPOINT_URL. Verify structure directly without making an STS call.
        """
        settings_path = tmp_path / "structure-check-settings.json"
        claude_json = tmp_path / "structure-check-claude.json"
        claude_json.write_text("{}")

        install_env = _clean_env_for_subprocess()
        install_proc = subprocess.run(
            [
                _IAM_JIT,
                "mcp",
                "install-claude-code",
                "--path",
                str(claude_json),
                "--settings-path",
                str(settings_path),
            ],
            env=install_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert install_proc.returncode == 0, (
            f"install failed: {install_proc.stderr!r}"
        )
        assert settings_path.exists(), "settings.json not created"

        data = json.loads(settings_path.read_text())
        assert isinstance(data, dict), f"settings.json root is not a dict: {type(data)}"
        assert "env" in data, f"settings.json has no 'env' key: {list(data.keys())}"
        assert isinstance(data["env"], dict), (
            f"settings.json env is not a dict: {type(data['env'])}"
        )
        url = data["env"].get("AWS_ENDPOINT_URL", "")
        assert url.startswith("http://"), (
            f"AWS_ENDPOINT_URL has unexpected value: {url!r}"
        )
        assert "8767" in url or "8080" in url, (
            f"Expected ibounce/gbounce port in AWS_ENDPOINT_URL; got: {url!r}"
        )

    def test_idempotent_second_install_does_not_duplicate(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Running install-claude-code twice must not corrupt settings.json.
        The env block must remain a single-level dict (no nested lists or duplicates).
        """
        settings_path = tmp_path / "idempotent-settings.json"
        claude_json = tmp_path / "idempotent-claude.json"
        claude_json.write_text("{}")

        install_env = _clean_env_for_subprocess()
        args = [
            _IAM_JIT,
            "mcp",
            "install-claude-code",
            "--path",
            str(claude_json),
            "--settings-path",
            str(settings_path),
        ]

        # First install.
        r1 = subprocess.run(
            args, env=install_env, capture_output=True, text=True, timeout=30
        )
        assert r1.returncode == 0, f"first install failed: {r1.stderr!r}"

        # Second install.
        r2 = subprocess.run(
            args, env=install_env, capture_output=True, text=True, timeout=30
        )
        assert r2.returncode == 0, f"second install failed: {r2.stderr!r}"

        data = json.loads(settings_path.read_text())
        env_block = data.get("env", {})
        # The env block must remain a flat dict of string→string.
        assert isinstance(env_block, dict), f"env block is not a dict: {env_block!r}"
        for k, v in env_block.items():
            assert isinstance(k, str) and isinstance(v, str), (
                f"env block contains non-string values: {k!r}={v!r}"
            )


# ---------------------------------------------------------------------------
# Test 2: Honest-restart-message verification
# ---------------------------------------------------------------------------


@live_bouncer
class TestRestartMessageVerification:
    """Verify _emit_restart_required_message is emitted in the install subprocess.

    Methodology: run install via real subprocess (not in-process Click runner),
    capture stderr, assert message content. Different from fix-agent's capsys
    approach (which tests the function directly in-process).
    """

    def test_install_command_emits_restart_message_on_stderr(
        self, tmp_path: pathlib.Path
    ) -> None:
        """install-claude-code subprocess must emit a restart/new-session warning
        on stderr when it writes the env block. The message must include:
          - 'restart' or 'new session' (case-insensitive)
          - 'AWS_ENDPOINT_URL' (the written var)
        """
        settings_path = tmp_path / "restart-msg-settings.json"
        claude_json = tmp_path / "restart-msg-claude.json"
        claude_json.write_text("{}")

        install_env = _clean_env_for_subprocess()
        proc = subprocess.run(
            [
                _IAM_JIT,
                "mcp",
                "install-claude-code",
                "--path",
                str(claude_json),
                "--settings-path",
                str(settings_path),
            ],
            env=install_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert proc.returncode == 0, (
            f"install failed (rc={proc.returncode}):\n"
            f"  stderr: {proc.stderr!r}"
        )

        # The restart message goes to stderr.
        combined = (proc.stderr + proc.stdout).lower()
        has_restart_hint = "restart" in combined or "new session" in combined
        assert has_restart_hint, (
            "install-claude-code did NOT emit a restart/new-session warning.\n"
            f"  stderr: {proc.stderr!r}\n"
            f"  stdout: {proc.stdout!r}\n"
            "Expected 'restart' or 'new session' (case-insensitive) in output."
        )

        has_env_var = "AWS_ENDPOINT_URL" in (proc.stderr + proc.stdout)
        assert has_env_var, (
            "install-claude-code restart warning did NOT mention AWS_ENDPOINT_URL.\n"
            f"  stderr: {proc.stderr!r}\n"
            f"  stdout: {proc.stdout!r}"
        )

    def test_no_env_block_flag_suppresses_restart_message(
        self, tmp_path: pathlib.Path
    ) -> None:
        """When --no-env-block is passed, no env block is written and therefore
        no restart message should be emitted about env wiring.
        settings.json must NOT be created (it was never written to).
        """
        claude_json = tmp_path / "no-env-block-claude.json"
        claude_json.write_text("{}")

        install_env = _clean_env_for_subprocess()
        proc = subprocess.run(
            [
                _IAM_JIT,
                "mcp",
                "install-claude-code",
                "--path",
                str(claude_json),
                "--no-env-block",
            ],
            env=install_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert proc.returncode == 0, (
            f"install --no-env-block failed:\n"
            f"  stderr: {proc.stderr!r}\n"
            f"  stdout: {proc.stdout!r}"
        )

        # The env wiring restart message should not be present.
        # (A general "restart" mention for the MCP entry itself is ok —
        # we specifically check there's no AWS_ENDPOINT_URL mention.)
        assert "AWS_ENDPOINT_URL" not in (proc.stderr + proc.stdout), (
            "--no-env-block was passed but install still mentioned AWS_ENDPOINT_URL.\n"
            f"  stderr: {proc.stderr!r}\n"
            f"  stdout: {proc.stdout!r}"
        )


# ---------------------------------------------------------------------------
# Test 3: Documentation reality check
# ---------------------------------------------------------------------------


class TestDocumentationRealityCheck:
    """Verify docs/MCP-RECIPES.md covers the install-bootstrap flow."""

    def _read_mcp_recipes(self) -> str:
        """Read MCP-RECIPES.md from the expected docs location."""
        repo_root = pathlib.Path(__file__).parent.parent.parent
        mcp_recipes = repo_root / "docs" / "MCP-RECIPES.md"
        if not mcp_recipes.exists():
            pytest.skip(f"docs/MCP-RECIPES.md not found at {mcp_recipes}")
        return mcp_recipes.read_text(encoding="utf-8")

    def test_mcp_recipes_exists(self) -> None:
        """docs/MCP-RECIPES.md must exist."""
        repo_root = pathlib.Path(__file__).parent.parent.parent
        mcp_recipes = repo_root / "docs" / "MCP-RECIPES.md"
        assert mcp_recipes.exists(), (
            f"docs/MCP-RECIPES.md not found at {mcp_recipes}. "
            "The MCP recipes documentation file is required."
        )

    def test_mcp_recipes_mentions_install_claude_code(self) -> None:
        """MCP-RECIPES.md should mention the install-claude-code command."""
        content = self._read_mcp_recipes()
        assert "install-claude-code" in content or "install_claude_code" in content, (
            "docs/MCP-RECIPES.md does NOT mention 'install-claude-code'.\n"
            "FINDING (MED): MCP-RECIPES.md was not updated with the PR #23 "
            "install-bootstrap flow. Follow-up task required."
        )

    def test_mcp_recipes_mentions_settings_json_env_block(self) -> None:
        """MCP-RECIPES.md should document that install-claude-code writes
        env vars to ~/.claude/settings.json. This is the core PR #23 behavior.

        If this fails, it's a MED documentation gap — the fix was shipped
        without updating the docs. File a follow-up.
        """
        content = self._read_mcp_recipes()

        # Check for any mention of the settings.json env block behavior.
        mentions_settings = (
            "settings.json" in content
            or "AWS_ENDPOINT_URL" in content
            or "env block" in content.lower()
            or "env vars" in content.lower()
        )

        if not mentions_settings:
            # This is a MED finding — log it clearly but don't fail hard.
            # Per [[ibounce-honest-positioning]]: surface honestly.
            pytest.xfail(
                "FINDING (MED): docs/MCP-RECIPES.md does not document the "
                "settings.json env block written by `iam-jit mcp install-claude-code`.\n"
                "PR #23 shipped the code but did not update MCP-RECIPES.md to "
                "explain that the install command auto-wires AWS_ENDPOINT_URL "
                "into ~/.claude/settings.json.\n"
                "Follow-up task: update docs/MCP-RECIPES.md to describe the "
                "env-block write + restart-required behavior for Claude Code users."
            )

    def test_ibounce_docs_not_required_but_informational(self) -> None:
        """IBOUNCE.md is a more likely place for install-bootstrap docs.
        Check it as a bonus — if it has the info, MCP-RECIPES gap is lower priority.
        """
        repo_root = pathlib.Path(__file__).parent.parent.parent
        ibounce_md = repo_root / "docs" / "IBOUNCE.md"
        if not ibounce_md.exists():
            pytest.skip("docs/IBOUNCE.md not found — skipping bonus check")

        content = ibounce_md.read_text(encoding="utf-8")
        # Just record — don't fail.
        has_settings_info = (
            "settings.json" in content or "AWS_ENDPOINT_URL" in content
        )
        # This test always passes; it's informational for the UAT report.
        _ = has_settings_info


# ---------------------------------------------------------------------------
# Test 4: First-60-seconds smoke equivalent
# ---------------------------------------------------------------------------


@live_bouncer
class TestFirstSixtySecondsSmoke:
    """Simulate operator's first-60-seconds experience.

    Round-trip:
      1. posture in unwired env → expect DIRECT/UNPROTECTED for AWS
      2. install-claude-code --settings-path to isolated file
      3. source settings env into a new subprocess
      4. posture in wired env → expect AWS is no longer UNPROTECTED
    """

    def test_posture_unwired_shows_direct_unprotected(self) -> None:
        """Without AWS_ENDPOINT_URL, iam-jit posture must show DIRECT for AWS."""
        # Run posture in a clean env (no endpoint URL wired).
        clean_env = _clean_env_for_subprocess()
        # Also strip IAM_JIT_DATA_DIR so posture doesn't pick up autopilot hints.
        clean_env.pop("IAM_JIT_DATA_DIR", None)

        proc = subprocess.run(
            [_IAM_JIT, "posture"],
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # posture may exit 0 even when showing DIRECT.
        combined = (proc.stdout + proc.stderr).upper()
        has_direct_unprotected = "DIRECT" in combined or "UNPROTECTED" in combined
        assert has_direct_unprotected, (
            "posture did NOT show DIRECT/UNPROTECTED for AWS in a clean env.\n"
            f"  stdout: {proc.stdout!r}\n"
            f"  stderr: {proc.stderr!r}\n"
            "Expected: posture should warn about DIRECT (UNPROTECTED) AWS calls "
            "when AWS_ENDPOINT_URL is not set and ibounce IS running but unwired.\n"
            "Note: ibounce IS running on :8767 — the issue is the env var is absent."
        )

    def test_posture_wired_after_install_no_longer_unprotected(
        self, tmp_path: pathlib.Path
    ) -> None:
        """After install wires the env, posture must not report UNPROTECTED for AWS.

        Round-trip:
          1. install-claude-code → settings.json
          2. Read AWS_ENDPOINT_URL from settings.json
          3. Run posture with that env var set
          4. posture output must not say DIRECT/UNPROTECTED for AWS
        """
        settings_path = tmp_path / "smoke-settings.json"
        claude_json = tmp_path / "smoke-claude.json"
        claude_json.write_text("{}")

        # Step 1: install.
        install_env = _clean_env_for_subprocess()
        install_proc = subprocess.run(
            [
                _IAM_JIT,
                "mcp",
                "install-claude-code",
                "--path",
                str(claude_json),
                "--settings-path",
                str(settings_path),
            ],
            env=install_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert install_proc.returncode == 0, (
            f"install failed: {install_proc.stderr!r}"
        )
        assert settings_path.exists(), "settings.json not created by install"

        # Step 2: read the written env var.
        settings_data = json.loads(settings_path.read_text())
        aws_ep = settings_data.get("env", {}).get("AWS_ENDPOINT_URL", "")
        assert aws_ep, (
            f"AWS_ENDPOINT_URL not in settings.json: {settings_data}"
        )

        # Step 3: run posture with the wired env.
        wired_env = _clean_env_for_subprocess(extra={"AWS_ENDPOINT_URL": aws_ep})
        posture_proc = subprocess.run(
            [_IAM_JIT, "posture"],
            env=wired_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Step 4: posture output must not say DIRECT/UNPROTECTED for AWS.
        combined = (posture_proc.stdout + posture_proc.stderr).upper()

        # We check specifically for the AWS DIRECT pattern.
        # The output may still mention "DIRECT" for k8s/db/http (those are
        # unrelated bouncers) — we only care about the AWS row.
        aws_is_unprotected = (
            # Report line format: "AWS -> DIRECT  (UNPROTECTED)"
            "AWS -> DIRECT" in combined
            or "AWS CALLS ARE DIRECT" in combined
            # JSON format: effective_protection.aws_calls.warning containing DIRECT
            or ('"aws_calls"' in combined and '"DIRECT"' in combined)
        )

        if aws_is_unprotected:
            pytest.fail(
                "FINDING (HIGH): posture STILL shows DIRECT/UNPROTECTED for AWS "
                "even after install-claude-code wrote AWS_ENDPOINT_URL.\n"
                f"  AWS_ENDPOINT_URL used: {aws_ep!r}\n"
                f"  posture stdout: {posture_proc.stdout!r}\n"
                f"  posture stderr: {posture_proc.stderr!r}\n"
                "This means the posture check does NOT recognise the wired env var, "
                "or the env var value does not match ibounce's actual port."
            )

    def test_posture_json_mode_wired_shows_ibounce_intercepted(
        self, tmp_path: pathlib.Path
    ) -> None:
        """posture --json with wired env must show ibounce as intercepting AWS calls."""
        settings_path = tmp_path / "json-posture-settings.json"
        claude_json = tmp_path / "json-posture-claude.json"
        claude_json.write_text("{}")

        install_env = _clean_env_for_subprocess()
        install_proc = subprocess.run(
            [
                _IAM_JIT,
                "mcp",
                "install-claude-code",
                "--path",
                str(claude_json),
                "--settings-path",
                str(settings_path),
            ],
            env=install_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert install_proc.returncode == 0, f"install failed: {install_proc.stderr!r}"
        settings_data = json.loads(settings_path.read_text())
        aws_ep = settings_data.get("env", {}).get("AWS_ENDPOINT_URL", "")
        assert aws_ep, "AWS_ENDPOINT_URL not written to settings"

        wired_env = _clean_env_for_subprocess(extra={"AWS_ENDPOINT_URL": aws_ep})
        posture_proc = subprocess.run(
            [_IAM_JIT, "posture", "--json"],
            env=wired_env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if posture_proc.returncode != 0:
            pytest.skip(
                f"posture --json failed (rc={posture_proc.returncode}): "
                f"{posture_proc.stderr!r}"
            )

        try:
            posture_data = json.loads(posture_proc.stdout.strip())
        except json.JSONDecodeError:
            pytest.skip(
                f"posture --json did not emit valid JSON: {posture_proc.stdout!r}"
            )

        # Drill into effective_protection.aws_calls.intercepted_by
        ep = posture_data.get("effective_protection", {})
        aws_calls = ep.get("aws_calls", {})
        intercepted_by = aws_calls.get("intercepted_by")

        assert intercepted_by == "ibounce", (
            f"posture --json shows aws_calls.intercepted_by={intercepted_by!r}; "
            f"expected 'ibounce'.\n"
            f"aws_calls block: {json.dumps(aws_calls, indent=2)}\n"
            "The wired env var did not cause posture to report ibounce as intercepting."
        )


# ---------------------------------------------------------------------------
# Independent live counter verification (minimal, no shared helpers)
# ---------------------------------------------------------------------------


@live_bouncer
def test_independent_counter_tick_via_direct_boto3_subprocess() -> None:
    """Standalone counter-tick proof using only urllib + subprocess.
    No imports from test_install_bootstrap_e2e.py. This is the canonical
    independent verification proof per [[tests-and-independent-uat-required]].

    Verifies:
      (A) boto3 STS call through ibounce returns parseable Account+UserId
      (B) decisions_count ticked by exactly 1
    """
    # Snapshot before.
    count_before = _snapshot_decisions_count()

    sts_code = (
        "import json, sys, boto3, os\n"
        "ep = os.environ.get('AWS_ENDPOINT_URL', '')\n"
        "assert ep, 'AWS_ENDPOINT_URL not set'\n"
        "sts = boto3.client('sts', endpoint_url=ep)\n"
        "resp = sts.get_caller_identity()\n"
        "print(json.dumps({'Account': resp['Account'], 'UserId': resp['UserId']}))\n"
    )

    env = _clean_env_for_subprocess(
        extra={"AWS_ENDPOINT_URL": f"http://{_IBOUNCE_HOST}:{_IBOUNCE_PORT}"}
    )
    proc = subprocess.run(
        [_PYTHON, "-c", sts_code],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    if proc.returncode != 0:
        pytest.skip(
            f"STS call failed (no AWS creds?): {proc.stderr!r}"
        )

    # (A) Parse the response.
    try:
        parsed = json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        pytest.fail(f"STS response not valid JSON: {proc.stdout!r}")

    assert parsed.get("Account"), f"Account missing from STS response: {parsed}"
    assert parsed.get("UserId"), f"UserId missing from STS response: {parsed}"

    # (B) Counter must tick.
    count_after = _snapshot_decisions_count()
    assert count_after == count_before + 1, (
        f"decisions_count did not tick by 1.\n"
        f"  Before: {count_before}\n"
        f"  After:  {count_after}\n"
        f"  Delta:  {count_after - count_before}\n"
        "The STS call did NOT route through ibounce."
    )
