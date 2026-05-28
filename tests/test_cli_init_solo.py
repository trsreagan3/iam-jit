"""Tests for the `iam-jit init-solo` command."""

from __future__ import annotations

import pathlib

import pytest
from click.testing import CliRunner

from iam_jit.cli import main


@pytest.fixture
def isolated_data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "iam-jit"


def test_init_solo_bootstraps_data_dir(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """init-solo creates the data dir, users.yaml, accounts.yaml, cli-token.
    #698: tests now pass --account-id explicitly because the no-creds
    silent-placeholder behavior was replaced with fail-loud."""
    monkeypatch.setattr("boto3.client", lambda *a, **k: (_ for _ in ()).throw(
        Exception("no creds in test env")
    ))
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init-solo", "--data-dir", str(isolated_data_dir),
         "--port", "8765", "--account-id", "123456789012"],
    )
    assert result.exit_code == 0, result.output
    assert (isolated_data_dir / "users.yaml").exists()
    assert (isolated_data_dir / "accounts.yaml").exists()
    assert (isolated_data_dir / "cli-token").exists()
    token = (isolated_data_dir / "cli-token").read_text().strip()
    assert token.startswith("iamjit_")


def test_init_solo_prints_next_steps(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("boto3.client", lambda *a, **k: (_ for _ in ()).throw(
        Exception("no creds")
    ))
    runner = CliRunner()
    result = runner.invoke(
        main, ["init-solo", "--data-dir", str(isolated_data_dir),
               "--account-id", "123456789012"],
    )
    assert "iam-jit serve --local" in result.output
    assert "mcpServers" in result.output
    assert "iam-jit" in result.output
    # Bearer-token usage is shown.
    assert "Authorization: Bearer" in result.output


def test_init_solo_print_mcp_config_only(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`--print-mcp-config` skips bootstrap and only prints snippets."""
    monkeypatch.setattr("boto3.client", lambda *a, **k: (_ for _ in ()).throw(
        Exception("no creds")
    ))
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init-solo", "--data-dir", str(isolated_data_dir),
         "--print-mcp-config"],
    )
    assert result.exit_code == 0, result.output
    assert "mcpServers" in result.output
    # No setup happened — directory shouldn't exist.
    assert not (isolated_data_dir / "users.yaml").exists()


def test_init_solo_idempotent(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Running init-solo twice doesn't corrupt anything or rotate the
    token. Second invocation must pass `--reuse-existing` per #617
    MED-3 fail-CLOSED preflight; idempotency is then preserved.
    """
    monkeypatch.setattr("boto3.client", lambda *a, **k: (_ for _ in ()).throw(
        Exception("no creds")
    ))
    runner = CliRunner()
    r1 = runner.invoke(
        main, ["init-solo", "--data-dir", str(isolated_data_dir),
               "--account-id", "123456789012"],
    )
    assert r1.exit_code == 0
    token_1 = (isolated_data_dir / "cli-token").read_text()
    users_1 = (isolated_data_dir / "users.yaml").read_text()

    r2 = runner.invoke(
        main,
        ["init-solo", "--data-dir", str(isolated_data_dir),
         "--reuse-existing"],
    )
    assert r2.exit_code == 0
    token_2 = (isolated_data_dir / "cli-token").read_text()
    users_2 = (isolated_data_dir / "users.yaml").read_text()

    assert token_1 == token_2  # MCP configs survive
    assert users_1 == users_2


# ---------------------------------------------------------------------------
# #698 MED-1 — init-solo + serve --local now fail-loud when neither
# --account-id nor live AWS credentials resolve. Pre-fix the placeholder
# 000000000000 silently landed in accounts.yaml + every grant quietly
# failed downstream against the non-existent account.
# ---------------------------------------------------------------------------


def test_init_solo_fails_loud_when_no_creds_and_no_account_id(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No --account-id + no live creds → exit 2 + actionable error,
    NOT a silently-seeded 000000000000 placeholder."""
    monkeypatch.setattr("boto3.client", lambda *a, **k: (_ for _ in ()).throw(
        Exception("no creds in test env")
    ))
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init-solo", "--data-dir", str(isolated_data_dir),
         "--no-doctor-check"],
    )
    assert result.exit_code == 2, result.output
    # The error message points at the fix.
    assert "--account-id" in result.output
    # And we did NOT silently land a placeholder accounts.yaml.
    assert not (isolated_data_dir / "accounts.yaml").exists()


def test_init_solo_accepts_explicit_account_id_offline(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit --account-id lets the operator bootstrap without
    live AWS creds (dev / demo / air-gapped runs)."""
    monkeypatch.setattr("boto3.client", lambda *a, **k: (_ for _ in ()).throw(
        Exception("no creds")
    ))
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init-solo", "--data-dir", str(isolated_data_dir),
         "--account-id", "060392206767"],
    )
    assert result.exit_code == 0, result.output
    content = (isolated_data_dir / "accounts.yaml").read_text()
    assert "060392206767" in content
    assert "000000000000" not in content
