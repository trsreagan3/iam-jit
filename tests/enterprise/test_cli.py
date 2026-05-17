"""Click integration tests for `iam-jit enterprise bootstrap`.

Covers:
  - License gating: free / pro / team tiers all refused with the
    Enterprise upgrade message
  - Dry-run path: discovery + proposal runs, no config written
  - Auto-accept path: writes config + audit row
  - Subcommand registered on the top-level `iam-jit` group
"""

from __future__ import annotations

import datetime as _dt
import pathlib

import pytest
from click.testing import CliRunner

from iam_jit import license as _license
from iam_jit.cli import main as iam_jit_main
from iam_jit.enterprise.discovery import (
    AccountSummary,
    BedrockAvailability,
    DiscoveredEnv,
)


def _stub_env() -> DiscoveredEnv:
    return DiscoveredEnv(
        discovered_at="2026-05-18T00:00:00Z",
        caller_account_id="111111111111",
        caller_arn="arn:aws:iam::111111111111:role/Admin",
        caller_region="us-east-1",
        accounts=(AccountSummary(account_id="111111111111", is_caller_account=True),),
        oidc_roles=(),
        bedrock=BedrockAvailability(
            region="us-east-1",
            bedrock_reachable=False,
            anthropic_model_ids=(),
        ),
        eks_clusters=(),
        ecs_clusters=(),
        errors=(),
    )


def _fake_enterprise_license() -> _license.License:
    return _license.License(
        tier="enterprise",
        issued_to="Test Co.",
        issued_at=_dt.datetime.now(_dt.UTC) - _dt.timedelta(days=1),
        expires_at=_dt.datetime.now(_dt.UTC) + _dt.timedelta(days=365),
        max_users=1000,
        license_id="lic_test",
    )


def _fake_team_license() -> _license.License:
    lic = _fake_enterprise_license()
    return _license.License(
        tier="team",
        issued_to=lic.issued_to,
        issued_at=lic.issued_at,
        expires_at=lic.expires_at,
        max_users=lic.max_users,
        license_id=lic.license_id,
    )


# ---------------------------------------------------------------------------
# Subcommand registration
# ---------------------------------------------------------------------------


def test_enterprise_group_registered_on_top_level_cli() -> None:
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["enterprise", "--help"])
    assert result.exit_code == 0
    assert "bootstrap" in result.output


def test_bootstrap_subcommand_help() -> None:
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["enterprise", "bootstrap", "--help"])
    assert result.exit_code == 0
    assert "Discovery" in result.output or "discovery" in result.output


# ---------------------------------------------------------------------------
# Tier gating
# ---------------------------------------------------------------------------


def test_bootstrap_rejected_on_free_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "iam_jit.license.load_license", lambda *a, **kw: None,
    )
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["enterprise", "bootstrap", "--dry-run"])
    assert result.exit_code == 3
    assert "Enterprise" in result.output or "Enterprise" in result.stderr
    combined = result.output + (result.stderr or "")
    assert "Free tier" in combined or "Enterprise license" in combined


def test_bootstrap_rejected_on_team_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "iam_jit.license.load_license", lambda *a, **kw: _fake_team_license(),
    )
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["enterprise", "bootstrap", "--dry-run"])
    assert result.exit_code == 3
    combined = result.output + (result.stderr or "")
    assert "Enterprise tier" in combined
    assert "team" in combined.lower()


def test_bootstrap_rejected_on_invalid_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a, **kw):
        raise _license.LicenseInvalidError("test: bad signature")
    monkeypatch.setattr("iam_jit.license.load_license", _raise)
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["enterprise", "bootstrap", "--dry-run"])
    assert result.exit_code == 3
    combined = result.output + (result.stderr or "")
    assert "bad signature" in combined or "verification" in combined


# ---------------------------------------------------------------------------
# Happy paths with Enterprise license
# ---------------------------------------------------------------------------


class _StubBackend:
    def chat(self, **kw):  # type: ignore[no-untyped-def]
        return ""  # triggers deterministic fallback


def test_bootstrap_dry_run_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    monkeypatch.setattr(
        "iam_jit.license.load_license",
        lambda *a, **kw: _fake_enterprise_license(),
    )
    # The CLI imports discover/propose lazily inside the command; patch
    # them on their home modules so the late `from .discovery import
    # discover` picks up the stubs.
    monkeypatch.setattr(
        "iam_jit.enterprise.discovery.discover",
        lambda **kw: _stub_env(),
    )
    from iam_jit.enterprise.proposal import _deterministic_fallback
    monkeypatch.setattr(
        "iam_jit.enterprise.proposal.propose",
        lambda env, prompt, **kw: _deterministic_fallback(env, "stub"),
    )
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, [
        "enterprise", "bootstrap",
        "--dry-run",
        "--config-path", str(cfg),
        "--audit-path", str(aud),
    ])
    assert result.exit_code == 0, result.output
    assert not cfg.exists()
    assert not aud.exists()
    assert "dry-run" in result.output.lower() or "would propose" in result.output.lower()


def test_bootstrap_auto_accept_writes_config_and_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    monkeypatch.setattr(
        "iam_jit.license.load_license",
        lambda *a, **kw: _fake_enterprise_license(),
    )
    monkeypatch.setattr(
        "iam_jit.enterprise.discovery.discover",
        lambda **kw: _stub_env(),
    )
    from iam_jit.enterprise.proposal import _deterministic_fallback
    monkeypatch.setattr(
        "iam_jit.enterprise.proposal.propose",
        lambda env, prompt, **kw: _deterministic_fallback(env, "stub"),
    )
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, [
        "enterprise", "bootstrap",
        "--yes",
        "--config-path", str(cfg),
        "--audit-path", str(aud),
    ])
    assert result.exit_code == 0, result.output
    assert cfg.exists()
    assert aud.exists()
    body = cfg.read_text()
    assert "org_context_name" in body
    # Audit row recorded.
    rows = [line for line in aud.read_text().splitlines() if line.strip()]
    assert len(rows) == 1
