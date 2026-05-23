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
# Tier gating — disabled at v1.0 per [[oss-only-launch-decision]] (#511b)
#
# Prior tests asserted bootstrap exits 3 on free / team / invalid-license
# paths. At v1.0 the gate ships FREE — bootstrap proceeds regardless of
# license tier (or absence thereof). The license-load call is retained
# (a malformed license file still surfaces as WARNING). Tests below
# flip to NoLicenseShipsFree state-verification per docs/CONTRIBUTING.md:
# verify the bootstrap actually RUNS to completion + produces the
# expected dry-run output, not just "exits 0."
# ---------------------------------------------------------------------------


def _stub_bootstrap_deps(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wire discover + propose stubs so a bootstrap --dry-run can
    complete without hitting AWS. Shared between the v1.0 tier-gate
    tests below."""
    monkeypatch.setattr(
        "iam_jit.enterprise.discovery.discover",
        lambda **kw: _stub_env(),
    )
    from iam_jit.enterprise.proposal import _deterministic_fallback
    monkeypatch.setattr(
        "iam_jit.enterprise.proposal.propose",
        lambda env, prompt, **kw: _deterministic_fallback(env, "stub"),
    )


def _reset_oss_advisory_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one-shot advisory flag survives across tests in the same
    module-load; reset it so each test can observe the INFO log."""
    from iam_jit.enterprise import cli as ent_cli_mod
    monkeypatch.setattr(ent_cli_mod, "_OSS_LAUNCH_ADVISORY_EMITTED", False)


def test_bootstrap_no_license_ships_free(
    monkeypatch: pytest.MonkeyPatch, caplog,
) -> None:
    """No license file at all = bootstrap proceeds at v1.0 (was: exit 3).

    State verification: dry-run completes (exit 0) AND the proposal
    YAML is on stdout AND the INFO advisory citing
    [[oss-only-launch-decision]] fires.
    """
    import logging

    monkeypatch.setattr(
        "iam_jit.license.load_license", lambda *a, **kw: None,
    )
    _stub_bootstrap_deps(monkeypatch)
    _reset_oss_advisory_flag(monkeypatch)

    runner = CliRunner()
    with caplog.at_level(logging.INFO, logger="iam_jit.enterprise.cli"):
        result = runner.invoke(
            iam_jit_main, ["enterprise", "bootstrap", "--dry-run"],
        )

    # 1. Reported status: dry-run succeeded.
    assert result.exit_code == 0, (
        f"expected exit 0 (gate disabled at v1.0); got {result.exit_code}\n"
        f"output: {result.output}"
    )
    # 2. State: the dry-run actually produced its proposal output
    #    (bootstrap reached Phase 2 + emitted YAML to stdout). A
    #    "exit 0 but no output" would be a #475-shape silent failure.
    out_lower = result.output.lower()
    assert "dry-run" in out_lower or "would propose" in out_lower
    # 3. State: the advisory fired with the memo reference.
    advisory_records = [
        r for r in caplog.records
        if "oss-only-launch-decision" in r.message
    ]
    assert advisory_records, (
        "expected one-shot INFO advisory citing "
        "[[oss-only-launch-decision]]; got: "
        f"{[r.message for r in caplog.records]}"
    )
    assert advisory_records[0].levelno == logging.INFO


def test_bootstrap_team_tier_ships_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Team license = bootstrap proceeds at v1.0 (was: exit 3).

    Pre-v1.0 the gate required Enterprise tier explicitly. Per
    [[oss-only-launch-decision]] every tier ships free.
    """
    monkeypatch.setattr(
        "iam_jit.license.load_license",
        lambda *a, **kw: _fake_team_license(),
    )
    _stub_bootstrap_deps(monkeypatch)
    _reset_oss_advisory_flag(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main, ["enterprise", "bootstrap", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    out_lower = result.output.lower()
    assert "dry-run" in out_lower or "would propose" in out_lower


def test_bootstrap_invalid_license_warns_but_proceeds(
    monkeypatch: pytest.MonkeyPatch, caplog,
) -> None:
    """Malformed license file = WARNING (not exit 3) + proceed at v1.0.

    A present-but-malformed license file is still operator-actionable
    so we surface a warning, but per [[oss-only-launch-decision]] we
    don't refuse.
    """
    import logging

    def _raise(*a, **kw):
        raise _license.LicenseInvalidError("test: bad signature")

    monkeypatch.setattr("iam_jit.license.load_license", _raise)
    _stub_bootstrap_deps(monkeypatch)
    _reset_oss_advisory_flag(monkeypatch)

    runner = CliRunner()
    with caplog.at_level(logging.WARNING, logger="iam_jit.enterprise.cli"):
        result = runner.invoke(
            iam_jit_main, ["enterprise", "bootstrap", "--dry-run"],
        )

    assert result.exit_code == 0, result.output
    # State: a warning fired surfacing the verification failure.
    warn_records = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and (
            "bad signature" in r.message or "failed verification" in r.message
        )
    ]
    assert warn_records, (
        "expected WARNING log surfacing the license verification "
        "failure; got: "
        f"{[(r.levelname, r.message) for r in caplog.records]}"
    )


def test_license_invalid_error_sentinel_still_exported() -> None:
    """`LicenseInvalidError` + `LicenseError` must remain importable
    so v1.1+ paid-tier reinstate is a one-line revert at each gate
    site. Mirrors the Go-side
    `TestAuditWebhook_LicenseErrorSentinelStillExported` pattern from
    the kbouncer #511 fix.
    """
    from iam_jit import license as license_mod
    from iam_jit.license import LicenseError, LicenseInvalidError

    assert LicenseError is license_mod.LicenseError
    assert LicenseInvalidError is license_mod.LicenseInvalidError
    assert issubclass(LicenseInvalidError, LicenseError)
    assert issubclass(LicenseError, Exception)


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
