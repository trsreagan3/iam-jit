"""State-verification tests for #617 MED-3 — `init-solo` preflight
warn + fail-CLOSED on pre-existing iam-jit data.

UAT-Lifecycle 2026-05-25 found `iam-jit init-solo` against a
populated `~/.iam-jit/` silently re-used pre-existing
accounts.yaml / users.yaml / audit logs. Operator re-running
init-solo on the same machine could believe they got a fresh
init; reality was prior state carrying forward unannounced.

Per [[creates-never-mutates]] + [[ibounce-honest-positioning]]:
init-solo now runs a preflight check that:

  1. Enumerates pre-existing data by category (accounts / users /
     cli_token / audit_logs / bouncer_state / canary).
  2. Prints a [WARN] block to stderr naming each pre-existing path.
  3. Fail-CLOSED (exit 2) by default unless `--reuse-existing` was
     passed.

Tests assert observable filesystem state + exit codes per
[[contributing-state-verification]] — not internal return values.
"""

from __future__ import annotations

import pathlib

import pytest
from click.testing import CliRunner

from iam_jit import cli as cli_module
from iam_jit.cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Per-test data dir under tmp_path. NOT pre-created — tests that
    need pre-existing state mkdir + write themselves so we can assert
    what init-solo did (or refused to do) to it."""
    return tmp_path / "iam-jit"


@pytest.fixture(autouse=True)
def _no_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent boto3 STS lookups during seeding."""
    monkeypatch.setattr(
        "boto3.client",
        lambda *a, **k: (_ for _ in ()).throw(Exception("no creds")),
    )


def _runner() -> CliRunner:
    # Click >= 8.2 always captures stderr separately on `result.stderr`.
    return CliRunner()


# ---------------------------------------------------------------------------
# Test 1 — fresh dir: exit 0 + no WARN
# ---------------------------------------------------------------------------


def test_fresh_dir_init_solo_succeeds_with_no_preflight_warning(
    isolated_data_dir: pathlib.Path,
) -> None:
    """Fresh tmpdir: init-solo succeeds (exit 0) and stderr contains
    no [WARN] block — preflight has nothing to flag."""
    assert not isolated_data_dir.exists()

    result = _runner().invoke(
        main,
        # --account-id bypasses boto3 STS which is mocked out in _no_boto3.
        # Without it, init-solo exits 2 on "no aws creds" before seeding
        # the data dir (#698 MED-1 strict resolution).
        ["init-solo", "--data-dir", str(isolated_data_dir),
         "--account-id", "123456789012"],
    )

    assert result.exit_code == 0, (result.stdout, result.stderr)
    assert "[WARN]" not in (result.stderr or "")
    # Observable state: init-solo did run + seed the dir.
    assert (isolated_data_dir / "users.yaml").exists()
    assert (isolated_data_dir / "accounts.yaml").exists()
    assert (isolated_data_dir / "cli-token").exists()


# ---------------------------------------------------------------------------
# Test 2 — pre-existing accounts.yaml: exit 2 + WARN + file untouched
# ---------------------------------------------------------------------------


def test_preexisting_accounts_yaml_fails_closed_with_warning(
    isolated_data_dir: pathlib.Path,
) -> None:
    """Pre-existing accounts.yaml: init-solo exits 2; stderr names
    the accounts category + the path; the existing accounts.yaml
    content is NOT overwritten."""
    isolated_data_dir.mkdir(parents=True)
    sentinel = "# OPERATOR EDIT — must not be clobbered by init-solo\n"
    accounts = isolated_data_dir / "accounts.yaml"
    accounts.write_text(sentinel)

    result = _runner().invoke(
        main, ["init-solo", "--data-dir", str(isolated_data_dir)],
    )

    assert result.exit_code == 2, (result.stdout, result.stderr)
    err = result.stderr or ""
    assert "[WARN]" in err
    assert "accounts:" in err
    assert str(accounts) in err
    # State: accounts.yaml content preserved byte-for-byte.
    assert accounts.read_text() == sentinel
    # State: init-solo refused to seed the other files either.
    assert not (isolated_data_dir / "users.yaml").exists()
    assert not (isolated_data_dir / "cli-token").exists()


# ---------------------------------------------------------------------------
# Test 3 — pre-existing audit.jsonl: exit 2 + WARN names audit_logs
# ---------------------------------------------------------------------------


def test_preexisting_audit_jsonl_fails_closed_with_warning(
    isolated_data_dir: pathlib.Path,
) -> None:
    """Pre-existing audit.jsonl: init-solo exits 2; stderr names the
    audit_logs category + the audit.jsonl path; the audit log is NOT
    truncated or overwritten."""
    isolated_data_dir.mkdir(parents=True)
    audit = isolated_data_dir / "audit.jsonl"
    audit_payload = '{"event": "grant_issued", "ts": "2026-05-24T12:00:00Z"}\n'
    audit.write_text(audit_payload)

    result = _runner().invoke(
        main, ["init-solo", "--data-dir", str(isolated_data_dir)],
    )

    assert result.exit_code == 2, (result.stdout, result.stderr)
    err = result.stderr or ""
    assert "[WARN]" in err
    assert "audit_logs:" in err
    assert str(audit) in err
    # State: audit log untouched.
    assert audit.read_text() == audit_payload


# ---------------------------------------------------------------------------
# Test 4 — multiple categories: WARN lists all three
# ---------------------------------------------------------------------------


def test_multiple_preexisting_categories_all_listed_in_warning(
    isolated_data_dir: pathlib.Path,
) -> None:
    """When accounts.yaml + users.yaml + audit.jsonl all pre-exist,
    the [WARN] block lists each category + each absolute path."""
    isolated_data_dir.mkdir(parents=True)
    accounts = isolated_data_dir / "accounts.yaml"
    users = isolated_data_dir / "users.yaml"
    audit = isolated_data_dir / "audit.jsonl"
    accounts.write_text("# accounts\n")
    users.write_text("# users\n")
    audit.write_text("# audit\n")

    result = _runner().invoke(
        main, ["init-solo", "--data-dir", str(isolated_data_dir)],
    )

    assert result.exit_code == 2, (result.stdout, result.stderr)
    err = result.stderr or ""
    for category in ("accounts:", "users:", "audit_logs:"):
        assert category in err, f"missing category {category} in stderr"
    for path in (accounts, users, audit):
        assert str(path) in err, f"missing path {path} in stderr"


# ---------------------------------------------------------------------------
# Test 5 — --reuse-existing bypasses gate (exit 0; WARN still printed)
# ---------------------------------------------------------------------------


def test_reuse_existing_flag_bypasses_fail_closed_gate(
    isolated_data_dir: pathlib.Path,
) -> None:
    """With `--reuse-existing` the preflight gate becomes
    informational: exit 0, WARN still printed (so reuse is never
    silent), pre-existing files preserved byte-for-byte."""
    isolated_data_dir.mkdir(parents=True)
    accounts = isolated_data_dir / "accounts.yaml"
    users = isolated_data_dir / "users.yaml"
    accounts_payload = "# operator-owned accounts.yaml — keep me\n"
    users_payload = "# operator-owned users.yaml — keep me\n"
    accounts.write_text(accounts_payload)
    users.write_text(users_payload)

    result = _runner().invoke(
        main,
        ["init-solo", "--data-dir", str(isolated_data_dir),
         "--reuse-existing"],
    )

    # State: exit 0 (gate bypassed by explicit acknowledgement).
    assert result.exit_code == 0, (result.stdout, result.stderr)
    err = result.stderr or ""
    # State: WARN still printed — reuse is never silent.
    assert "[WARN]" in err
    assert "--reuse-existing" in err or "Continuing" in err
    # State: pre-existing operator files preserved byte-for-byte.
    assert accounts.read_text() == accounts_payload
    assert users.read_text() == users_payload
    # State: missing pieces (cli-token) DID get seeded — reuse is
    # additive, not destructive.
    assert (isolated_data_dir / "cli-token").exists()


# ---------------------------------------------------------------------------
# Test 6 — sabotage check: preflight is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_preflight_helper_removes_safety_gate(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check: if `_preflight_check_existing_data` always
    returns empty (i.e. the safety gate is gone), test #2's scenario
    now incorrectly returns exit 0 + clobbers accounts.yaml.

    This proves the preflight check is load-bearing — without it
    the fail-CLOSED gate doesn't fire."""
    isolated_data_dir.mkdir(parents=True)
    sentinel = "# OPERATOR EDIT — would be clobbered if preflight is bypassed\n"
    accounts = isolated_data_dir / "accounts.yaml"
    accounts.write_text(sentinel)

    # Sabotage: make the preflight helper see no pre-existing data.
    monkeypatch.setattr(
        cli_module,
        "_preflight_check_existing_data",
        lambda _data_dir: {
            "accounts": [], "users": [], "cli_token": [],
            "audit_logs": [], "bouncer_state": [], "canary": [],
        },
    )

    result = _runner().invoke(
        main, ["init-solo", "--data-dir", str(isolated_data_dir)],
    )

    # With the gate sabotaged, init-solo now incorrectly proceeds.
    assert result.exit_code == 0, (result.stdout, result.stderr)
    # The sentinel survives only because _seed_local_accounts itself
    # short-circuits when accounts.yaml exists; this assertion is
    # informational about that defense-in-depth layer, NOT the
    # preflight gate we're proving load-bearing.
    assert accounts.read_text() == sentinel
    # The real load-bearing assertion: with the gate sabotaged the
    # operator no longer gets the [WARN] block — silent reuse, which
    # is exactly the UAT-Lifecycle 2026-05-25 finding.
    assert "[WARN]" not in (result.stderr or "")
