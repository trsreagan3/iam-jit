"""#540 — `iam-jit canary update` SQLite-schema pre-check tests.

Per docs/MRR-4-HALT-CONDITIONS.md D6 + RB-D6 + docs/CONTRIBUTING.md
state-verification convention: pre-#540 the canary update path ran
`pip install -e .` UNCONDITIONALLY, then restarted bouncers. If the
new code's SCHEMA_VERSION had diverged from the operator's DB version
the bouncer would crash on first DB open AFTER the new code was already
installed in the venv — leaving the operator with code that can't speak
to their state.db.

#540 adds a HALT BEFORE pip install:
  * `_probe_new_code_schema_version(repo)` — runs a subprocess that
    imports `iam_jit.bouncer.store.SCHEMA_VERSION` from the post-pull
    src/ directory (NOT the installed venv).
  * `_current_db_schema_version()` — reads `SELECT version FROM
    schema_version` from the bouncer's DB.
  * `_schema_precheck_halt(repo)` — returns a halt-message when the
    two diverge; None when safe to proceed.

Each test asserts the reported result AND the observable side effect
(DB file UNTOUCHED on halt; no pip-install subprocess invocation).
"""

from __future__ import annotations

import os
import pathlib
import sqlite3
import sys
from typing import Any
from unittest import mock

import pytest

import iam_jit.cli_canary as cc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_db_with_version(db_path: pathlib.Path, version: int) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "CREATE TABLE schema_version(version INTEGER PRIMARY KEY)"
        )
        conn.execute(
            "INSERT INTO schema_version(version) VALUES (?)", (version,),
        )
        conn.commit()
    finally:
        conn.close()


def _stub_iam_roles_repo(
    tmp_path: pathlib.Path, schema_version_const: int,
) -> pathlib.Path:
    """Create a synthetic iam-roles tree with a stand-alone
    iam_jit.bouncer.store module that exposes SCHEMA_VERSION."""
    repo = tmp_path / "iam-roles"
    src = repo / "src" / "iam_jit" / "bouncer"
    src.mkdir(parents=True)
    # __init__ files so the import chain resolves.
    (repo / "src" / "iam_jit" / "__init__.py").write_text("")
    (repo / "src" / "iam_jit" / "bouncer" / "__init__.py").write_text("")
    store_py = (
        f"SCHEMA_VERSION = {schema_version_const}\n"
    )
    (src / "store.py").write_text(store_py)
    return repo


@pytest.fixture
def env_no_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_CANARY_SKIP_SCHEMA_CHECK", raising=False)


# ---------------------------------------------------------------------------
# 1. _probe_new_code_schema_version reads from the post-pull tree
# ---------------------------------------------------------------------------


def test_probe_new_code_schema_version_reads_from_repo(
    tmp_path: pathlib.Path,
) -> None:
    """The probe MUST import SCHEMA_VERSION from the repo's src/, not
    from any already-loaded module — proves it reflects new code on disk."""
    repo = _stub_iam_roles_repo(tmp_path, schema_version_const=999)
    version, err = cc._probe_new_code_schema_version(repo)
    assert err == ""
    assert version == 999


def test_probe_new_code_schema_version_handles_missing_repo(
    tmp_path: pathlib.Path,
) -> None:
    nonexistent = tmp_path / "does-not-exist"
    version, err = cc._probe_new_code_schema_version(nonexistent)
    assert version is None
    assert "does not exist" in err


def test_probe_new_code_schema_version_handles_broken_module(
    tmp_path: pathlib.Path,
) -> None:
    """A repo whose store.py raises on import surfaces an error string
    (not a crash)."""
    repo = tmp_path / "iam-roles"
    src = repo / "src" / "iam_jit" / "bouncer"
    src.mkdir(parents=True)
    (repo / "src" / "iam_jit" / "__init__.py").write_text("")
    (repo / "src" / "iam_jit" / "bouncer" / "__init__.py").write_text("")
    (src / "store.py").write_text("raise RuntimeError('broken store module')")
    version, err = cc._probe_new_code_schema_version(repo)
    assert version is None
    assert "exit" in err.lower() or "subprocess" in err.lower()


# ---------------------------------------------------------------------------
# 2. _current_db_schema_version round-trips a real SQLite DB
# ---------------------------------------------------------------------------


def test_current_db_schema_version_reads_seeded_db(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = tmp_path / "state.db"
    _seed_db_with_version(db, version=7)
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))

    version, err = cc._current_db_schema_version()
    assert err == ""
    assert version == 7


def test_current_db_schema_version_handles_missing_db(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = tmp_path / "missing.db"
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))
    version, err = cc._current_db_schema_version()
    assert version is None
    assert "not present" in err


def test_current_db_schema_version_handles_corrupt_db(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DB file that's NOT a real SQLite (e.g. truncated) surfaces an
    error string (not a crash)."""
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"not-a-sqlite-file\n")
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))
    version, err = cc._current_db_schema_version()
    assert version is None
    # sqlite reports a generic "file is encrypted or is not a database"
    # depending on version; the helper just needs to surface SOMETHING.
    assert err


# ---------------------------------------------------------------------------
# 3. _schema_precheck_halt — happy path (versions match → None)
# ---------------------------------------------------------------------------


def test_schema_precheck_halt_returns_none_when_versions_match(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    env_no_skip: None,
) -> None:
    repo = _stub_iam_roles_repo(tmp_path, schema_version_const=11)
    db = tmp_path / "state.db"
    _seed_db_with_version(db, version=11)
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))

    halt = cc._schema_precheck_halt(repo)
    assert halt is None


# ---------------------------------------------------------------------------
# 4. _schema_precheck_halt — mismatch returns HALT message
# ---------------------------------------------------------------------------


def test_schema_precheck_halt_returns_message_on_version_mismatch(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    env_no_skip: None,
) -> None:
    """When NEW code's SCHEMA_VERSION differs from the DB's current
    version, the halt message MUST name both versions + reference the
    rollback runbook."""
    repo = _stub_iam_roles_repo(tmp_path, schema_version_const=42)
    db = tmp_path / "state.db"
    _seed_db_with_version(db, version=11)
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))

    halt = cc._schema_precheck_halt(repo)
    assert halt is not None
    # 1. Reported: message names both versions.
    assert "11" in halt
    assert "42" in halt
    # 2. Observable: message points operator at the backup + override path.
    assert "ibounce backup" in halt
    assert "IAM_JIT_CANARY_SKIP_SCHEMA_CHECK=1" in halt
    assert "RB-D6" in halt or "MRR-4-ROLLBACK-RUNBOOK" in halt


# ---------------------------------------------------------------------------
# 5. Operator opt-out via env var
# ---------------------------------------------------------------------------


def test_schema_precheck_halt_opt_out_via_env_var(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM_JIT_CANARY_SKIP_SCHEMA_CHECK=1 returns None even on mismatch."""
    repo = _stub_iam_roles_repo(tmp_path, schema_version_const=99)
    db = tmp_path / "state.db"
    _seed_db_with_version(db, version=11)
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))
    monkeypatch.setenv("IAM_JIT_CANARY_SKIP_SCHEMA_CHECK", "1")

    halt = cc._schema_precheck_halt(repo)
    assert halt is None, (
        "operator opt-out via IAM_JIT_CANARY_SKIP_SCHEMA_CHECK=1 MUST "
        "skip the halt"
    )


# ---------------------------------------------------------------------------
# 6. Missing DB (fresh install) — no halt
# ---------------------------------------------------------------------------


def test_schema_precheck_halt_skipped_on_fresh_install(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    env_no_skip: None,
) -> None:
    """No DB = fresh install. Nothing to be incompatible with; halt
    MUST NOT fire."""
    repo = _stub_iam_roles_repo(tmp_path, schema_version_const=42)
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "missing.db"))
    halt = cc._schema_precheck_halt(repo)
    assert halt is None


# ---------------------------------------------------------------------------
# 7. _do_one_update HALTS pre-pip-install on schema mismatch
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_canary(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    monkeypatch.setattr(cc, "CANARY_DIR", canary_dir)
    monkeypatch.setattr(cc, "ISSUES_PATH", canary_dir / "issues.jsonl")
    monkeypatch.setattr(cc, "STATUS_PATH", canary_dir / "status.json")
    monkeypatch.setattr(cc, "URLS_PATH", canary_dir / "urls.md")
    monkeypatch.setattr(cc, "NOTES_PATH", canary_dir / "notes.md")
    monkeypatch.setattr(cc, "CANARY_YAML_PATH", canary_dir / ".iam-jit.yaml")
    return canary_dir


def test_do_one_update_halts_pre_pip_install_on_schema_mismatch(
    isolated_canary: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    env_no_skip: None,
) -> None:
    """End-to-end: _do_one_update detects schema mismatch + halts BEFORE
    any pip install / go install subprocess fires. State.db file MUST
    remain byte-identical."""
    # Stub canary repos + give iam-roles a real synthetic SCHEMA_VERSION.
    repo = _stub_iam_roles_repo(tmp_path, schema_version_const=42)
    (repo / ".git").mkdir()
    gbounce = tmp_path / "gbounce"
    gbounce.mkdir()
    (gbounce / ".git").mkdir()
    monkeypatch.setattr(
        cc, "_CANARY_REPOS",
        {"iam-roles": repo, "gbounce": gbounce},
    )
    # Seed DB at version 11.
    db = tmp_path / "state.db"
    _seed_db_with_version(db, version=11)
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))
    pre_db_bytes = db.read_bytes()

    # Stub: fake _git so the fetch/pull steps "succeed" without network.
    # `git status --porcelain` MUST return empty (clean tree); the
    # other invocations (rev-parse, fetch, pull, checkout) can return
    # the synthetic SHA.
    def fake_git(repo_path, *args):
        if args and args[0] == "status":
            return 0, ""
        return 0, "abc123def456789"

    monkeypatch.setattr(cc, "_git", fake_git)
    # Stub: subprocess.run records every call so we can prove pip
    # install was never invoked. The schema-probe needs a REAL
    # subprocess so we pass-through when argv[0] is `sys.executable`
    # (the probe shape).
    real_run = cc.subprocess.run
    called: list[list[str]] = []

    def fake_run(argv, *a, **kw):
        called.append(list(argv))
        if argv and str(argv[0]) == sys.executable:
            return real_run(argv, *a, **kw)
        return mock.Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cc.subprocess, "run", fake_run)
    # Make a venv pip exist so the pip step is reachable in principle
    # (we want to prove it's NOT taken because of the halt).
    venv_pip = tmp_path / "home" / ".iam-jit" / "venv" / "bin" / "pip"
    venv_pip.parent.mkdir(parents=True)
    venv_pip.write_text("#!/bin/sh\n")
    venv_pip.chmod(0o755)
    monkeypatch.setattr(
        cc.pathlib.Path, "home", classmethod(lambda cls: tmp_path / "home"),
    )
    # Stub shutil.which so the go install step is reachable in principle.
    monkeypatch.setattr(cc.shutil, "which", lambda name: f"/fake/{name}")
    # Stub _fail so the test surfaces the halt-message + skips the
    # rollback chain (which would itself re-run pip install per #539
    # — legitimate rollback behaviour but it would pollute the
    # "did pip install run BEFORE the halt fired?" assertion below).
    fail_calls: list[tuple[str, dict[str, Any], dict[str, str], bool]] = []

    def fake_fail(msg, pre_status, pre_shas, dry_run):
        fail_calls.append((msg, pre_status, pre_shas, dry_run))
        # Mirror the real _fail's issue-emit behaviour so the issues
        # file still carries the CRIT entry the test asserts on.
        cc.append_issue(
            bouncer="iam-jit", severity="CRIT", category="update_failure",
            observable=msg[:500], expected="canary update succeeded",
            repro_hint="iam-jit canary update", auto_generated=True,
            related_task="#540",
        )

    monkeypatch.setattr(cc, "_fail", fake_fail)

    cc.write_status({
        "ports": {"ibounce": 7401},
        "pids": {"ibounce": 1234},
    })

    cc._do_one_update(dry_run=False)

    # 1. Reported: _fail was called with the #540 halt message.
    assert len(fail_calls) == 1
    halt_msg = fail_calls[0][0]
    assert "#540 schema pre-check HALT" in halt_msg
    assert "11" in halt_msg and "42" in halt_msg

    # 2. Reported: a CRIT update_failure issue was filed naming #540.
    issues = cc.read_issues()
    crits = [
        i for i in issues
        if i.get("severity") == "CRIT"
        and "#540 schema pre-check" in i.get("observable", "")
    ]
    assert crits, f"expected #540 CRIT; got {issues!r}"

    # 3. Observable: pip install was NEVER invoked (no pip subprocess
    #    call). The schema probe IS a subprocess via sys.executable;
    #    only pip + go calls would be the violations.
    argv_strs = [" ".join(str(x) for x in c) for c in called]
    pip_installs = [
        s for s in argv_strs
        if str(venv_pip) in s and "install -e ." in s
    ]
    assert not pip_installs, (
        f"pip install MUST NOT run after #540 halt; subprocess argvs: "
        f"{argv_strs!r}"
    )

    # 4. Observable: go install was NEVER invoked either.
    go_installs = [s for s in argv_strs if "go install ./..." in s]
    assert not go_installs, (
        f"go install MUST NOT run after #540 halt; argvs: {argv_strs!r}"
    )

    # 5. Observable: state.db is byte-identical (untouched). The
    #    schema pre-check opens the DB read-only; the contents
    #    must not change.
    assert db.read_bytes() == pre_db_bytes, (
        "state.db was modified despite #540 halt; the schema pre-check "
        "MUST be read-only against the DB"
    )


def test_do_one_update_proceeds_on_matching_schema_versions(
    isolated_canary: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    env_no_skip: None,
) -> None:
    """When NEW code's SCHEMA_VERSION matches the DB's version, pip
    install IS invoked + go install IS invoked (happy path)."""
    repo = _stub_iam_roles_repo(tmp_path, schema_version_const=11)
    (repo / ".git").mkdir()
    gbounce = tmp_path / "gbounce"
    gbounce.mkdir()
    (gbounce / ".git").mkdir()
    monkeypatch.setattr(
        cc, "_CANARY_REPOS",
        {"iam-roles": repo, "gbounce": gbounce},
    )
    db = tmp_path / "state.db"
    _seed_db_with_version(db, version=11)
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))

    def fake_git(repo_path, *args):
        if args and args[0] == "status":
            return 0, ""
        return 0, "abc123"

    monkeypatch.setattr(cc, "_git", fake_git)
    real_run = cc.subprocess.run
    called: list[list[str]] = []

    def fake_run(argv, *a, **kw):
        called.append(list(argv))
        if argv and str(argv[0]) == sys.executable:
            return real_run(argv, *a, **kw)
        return mock.Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cc.subprocess, "run", fake_run)
    venv_pip = tmp_path / "home" / ".iam-jit" / "venv" / "bin" / "pip"
    venv_pip.parent.mkdir(parents=True)
    venv_pip.write_text("#!/bin/sh\n")
    venv_pip.chmod(0o755)
    monkeypatch.setattr(
        cc.pathlib.Path, "home", classmethod(lambda cls: tmp_path / "home"),
    )
    monkeypatch.setattr(cc.shutil, "which", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        cc, "_restart_bouncers", lambda pre: (True, "ok"),
    )

    cc.write_status({"ports": {"ibounce": 7401}, "pids": {"ibounce": 1234}})

    cc._do_one_update(dry_run=False)

    argv_strs = [" ".join(c) for c in called]
    pip_installs = [
        s for s in argv_strs
        if "pip" in s and "install -e ." in s
    ]
    assert pip_installs, (
        f"happy-path matching schema MUST proceed to pip install; got: "
        f"{argv_strs!r}"
    )
